"""Googlebot verification.

Primary: Google's published IP range lists (cached 24 h in the state directory, last
good copy kept on failure). When the lists are loaded they decide alone: an
address outside them is "false", whatever its reverse DNS says - a Google Cloud VM
(*.bc.googleusercontent.com) with a faked user agent is no Googlebot. Only without any
list: reverse DNS to googlebot.com / google.com / gae.googleusercontent.com (user-triggered
fetchers) with forward confirmation (2 s timeout, at most 200 lookups per run, cached per
IP in memory). The check runs on the raw IP *before* pseudonymisation;
only ``bot_verified`` = "true"/"false" leaves the server, or nothing (unchecked).
"""
from __future__ import annotations

import ipaddress
import json
import os
import queue
import socket
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .privacy import IpAddress, parse_ip

# Source: https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
# (checked 2026-11-12; the former /search/apis/ipranges/ URLs redirect here).
GOOGLE_RANGE_URLS: Tuple[str, ...] = (
    "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
    "https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json",
)
# Not all of googleusercontent.com: that is every Google Cloud VM, too.
GOOGLE_DNS_SUFFIXES = (".googlebot.com", ".google.com", ".gae.googleusercontent.com")
CACHE_FILE = "google-ranges.json"
CACHE_TTL_SECONDS = 24 * 3600
DNS_TIMEOUT_SECONDS = 2.0
DNS_BUDGET_PER_RUN = 200

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_google_ranges(data: dict) -> List[str]:
    """Extract CIDR strings from one of Google's JSON files; raises ValueError if malformed."""
    prefixes = data.get("prefixes") if isinstance(data, dict) else None
    if not isinstance(prefixes, list) or not prefixes:
        raise ValueError("no prefixes")
    out = []
    for item in prefixes:
        if not isinstance(item, dict):
            continue
        cidr = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        if isinstance(cidr, str):
            ipaddress.ip_network(cidr, strict=False)  # validates
            out.append(cidr)
    if not out:
        raise ValueError("no valid prefixes")
    return out


class GoogleRanges:
    def __init__(self, cidrs: Iterable[str], fetched_at: float = 0.0, source: str = ""):
        self.cidrs = sorted(set(cidrs))
        self.fetched_at = fetched_at
        self.source = source
        self._v4: List[Network] = []
        self._v6: List[Network] = []
        for cidr in self.cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            (self._v4 if net.version == 4 else self._v6).append(net)

    def __len__(self) -> int:
        return len(self.cidrs)

    def contains(self, addr: IpAddress) -> bool:
        nets = self._v4 if addr.version == 4 else self._v6
        return any(addr in net for net in nets)

    @classmethod
    def from_path(cls, path: str) -> "GoogleRanges":
        """Load a local copy: one JSON file in Google's format or a directory of such files."""
        files = [path]
        if os.path.isdir(path):
            files = sorted(os.path.join(path, f) for f in os.listdir(path) if f.endswith(".json"))
        cidrs: List[str] = []
        for file in files:
            with open(file, encoding="utf-8") as fh:
                cidrs.extend(parse_google_ranges(json.load(fh)))
        return cls(cidrs, os.path.getmtime(path), source=path)

    # cache in the state directory -------------------------------------------------------------
    @classmethod
    def load_cache(cls, state_dir: str) -> Optional["GoogleRanges"]:
        try:
            with open(os.path.join(state_dir, CACHE_FILE), encoding="utf-8") as fh:
                data = json.load(fh)
            return cls(data["cidrs"], float(data["fetchedAt"]), source="cache")
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def save_cache(self, state_dir: str) -> None:
        from .state import atomic_write_json

        atomic_write_json(os.path.join(state_dir, CACHE_FILE), {"fetchedAt": self.fetched_at, "cidrs": self.cidrs})

    def is_fresh(self, now: float) -> bool:
        return 0 <= now - self.fetched_at < CACHE_TTL_SECONDS


def fetch_google_ranges(get_json: Callable[[str], dict], now: float) -> GoogleRanges:
    """Download all lists; raises if any list fails (a partial list would mark real crawlers as fake)."""
    cidrs: List[str] = []
    for url in GOOGLE_RANGE_URLS:
        cidrs.extend(parse_google_ranges(get_json(url)))
    return GoogleRanges(cidrs, now, source="download")


def _system_reverse(ip: str) -> str:
    return socket.gethostbyaddr(ip)[0]


def _system_forward(host: str) -> List[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


def _with_timeout(fn: Callable, arg: str, timeout: float):
    """Run a blocking resolver call in a daemon thread; ``TimeoutError`` after ``timeout`` seconds."""
    result: "queue.Queue[tuple]" = queue.Queue(maxsize=1)

    def target() -> None:
        try:
            result.put((True, fn(arg)))
        except Exception as exc:  # resolver errors are results, too
            result.put((False, exc))

    threading.Thread(target=target, daemon=True).start()
    try:
        ok, value = result.get(timeout=timeout)
    except queue.Empty:
        raise TimeoutError(f"DNS lookup for {arg} timed out") from None
    if not ok:
        raise value
    return value


class DnsVerifier:
    """Reverse DNS + forward confirmation; tri-state result (True, False, None = unknown)."""

    def __init__(
        self,
        reverse: Callable[[str], str] = _system_reverse,
        forward: Callable[[str], Sequence[str]] = _system_forward,
        timeout: float = DNS_TIMEOUT_SECONDS,
        budget: int = DNS_BUDGET_PER_RUN,
    ):
        self.reverse = reverse
        self.forward = forward
        self.timeout = timeout
        self.budget = budget
        self.lookups = 0
        self._cache: Dict[str, Optional[bool]] = {}

    def check(self, addr: IpAddress) -> Optional[bool]:
        key = str(addr)
        if key in self._cache:
            return self._cache[key]
        if self.lookups >= self.budget:
            return None
        self.lookups += 1
        result: Optional[bool]
        try:
            host = _with_timeout(self.reverse, key, self.timeout).rstrip(".").lower()
            if not host.endswith(GOOGLE_DNS_SUFFIXES):
                result = False
            else:
                addresses = {str(parse_ip(a)) for a in _with_timeout(self.forward, host, self.timeout)}
                result = key in addresses
        except TimeoutError:
            result = None
        except (socket.herror, socket.gaierror):
            result = False  # no PTR record or the name does not resolve
        except OSError:
            result = None
        self._cache[key] = result
        return result


class GooglebotVerifier:
    """Combines range lists and DNS. Returns "true", "false" or None (unchecked)."""

    def __init__(self, ranges: Optional[GoogleRanges], dns: Optional[DnsVerifier]):
        self.ranges = ranges
        self.dns = dns
        self._cache: Dict[str, Optional[str]] = {}
        self.stats = {"true": 0, "false": 0, "unchecked": 0}

    def verify(self, client: str) -> Optional[str]:
        addr = parse_ip(client)
        if addr is None:
            return None
        key = str(addr)
        if key not in self._cache:
            self._cache[key] = self._decide(addr)
        result = self._cache[key]
        self.stats[result or "unchecked"] += 1
        return result

    def _decide(self, addr: IpAddress) -> Optional[str]:
        if self.ranges is not None:
            # Complete lists decide alone; DNS is never asked (no googleusercontent.com VM passes).
            return "true" if self.ranges.contains(addr) else "false"
        dns = self.dns.check(addr) if self.dns is not None else None
        if dns is True:
            return "true"
        if dns is False:
            return "false"
        return None


def load_ranges(
    state_dir: Optional[str],
    ranges_file: Optional[str],
    get_json: Optional[Callable[[str], dict]],
    write_cache: bool,
    now: Optional[float] = None,
    warn: Callable[[str], None] = lambda msg: None,
) -> Optional[GoogleRanges]:
    """Resolve the range list for this run: local file, fresh cache, download, stale cache."""
    now = time.time() if now is None else now
    if ranges_file:
        try:
            return GoogleRanges.from_path(ranges_file)
        except (OSError, ValueError) as exc:
            warn(f"bots: cannot read ranges_file {ranges_file}: {exc}")
            return None
    cached = GoogleRanges.load_cache(state_dir) if state_dir else None
    if cached is not None and cached.is_fresh(now):
        return cached
    if get_json is not None:
        try:
            fresh = fetch_google_ranges(get_json, now)
            if write_cache and state_dir:
                fresh.save_cache(state_dir)
            return fresh
        except Exception as exc:  # network, TLS, JSON
            warn(f"bots: Google IP lists not available ({exc.__class__.__name__}); using last known copy")
    return cached
