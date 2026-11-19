"""Pseudonymisation and data minimisation.

* ``ip`` becomes ``n-`` + the first 10 hex characters of HMAC-SHA256(day key, ip).
* The day key is 32 random bytes per UTC day, stored only in the state directory
  (mode 0600) and deleted two days later. It never leaves the server.
* Keys of days older than yesterday are kept in memory only (backfill), so a
  pseudonym of an old day cannot be recomputed after the run.
* Every IP address in free text (path, request, referer, messages, user agent)
  is replaced by its pseudonym - also right after a word and a colon
  (``client:2001:db8::1``) and percent-encoded (``203%2E0%2E113%2E7``).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import urllib.parse
from typing import Dict, Optional, Tuple, Union

IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

PSEUDONYM_RE = re.compile(r"^n-[0-9a-f]{10}$")
KEY_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.key$")
KEY_BYTES = 32
KEEP_KEY_DAYS = 2  # a key of day D is deleted once today >= D + 2

# IPv6 candidates: maximal runs of hex digits, ":" and "." with at least two colons, validated
# with ipaddress afterwards (see _ipv6_run); also covers ::ffff:192.0.2.1.
_IPV6_RUN = re.compile(r"[0-9A-Fa-f:.]+")
_WORD_CHAR = re.compile(r"[A-Za-z0-9_]")
# IPv4 candidates; not part of a longer dotted number (1.2.3.4.5), but a trailing
# full stop or ":port" is fine. Leading zeros are accepted on purpose (no leak).
_IPV4_CANDIDATE = re.compile(r"(?<!\d)(?<!\d\.)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d)(?!\.\d)")
# A component between URL delimiters with at least one percent escape.
_ENCODED_COMPONENT = re.compile(r"[^/?&=#;,\s\"']*%[0-9A-Fa-f]{2}[^/?&=#;,\s\"']*")
_DECODE_ROUNDS = 3


def _ipv6_run(text: str, start: int, run: str) -> Optional[Tuple[str, str, str]]:
    """Split an IPv6 candidate run into (prefix, address, suffix), or None.

    A run right after a word (``client:2001:db8::1``, ``host:::1``) loses one leading colon as a
    separator; a run inside a word (``Class::method``, ``std::vector``) is no address. A trailing full
    stop or colon is not part of the address. The same rules as the gateway (IpLiteralMask).
    """
    if run.count(":") < 2:
        return None
    end = start + len(run)
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    if after and _WORD_CHAR.match(after):
        return None
    prefix, core = "", run
    if (before and _WORD_CHAR.match(before)) or (core.startswith(":") and not core.startswith("::")):
        if not core.startswith(":"):
            return None
        prefix, core = ":", core[1:]
    for candidate in dict.fromkeys((core, core.rstrip("."), core.rstrip(".:"))):
        if candidate and _is_ipv6(candidate):
            return prefix, candidate, core[len(candidate):]
    return None


def _is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _decoded(component: str) -> str:
    decoded = component
    for _ in range(_DECODE_ROUNDS):
        if "%" not in decoded:
            break
        nxt = urllib.parse.unquote(decoded, errors="replace")
        if nxt == decoded:
            break
        decoded = nxt
    return decoded


def _find_literals(text: str, user_agent: bool) -> bool:
    if text.count(":") >= 2:
        for m in _IPV6_RUN.finditer(text):
            if _ipv6_run(text, m.start(), m.group(0)) is not None:
                return True
    for m in _IPV4_CANDIDATE.finditer(text):
        if user_agent and m.start() > 0 and text[m.start() - 1] == "/":
            continue
        if all(int(g) <= 255 for g in m.groups()):
            return True
    return False


QUERY_MODES = ("mask_values", "keep", "strip")
MASKED_VALUE = "x"


def parse_ip(value: str) -> Optional[IpAddress]:
    value = (value or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def network_of(addr: IpAddress) -> str:
    """Shortened network for scan senders: IPv4 /24, IPv6 /48."""
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


class DayKeys:
    """Random HMAC keys per UTC day.

    ``ephemeral=True`` (dry run) never touches the disk.
    """

    def __init__(self, state_dir: Optional[str], today: dt.date, ephemeral: bool = False):
        self.dir = os.path.join(state_dir, "keys") if state_dir else None
        self.today = today
        self.ephemeral = ephemeral or not state_dir
        self._cache: Dict[dt.date, bytes] = {}

    def _persisted(self, day: dt.date) -> bool:
        return not self.ephemeral and day >= self.today - dt.timedelta(days=KEEP_KEY_DAYS - 1)

    def get(self, day: dt.date) -> bytes:
        key = self._cache.get(day)
        if key is not None:
            return key
        if self._persisted(day):
            key = self._load_or_create(day)
        else:
            key = secrets.token_bytes(KEY_BYTES)
        self._cache[day] = key
        return key

    def _load_or_create(self, day: dt.date) -> bytes:
        assert self.dir is not None
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        path = os.path.join(self.dir, day.isoformat() + ".key")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            with open(path, "rb") as fh:
                key = fh.read()
            if len(key) == KEY_BYTES:
                return key
            # damaged file: replace it
            os.unlink(path)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        key = secrets.token_bytes(KEY_BYTES)
        try:
            os.write(fd, key)
            os.fsync(fd)
        finally:
            os.close(fd)
        return key

    def cleanup(self) -> int:
        """Delete keys older than two days. Returns the number of deleted files."""
        if self.ephemeral or not self.dir or not os.path.isdir(self.dir):
            return 0
        removed = 0
        limit = self.today - dt.timedelta(days=KEEP_KEY_DAYS - 1)
        for name in os.listdir(self.dir):
            m = KEY_FILE_RE.match(name)
            if not m:
                continue
            try:
                day = dt.date.fromisoformat(m.group(1))
            except ValueError:
                continue
            if day < limit:
                os.unlink(os.path.join(self.dir, name))
                removed += 1
        for day in [d for d in self._cache if d < limit]:
            del self._cache[day]
        return removed


class Pseudonymizer:
    def __init__(self, keys: DayKeys):
        self.keys = keys

    def pseudonym(self, value: str, day: dt.date) -> str:
        addr = parse_ip(value)
        material = str(addr) if addr is not None else value.strip().lower()
        digest = hmac.new(self.keys.get(day), material.encode("utf-8"), hashlib.sha256).hexdigest()
        return "n-" + digest[:10]

    def scrub(self, text: str, day: dt.date, user_agent: bool = False) -> str:
        """Replace every IP address in ``text`` by its pseudonym.

        In user agents, dotted version numbers right after ``/`` (``Chrome/120.0.0.0``) stay.
        """
        if not text:
            return text

        def repl6(m: "re.Match[str]") -> str:
            parts = _ipv6_run(m.string, m.start(), m.group(0))
            if parts is None:
                return m.group(0)
            prefix, address, suffix = parts
            return prefix + self.pseudonym(address, day) + suffix

        def repl4(m: "re.Match[str]") -> str:
            octets = [int(g) for g in m.groups()]
            if any(o > 255 for o in octets):
                return m.group(0)
            if user_agent and m.start() > 0 and text4[m.start() - 1] == "/":
                return m.group(0)
            return self.pseudonym(".".join(str(o) for o in octets), day)

        if text.count(":") >= 2:
            text = _IPV6_RUN.sub(repl6, text)
        text4 = text
        text = _IPV4_CANDIDATE.sub(repl4, text4)
        if "%" not in text:
            return text

        def repl_encoded(m: "re.Match[str]") -> str:
            # Percent-encoded address: the component is decoded, scrubbed and encoded again.
            decoded = _decoded(m.group(0))
            if decoded == m.group(0) or not _find_literals(decoded, False):
                return m.group(0)
            return urllib.parse.quote(self.scrub(decoded, day), safe="-._~:")

        return _ENCODED_COMPONENT.sub(repl_encoded, text)


def contains_raw_ip(text: str, user_agent: bool = False) -> bool:
    """True if ``text`` contains something that parses as an IP address (used by tests and self checks).

    ``user_agent=True`` applies the same exception as :meth:`Pseudonymizer.scrub` (``Chrome/130.0.0.0``).
    """
    if _find_literals(text, user_agent):
        return True
    for m in _ENCODED_COMPONENT.finditer(text):
        decoded = _decoded(m.group(0))
        if decoded != m.group(0) and _find_literals(decoded, False):
            return True
    return False


def mask_query(target: str, mode: str) -> str:
    """Apply the query string mode to a request target (path plus optional query)."""
    if "?" not in target or mode == "keep":
        return target
    base, query = target.split("?", 1)
    if mode == "strip" or not query:
        return base
    parts = []
    for item in query.split("&"):
        if item == "":
            continue
        if "=" in item:
            name, value = item.split("=", 1)
            parts.append(name + "=" + (MASKED_VALUE if value != "" else ""))
        else:
            parts.append(item)
    return base + ("?" + "&".join(parts) if parts else "")


def clean_referer(value: str) -> Optional[str]:
    """Referer without query string and fragment; ``-`` or empty means none."""
    value = (value or "").strip()
    if value in ("", "-"):
        return None
    for sep in ("?", "#"):
        if sep in value:
            value = value.split(sep, 1)[0]
    return value or None


_URL_QUERY_IN_TEXT = re.compile(r"(\S*?)\?([^\s\"',]*)")


_REFERER_IN_TEXT = re.compile(r"(referr?er: \"?)([^\s\",]*)", re.IGNORECASE)


def mask_query_in_text(text: str, mode: str) -> str:
    """Apply the query string mode to URLs inside free text (error log messages).

    Referers in messages (``referrer: "…"`` from nginx, ``referer: …`` from Apache) lose their
    query string in every mode, like the ``referer`` field.
    """
    if "?" not in text and "#" not in text:
        return text
    text = _REFERER_IN_TEXT.sub(lambda m: m.group(1) + (clean_referer(m.group(2)) or ""), text)
    if mode == "keep" or "?" not in text:
        return text
    return _URL_QUERY_IN_TEXT.sub(lambda m: mask_query(m.group(1) + "?" + m.group(2), mode), text)
