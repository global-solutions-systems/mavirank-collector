"""Turn parsed log lines into NDJSON records for the ingest gateway (§19.4).

All values are strings. Field lengths follow the contract; text is cut on UTF-8
boundaries. Every free-text field is scrubbed of IP addresses. The raw client IP is
only used for the Googlebot check and the scan network, never sent.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import bots
from .parse import AccessLine, ErrorLine, parse_access, parse_error
from .privacy import Pseudonymizer, clean_referer, mask_query, mask_query_in_text, network_of, parse_ip
from .rules import ScanRules
from .verify import GooglebotVerifier

MAX_PATH = 2048
MAX_REQUEST = 2048
MAX_REFERER = 1024
MAX_USER_AGENT = 512
MAX_BOT = 60
MAX_MSG = 2048
MAX_ERROR_LINE = 2048
MAX_LINE_BYTES = 8192
AGE_MARGIN = dt.timedelta(minutes=15)  # the gateway checks the age again on arrival
MAX_AGE = dt.timedelta(days=30) - AGE_MARGIN

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# skip reasons (shown in dry run and summaries)
SKIP_UNPARSED = "unparsed"
SKIP_TOO_OLD = "too_old"
SKIP_NO_DOMAIN = "no_domain"
SKIP_DOMAIN = "domain_not_allowed"
SKIP_TOO_LONG = "too_long"
SKIP_EMPTY = "empty"


def cut(value: str, limit: int) -> str:
    """Cut to at most ``limit`` UTF-8 bytes without splitting a character."""
    raw = value.encode("utf-8")
    if len(raw) <= limit:
        return value
    return raw[:limit].decode("utf-8", errors="ignore")


def iso_utc(when: dt.datetime) -> str:
    return when.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


@dataclass
class Settings:
    error_log: bool = True
    query_mode: str = "mask_values"
    scan_net: bool = True

    @classmethod
    def from_config(cls, data: Optional[dict]) -> "Settings":
        data = data if isinstance(data, dict) else {}
        mode = data.get("queryStringMode", "mask_values")
        return cls(
            error_log=data.get("errorLog", True) is not False,
            query_mode=mode if mode in ("mask_values", "keep", "strip") else "mask_values",
            scan_net=data.get("scanNet", True) is not False,
        )


@dataclass
class Stats:
    lines: int = 0
    records: Dict[str, int] = field(default_factory=lambda: {"access": 0, "error": 0})
    skipped: Dict[str, int] = field(default_factory=dict)
    domains: Dict[str, int] = field(default_factory=dict)
    bots: Dict[str, int] = field(default_factory=dict)
    scans: int = 0

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


class RecordBuilder:
    def __init__(
        self,
        settings: Settings,
        hostnames: Optional[List[str]],
        default_domain: Optional[str],
        scan_rules: ScanRules,
        pseudonymizer: Pseudonymizer,
        verifier: Optional[GooglebotVerifier],
        now: dt.datetime,
        error_tz: Optional[dt.tzinfo] = None,
        max_age: dt.timedelta = dt.timedelta(days=30),
        line_bytes: int = MAX_LINE_BYTES,
        error_bytes: int = MAX_ERROR_LINE,
    ):
        self.settings = settings
        self.hostnames = set(hostnames) if hostnames is not None else None
        self.default_domain = default_domain
        if self.default_domain is None and hostnames is not None and len(hostnames) == 1:
            self.default_domain = hostnames[0]
        self.rules = scan_rules
        self.pseudo = pseudonymizer
        self.verifier = verifier
        self.now = now
        self.cutoff = now - min(MAX_AGE, max_age - AGE_MARGIN)
        self.line_bytes = min(line_bytes, MAX_LINE_BYTES)
        self.error_bytes = min(error_bytes, MAX_ERROR_LINE)
        self.error_tz = error_tz
        self.stats = Stats()

    # helpers ------------------------------------------------------------------------------------
    def _domain(self, candidate: Optional[str], strict: bool = False) -> Tuple[Optional[str], Optional[str]]:
        """Domain from the line's virtual host, else the configured default.

        ``strict``: a virtual host that is an IP address (request to the bare server IP)
        belongs to no website and is skipped instead of falling back to the default.
        """
        domain = None
        if candidate:
            domain = candidate.strip().lower().rstrip(".")
            if domain.startswith("[") or domain.count(":") > 1:
                domain = ""  # IPv6 literal
            elif ":" in domain:
                domain = domain.split(":", 1)[0]
            if domain and parse_ip(domain) is not None:
                domain = ""
            if domain == "" and strict:
                return None, SKIP_NO_DOMAIN
        if not domain:
            domain = self.default_domain
        if not domain:
            return None, SKIP_NO_DOMAIN
        if self.hostnames is not None and domain not in self.hostnames:
            return None, SKIP_DOMAIN
        return domain, None

    def _encode(self, record: Dict[str, str]) -> Optional[bytes]:
        for key, value in record.items():
            if _CONTROL.search(value):
                record[key] = _CONTROL.sub(" ", value)  # the gateway rejects control characters
        data = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(data) <= self.line_bytes:
            return data
        for key, limit in (("request", 0), ("_msg", 512), ("user_agent", 256), ("referer", 256), ("path", 1024)):
            if key in record:
                if limit == 0:
                    del record[key]
                else:
                    record[key] = cut(record[key], limit)
            data = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(data) <= self.line_bytes:
                return data
        return None

    # access -------------------------------------------------------------------------------------
    def access(self, raw: str) -> Tuple[Optional[bytes], Optional[str]]:
        self.stats.lines += 1
        line = parse_access(raw)
        if line is None:
            self.stats.skip(SKIP_UNPARSED)
            return None, SKIP_UNPARSED
        record, reason = self._access_record(line)
        if record is None:
            self.stats.skip(reason or SKIP_UNPARSED)
            return None, reason
        data = self._encode(record)
        if data is None:
            self.stats.skip(SKIP_TOO_LONG)
            return None, SKIP_TOO_LONG
        self.stats.records["access"] += 1
        self.stats.domains[record["domain"]] = self.stats.domains.get(record["domain"], 0) + 1
        if "bot" in record:
            self.stats.bots[record["bot"]] = self.stats.bots.get(record["bot"], 0) + 1
        return data, None

    def _access_record(self, line: AccessLine) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
        if line.time < self.cutoff:
            return None, SKIP_TOO_OLD
        domain, reason = self._domain(line.vhost, strict=True)
        if domain is None:
            return None, reason
        day = line.time.astimezone(dt.timezone.utc).date()
        mode = self.settings.query_mode
        scrub = self.pseudo.scrub
        rec: Dict[str, str] = {"_time": iso_utc(line.time), "log": "access", "domain": domain, "status": line.status}

        if line.target is not None:
            rec["method"] = line.method or ""
            rec["path"] = cut(scrub(mask_query(line.target, mode), day), MAX_PATH)
            if line.protocol:
                rec["protocol"] = line.protocol
            msg = f"{line.status} {rec['method']} {rec['path']}"
        else:
            request = cut(scrub(mask_query(line.request, mode), day), MAX_REQUEST)
            if request:
                rec["request"] = request
            msg = f"{line.status} {request}".rstrip()
        rec["size"] = line.size

        addr = parse_ip(line.client)
        if line.client and line.client != "-":
            rec["ip"] = self.pseudo.pseudonym(line.client, day)
        if (
            addr is not None
            and self.settings.scan_net
            and self.rules.matches(line.status, line.target or line.request)
        ):
            rec["net"] = network_of(addr)
            self.stats.scans += 1

        referer = clean_referer(line.referer)
        if referer:
            rec["referer"] = cut(scrub(referer, day), MAX_REFERER)
        ua = line.user_agent.strip()
        if ua and ua != "-":
            rec["user_agent"] = cut(scrub(ua, day, user_agent=True), MAX_USER_AGENT)
            match = bots.classify(ua)
            if match is not None:
                rec["bot"] = cut(match.name, MAX_BOT)
                rec["bot_kind"] = match.kind
                if match.variant:
                    rec["bot_variant"] = match.variant
                if match.google and self.verifier is not None:
                    verified = self.verifier.verify(line.client)  # raw IP, before pseudonymisation
                    if verified is not None:
                        rec["bot_verified"] = verified
        rec["_msg"] = cut(msg, MAX_MSG)
        if "method" in rec and not rec["method"]:
            del rec["method"]
        return rec, None

    # error --------------------------------------------------------------------------------------
    def error(self, raw: str) -> Tuple[Optional[bytes], Optional[str]]:
        self.stats.lines += 1
        line = parse_error(raw, self.error_tz)
        if line is None:
            self.stats.skip(SKIP_UNPARSED)
            return None, SKIP_UNPARSED
        record, reason = self._error_record(line)
        if record is None:
            self.stats.skip(reason or SKIP_UNPARSED)
            return None, reason
        data = self._encode(record)
        if data is None:
            self.stats.skip(SKIP_TOO_LONG)
            return None, SKIP_TOO_LONG
        self.stats.records["error"] += 1
        self.stats.domains[record["domain"]] = self.stats.domains.get(record["domain"], 0) + 1
        return data, None

    def _error_record(self, line: ErrorLine) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
        if line.time < self.cutoff:
            return None, SKIP_TOO_OLD
        domain, reason = self._domain(line.host)
        if domain is None:
            return None, reason
        day = line.time.astimezone(dt.timezone.utc).date()
        message = mask_query_in_text(line.message, self.settings.query_mode)
        message = cut(self.pseudo.scrub(cut(message, self.error_bytes * 2), day), self.error_bytes)
        rec: Dict[str, str] = {
            "_time": iso_utc(line.time),
            "log": "error",
            "domain": domain,
            "level": line.level,
            "server": line.server,
            "_msg": message or "-",
        }
        if line.module:
            rec["module"] = cut(line.module, 64)
        if line.client and line.client != "-":
            rec["ip"] = self.pseudo.pseudonym(line.client, day)
        return rec, None
