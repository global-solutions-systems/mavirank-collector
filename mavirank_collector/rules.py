"""Scan rules: path patterns that mark a rejected (4xx) request as a scan.

The authoritative, versioned list comes from ``GET /ingest/config`` (``scanRules``). The
built-in list is only used offline (dry run without connection) or before the first
successful config fetch. Rules only decide whether the shortened network ``net`` is sent.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, List, Optional, Pattern

DEFAULT_SCAN_PATTERNS = (
    r"(^|/)\.env(\.|$)",
    r"(^|/)\.git(/|$)",
    r"(^|/)\.(aws|ssh|docker|svn|hg|htpasswd)(/|$)",
    r"(^|/)wp-login\.php$",
    r"(^|/)wp-admin(/|$)",
    r"(^|/)xmlrpc\.php$",
    r"(^|/)(phpmyadmin|pma|myadmin|adminer)(/|\.php|$)",
    r"\.(sql|bak|old|orig|swp|save)$",
    r"(^|/)cgi-bin/",
    r"(^|/)vendor/phpunit/",
    r"(^|/)(config|credentials|secrets)\.(json|ya?ml|php\.bak)$",
    r"(^|/)server-(status|info)$",
    r"(^|/)(shell|cmd|eval-stdin)\.php$",
    r"(^|/)actuator(/|$)",
)

MAX_RULES = 500
MAX_PATTERN_LENGTH = 500


class ScanRules:
    def __init__(self, patterns: Iterable[str], version: str = "builtin"):
        self.version = version
        self.patterns: List[Pattern[str]] = []
        self.invalid = 0
        for pattern in list(patterns)[:MAX_RULES]:
            if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN_LENGTH:
                self.invalid += 1
                continue
            try:
                self.patterns.append(re.compile(_pcre_to_python(pattern), re.IGNORECASE))
            except re.error:
                self.invalid += 1

    def matches(self, status: str, path: str) -> bool:
        if not status.startswith("4") or not path:
            return False
        bare = path.split("?", 1)[0]  # like the backend: the path without query string
        return any(p.search(bare) for p in self.patterns)

    @classmethod
    def builtin(cls) -> "ScanRules":
        return cls(DEFAULT_SCAN_PATTERNS)

    @classmethod
    def from_config(cls, value: Any, version: Optional[str] = None) -> Optional["ScanRules"]:
        """Accept ``["regex", …]``, ``[{"pattern"|"regex": …}, …]`` or ``{"version": …, "rules": […]}``."""
        if isinstance(value, dict):
            version = str(value.get("version") or version or "")
            value = value.get("rules") or value.get("patterns")
        if not isinstance(value, list):
            return None
        patterns = []
        for item in value:
            if isinstance(item, str):
                patterns.append(item)
            elif isinstance(item, dict):
                pat = item.get("pattern") or item.get("regex") or item.get("path")
                if isinstance(pat, str):
                    patterns.append(pat)
        return cls(patterns, version or "config")


def _pcre_to_python(pattern: str) -> str:
    """Accept PCRE-style delimiters (``#…#i``, ``/…/i``) as the backend may send them."""
    if len(pattern) >= 2 and pattern[0] in "#/~" and pattern[0] in pattern[1:]:
        end = pattern.rfind(pattern[0])
        if end > 0 and re.fullmatch(r"[imsxu]*", pattern[end + 1:]):
            return pattern[1:end]
    return pattern
