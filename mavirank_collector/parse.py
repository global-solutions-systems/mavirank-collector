"""Parsers for access logs (combined, optionally with a leading virtual host) and error logs.

Access (nginx ``combined`` and Apache ``combined`` are the same layout)::

    [vhost[:port] ]client ident user [10/Nov/2026:13:55:36 +0100] "GET /x HTTP/1.1" 200 512 "referer" "agent"

Apache ``vhost_combined`` (``%v:%p`` first) and nginx formats that start with ``$host``
are recognised by the extra token before the client address.

Error logs::

    nginx:  2026/11/10 13:55:36 [error] 123#123: *5 message, client: 192.0.2.1, server: example.com, host: "example.com"
    Apache: [Tue Nov 10 13:55:36.123456 2026] [core:error] [pid 1:tid 2] [client 192.0.2.1:5555] AH00128: message
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
import time
from typing import NamedTuple, Optional

MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

_Q = r'"((?:[^"\\]|\\.)*)"'
ACCESS_RE = re.compile(
    r"^(?:(?P<vhost>[A-Za-z0-9._-]+(?::\d{1,5})?) )?"
    r"(?P<client>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    + _Q.replace("(", "(?P<request>", 1)
    + r" (?P<status>\d{3}) (?P<size>\d+|-)"
    r"(?: " + _Q.replace("(", "(?P<referer>", 1) + r" " + _Q.replace("(", "(?P<agent>", 1) + r")?"
)
ACCESS_TIME_RE = re.compile(r"^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")

NGINX_ERROR_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2}) (?P<hms>\d{2}:\d{2}:\d{2}) \[(?P<level>[a-z]+)\] \d+#\d+: (?:\*\d+ )?(?P<msg>.*)$"
)
NGINX_FIELD_RE = re.compile(r', (client|server|host): ("([^"]*)"|[^,]*)')
APACHE_ERROR_RE = re.compile(
    r"^\[(?:[A-Z][a-z]{2}) (?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2})(?:\.\d+)? (?P<year>\d{4})\] "
    r"(?:\[(?:(?P<module>[A-Za-z0-9_]*):)?(?P<level>[a-z0-9]+)\] )?"
    r"(?:\[pid [^\]]*\] )?"
    r"(?:\[client (?P<client>\[[^\]]+\](?::\d+)?|[^\]]+)\] )?"
    r"(?P<msg>.*)$"
)
LEVELS = ("emerg", "alert", "crit", "error", "warn", "notice", "info", "debug")
METHOD_RE = re.compile(r"^[A-Z][A-Z_-]{0,15}$")
PROTOCOL_RE = re.compile(r"^HTTP/\d(?:\.\d)?$")


class AccessLine(NamedTuple):
    vhost: Optional[str]
    client: str
    time: dt.datetime  # aware
    request: str
    method: Optional[str]
    target: Optional[str]
    protocol: Optional[str]
    status: str
    size: str
    referer: str
    user_agent: str


class ErrorLine(NamedTuple):
    time: dt.datetime  # aware
    level: str
    module: Optional[str]
    client: Optional[str]
    host: Optional[str]
    message: str
    server: str  # "nginx" or "apache"


def _unescape(value: str) -> str:
    # Apache escapes " and \ with a backslash; nginx writes \x22. Keep other escapes as they are.
    return value.replace('\\"', '"').replace("\\x22", '"').replace("\\\\", "\\")


def parse_access_time(text: str) -> Optional[dt.datetime]:
    m = ACCESS_TIME_RE.match(text)
    if not m:
        return None
    day, mon, year, hh, mi, ss, sign, oh, om = m.groups()
    month = MONTHS.get(mon)
    if month is None:
        return None
    offset = dt.timedelta(hours=int(oh), minutes=int(om))
    try:
        return dt.datetime(
            int(year), month, int(day), int(hh), int(mi), int(ss),
            tzinfo=dt.timezone(offset if sign == "+" else -offset),
        )
    except ValueError:
        return None


def parse_access(line: str) -> Optional[AccessLine]:
    m = ACCESS_RE.match(line)
    if not m:
        return None
    when = parse_access_time(m.group("time"))
    if when is None:
        return None
    request = _unescape(m.group("request"))
    method = target = protocol = None
    parts = request.split(" ")
    if len(parts) == 3 and METHOD_RE.match(parts[0]) and PROTOCOL_RE.match(parts[2]) and parts[1]:
        method, target, protocol = parts
    elif len(parts) == 2 and METHOD_RE.match(parts[0]) and parts[1].startswith("/"):
        method, target = parts  # HTTP/0.9 style
    vhost = m.group("vhost")
    if vhost is not None and m.group("client") and not _looks_like_client(m.group("client")):
        return None
    size = m.group("size")
    return AccessLine(
        vhost=vhost,
        client=m.group("client"),
        time=when,
        request=request,
        method=method,
        target=target,
        protocol=protocol,
        status=m.group("status"),
        size="0" if size == "-" else size,
        referer=_unescape(m.group("referer") or ""),
        user_agent=_unescape(m.group("agent") or ""),
    )


def _looks_like_client(token: str) -> bool:
    # With a leading vhost the next token is the client: an IP or a resolved host name.
    return bool(re.match(r"^[0-9A-Za-z.:_\[\]-]+$", token))


def _local_time(naive: dt.datetime, tz: Optional[dt.tzinfo]) -> dt.datetime:
    if tz is not None:
        return naive.replace(tzinfo=tz)
    # system local time incl. DST at that moment
    local = time.localtime(time.mktime(naive.timetuple()))
    return naive.replace(tzinfo=dt.timezone(dt.timedelta(seconds=local.tm_gmtoff)))


def normalize_level(level: str) -> str:
    level = level.lower()
    if level.startswith("trace"):
        return "debug"
    if level == "warning":
        return "warn"
    if level in ("err",):
        return "error"
    if level in ("emergency",):
        return "emerg"
    if level in ("critical",):
        return "crit"
    return level if level in LEVELS else "notice"


def parse_error(line: str, tz: Optional[dt.tzinfo] = None) -> Optional[ErrorLine]:
    m = NGINX_ERROR_RE.match(line)
    if m:
        try:
            naive = dt.datetime.strptime(m.group("date") + " " + m.group("hms"), "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
        fields = {}
        for fm in NGINX_FIELD_RE.finditer(m.group("msg")):
            fields.setdefault(fm.group(1), fm.group(3) if fm.group(3) is not None else fm.group(2).strip())
        host = fields.get("host") or fields.get("server")
        return ErrorLine(
            time=_local_time(naive, tz),
            level=normalize_level(m.group("level")),
            module=None,
            client=fields.get("client"),
            host=host if host and host not in ("_", "localhost") else None,
            message=m.group("msg"),
            server="nginx",
        )
    m = APACHE_ERROR_RE.match(line)
    if m:
        month = MONTHS.get(m.group("mon"))
        if month is None:
            return None
        try:
            hh, mi, ss = (int(x) for x in m.group("hms").split(":"))
            naive = dt.datetime(int(m.group("year")), month, int(m.group("day")), hh, mi, ss)
        except ValueError:
            return None
        client = m.group("client")
        if client:
            client = _apache_client(client)
        return ErrorLine(
            time=_local_time(naive, tz),
            level=normalize_level(m.group("level") or "error"),
            module=m.group("module") or None,
            client=client,
            host=None,
            message=m.group("msg"),
            server="apache",
        )
    return None


def _apache_client(value: str) -> str:
    """Apache 2.4 writes ``[client <addr>:<port>]``, also for IPv6 without brackets."""
    value = value.strip()
    if value.startswith("["):
        return _strip_port(value)
    head, sep, tail = value.rpartition(":")
    if sep and tail.isdigit():
        try:
            ipaddress.ip_address(head)
            return head
        except ValueError:
            pass
    return value


def _strip_port(value: str) -> str:
    value = value.strip()
    if value.startswith("["):
        return value[1:value.index("]")] if "]" in value else value
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value
