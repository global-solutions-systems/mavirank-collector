"""Configuration file (INI) handling.

The token may come from the file or from the environment variable
``MAVIRANK_COLLECTOR_TOKEN`` (the environment wins). The token is never
printed; use :func:`token_hint` for log output.
"""
from __future__ import annotations

import configparser
import datetime as dt
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

# Configuration of older installations, still found when the file in the home directory is missing.
# (The container image sets XDG_CONFIG_HOME=/etc and XDG_STATE_HOME=/var/lib instead.)
SYSTEM_CONFIG_PATH = "/etc/mavirank-collector/collector.conf"
APP_DIR = "mavirank-collector"
CONFIG_ENV = "MAVIRANK_COLLECTOR_CONFIG"
TOKEN_ENV = "MAVIRANK_COLLECTOR_TOKEN"
FORMATS = ("auto", "nginx_combined", "apache_combined")
SERVERS = ("nginx", "apache")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
TZ_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


class ConfigError(Exception):
    """Invalid or incomplete configuration."""


@dataclass
class Config:
    path: str
    ingest_url: str = ""
    token: str = ""
    allow_insecure_http: bool = False
    ca_file: Optional[str] = None
    timeout: float = 20.0
    access_logs: List[str] = field(default_factory=list)
    error_logs: List[str] = field(default_factory=list)
    log_format: str = "auto"
    server: str = "nginx"
    domain: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    timezone: str = "local"
    state_dir: str = ""
    verify_bots: bool = True
    ranges_file: Optional[str] = None

    @property
    def api_base(self) -> str:
        return api_base(self.ingest_url)

    def tzinfo(self) -> Optional[dt.tzinfo]:
        """Time zone of error log timestamps (they carry no offset). ``None`` = local time."""
        return parse_timezone(self.timezone)


def is_root() -> bool:
    """True when the process runs as uid 0."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _xdg_dir(environ: Optional[dict], variable: str, fallback: str) -> str:
    """``$XDG_…/mavirank-collector`` if the variable holds an absolute path, else ``~/<fallback>/…``."""
    env = os.environ if environ is None else environ
    base = (env.get(variable) or "").strip()
    if not os.path.isabs(base):  # the XDG spec says to ignore relative paths
        home = (env.get("HOME") or "").strip() or os.path.expanduser("~")
        base = os.path.join(home, fallback)
    return os.path.join(base, APP_DIR)


def user_config_path(environ: Optional[dict] = None) -> str:
    """Configuration of a user installation: ``~/.config/mavirank-collector/collector.conf``."""
    return os.path.join(_xdg_dir(environ, "XDG_CONFIG_HOME", ".config"), "collector.conf")


def user_state_dir(environ: Optional[dict] = None) -> str:
    """State directory of a user installation: ``~/.local/state/mavirank-collector``."""
    return _xdg_dir(environ, "XDG_STATE_HOME", os.path.join(".local", "state"))


def default_config_path(environ: Optional[dict] = None) -> str:
    """Configuration file used when neither ``--config`` nor ``MAVIRANK_COLLECTOR_CONFIG`` is given.

    ``~/.config/mavirank-collector/collector.conf`` (``$XDG_CONFIG_HOME`` respected). If only the file
    of an older installation exists (``/etc/mavirank-collector/collector.conf``), that one is used.
    """
    candidate = user_config_path(environ)
    if not os.path.isfile(candidate) and os.path.isfile(SYSTEM_CONFIG_PATH):
        return SYSTEM_CONFIG_PATH
    return candidate


def default_state_dir(environ: Optional[dict] = None) -> str:
    """State directory used when ``[state] dir`` is not set: ``~/.local/state/mavirank-collector``."""
    return user_state_dir(environ)


def missing_config_hint(path: str, environ: Optional[dict] = None) -> str:
    """Extra text for "configuration file not found" at the default location."""
    if path != user_config_path(environ):
        return ""
    return "; run install.sh to create it, or pass --config"


def token_hint(token: str) -> str:
    """Safe representation of a token for output: the 14 character prefix only."""
    if not token:
        return "(none)"
    return token[:14] + "…"


def normalize_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


def split_list(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def api_base(url: str) -> str:
    """Return ``<scheme>://<host>[/prefix]`` so that ``+ '/ingest/config'`` is the config endpoint.

    Accepted spellings: ``https://app.example.com/api/v1/ingest`` (the ``ingestUrl`` of the install
    page), ``…/api/v1/ingest/logs``, ``…/api/v1`` or just the origin (``/api/v1`` is assumed).
    """
    parts = urlsplit(url.strip())
    path = parts.path.rstrip("/")
    for suffix in ("/ingest/logs", "/ingest/config", "/ingest"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    if path == "":
        path = "/api/v1"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def parse_timezone(value: str) -> Optional[dt.tzinfo]:
    value = (value or "local").strip()
    if value.lower() == "local":
        return None
    if value.upper() in ("UTC", "Z", "GMT"):
        return dt.timezone.utc
    m = TZ_OFFSET_RE.match(value)
    if m:
        delta = dt.timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
        return dt.timezone(delta if m.group(1) == "+" else -delta)
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(value)
    except Exception as exc:  # unknown zone or no tz database
        raise ConfigError(f"[logs] timezone: unknown time zone {value!r}") from exc


def _bool(section: configparser.SectionProxy, key: str, default: bool) -> bool:
    try:
        return section.getboolean(key, fallback=default)
    except ValueError as exc:
        raise ConfigError(f"[{section.name}] {key}: expected true or false") from exc


def load_config(path: str, environ: Optional[dict] = None, require_remote: bool = True) -> Config:
    """Read and validate the configuration file.

    ``require_remote=False`` (offline dry run) accepts a missing ``ingest_url``/``token``.
    """
    env = os.environ if environ is None else environ
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as fh:
            parser.read_file(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {path}{missing_config_hint(path, environ)}") from exc
    except PermissionError as exc:
        uid = os.getuid() if hasattr(os, "getuid") else None
        hint = (
            f" by uid {uid}; give the file and its directory to this user and keep them private"
            f" (chown {uid} <dir> <file>, chmod 700 <dir>, chmod 600 <file>), never make them world-readable"
            if uid not in (None, 0) else ""
        )
        raise ConfigError(f"configuration file not readable: {path}{hint}") from exc
    except configparser.Error as exc:
        raise ConfigError(f"configuration file is not valid INI: {exc}") from exc

    for name in ("mavirank", "logs", "state", "bots"):
        if not parser.has_section(name):
            parser.add_section(name)
    m, logs, state, bots = parser["mavirank"], parser["logs"], parser["state"], parser["bots"]

    cfg = Config(path=path)
    cfg.ingest_url = m.get("ingest_url", "").strip()
    cfg.token = (env.get(TOKEN_ENV) or m.get("token", "")).strip()
    cfg.allow_insecure_http = _bool(m, "allow_insecure_http", False)
    cfg.ca_file = m.get("ca_file", "").strip() or None
    try:
        cfg.timeout = float(m.get("timeout", "20"))
    except ValueError as exc:
        raise ConfigError("[mavirank] timeout: expected seconds") from exc
    if not 1 <= cfg.timeout <= 120:
        raise ConfigError("[mavirank] timeout: must be between 1 and 120 seconds")

    cfg.access_logs = split_list(logs.get("access_log", ""))
    cfg.error_logs = split_list(logs.get("error_log", ""))
    cfg.log_format = logs.get("format", "auto").strip().lower() or "auto"
    cfg.server = logs.get("server", "nginx").strip().lower() or "nginx"
    domain = logs.get("domain", "").strip()
    cfg.domain = normalize_host(domain) if domain else None
    cfg.hostnames = [normalize_host(h) for h in split_list(logs.get("hostnames", ""))]
    cfg.timezone = logs.get("timezone", "local").strip() or "local"
    cfg.state_dir = state.get("dir", "").strip() or default_state_dir(environ)
    cfg.verify_bots = _bool(bots, "verify", True)
    cfg.ranges_file = bots.get("ranges_file", "").strip() or None

    if cfg.log_format not in FORMATS:
        raise ConfigError(f"[logs] format: expected one of {', '.join(FORMATS)}")
    if cfg.server not in SERVERS:
        raise ConfigError(f"[logs] server: expected one of {', '.join(SERVERS)}")
    if not cfg.access_logs and not cfg.error_logs:
        raise ConfigError("[logs] access_log: at least one log file (or glob) is required")
    for host in ([cfg.domain] if cfg.domain else []) + cfg.hostnames:
        if not HOSTNAME_RE.match(host):
            raise ConfigError(f"[logs] invalid host name: {host!r}")
    cfg.tzinfo()  # validates

    if require_remote or cfg.ingest_url:
        validate_remote(cfg)
    return cfg


def validate_remote(cfg: Config) -> None:
    if not cfg.ingest_url:
        raise ConfigError("[mavirank] ingest_url is missing")
    parts = urlsplit(cfg.ingest_url)
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise ConfigError("[mavirank] ingest_url: expected an https:// URL")
    if parts.scheme == "http" and not cfg.allow_insecure_http:
        raise ConfigError(
            "[mavirank] ingest_url uses http://; TLS is required (set allow_insecure_http = true only for local development)"
        )
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigError("[mavirank] ingest_url must not contain credentials, query or fragment")
    if not cfg.token:
        raise ConfigError(f"[mavirank] token is missing (or set {TOKEN_ENV})")
    if not re.fullmatch(r"mvrk_log_[A-Za-z0-9_-]{20,128}", cfg.token):
        raise ConfigError(f"[mavirank] token has an unexpected format ({token_hint(cfg.token)})")
    if cfg.ca_file and not os.path.isfile(cfg.ca_file):
        raise ConfigError(f"[mavirank] ca_file not found: {cfg.ca_file}")
