"""Command line: ``mavirank-collector [--config PATH] run [--dry-run] [--offline] [--every SEC] | check``."""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import os
import signal
import sys
import threading
import time
from typing import List, Optional, TextIO

from . import __version__
from .config import (CONFIG_ENV, SYSTEM_CONFIG_PATH, Config, ConfigError, default_config_path, is_root,
                     load_config, token_hint, user_config_path)
from .files import discover, read_lines
from .parse import parse_access, parse_error
from .runner import EXIT_AUTH, EXIT_CONFIG, EXIT_DEFERRED, EXIT_ERROR, EXIT_OK, Runner
from .transport import HttpClient, IngestClient, IngestError, build_opener, google_json_fetcher
from .verify import GOOGLE_RANGE_URLS, GoogleRanges

MIN_EVERY = 60
AUTH_BACKOFF = 3600
SKEW_WARN = 60
SKEW_FAIL = 300


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mavirank-collector",
        description="Ships pseudonymised web server logs to the mavirank log analysis.",
    )
    default = os.environ[CONFIG_ENV] if CONFIG_ENV in os.environ else default_config_path()
    parser.add_argument("--config", default=default,
                        help=f"configuration file (default ${CONFIG_ENV}, else {user_config_path()}; "
                             f"{SYSTEM_CONFIG_PATH} if only that one exists)")
    parser.add_argument("--version", action="version", version=f"mavirank-collector {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="read new log lines and send them (one pass, for cron)")
    run.add_argument("--dry-run", action="store_true", help="parse and pseudonymise, print a summary, send nothing")
    run.add_argument("--offline", action="store_true", help="with --dry-run: do not contact any server")
    run.add_argument("--every", type=int, metavar="SECONDS",
                     help=f"repeat forever with this pause (container mode, at least {MIN_EVERY})")
    run.add_argument("--samples", type=int, default=6, help="sample records shown by --dry-run (default 6)")
    run.add_argument("--quiet", action="store_true", help="no summary line on success")
    sub.add_parser("check", help="check configuration, log files, server connection, token and clock")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return cmd_check(args.config)
    if args.offline and not args.dry_run:
        print("mavirank-collector: --offline is only allowed together with --dry-run", file=sys.stderr)
        return EXIT_CONFIG
    if args.every is not None and (args.dry_run or args.every < MIN_EVERY):
        print(f"mavirank-collector: --every needs at least {MIN_EVERY} seconds and no --dry-run", file=sys.stderr)
        return EXIT_CONFIG
    try:
        cfg = load_config(args.config, require_remote=not args.offline)
    except ConfigError as exc:
        print(f"mavirank-collector: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    if args.every is None:
        return Runner(cfg, dry_run=args.dry_run, offline=args.offline, samples=max(0, args.samples),
                      quiet=args.quiet).run()
    return run_forever(cfg, args.every, args.quiet)


def run_forever(cfg: Config, every: int, quiet: bool) -> int:
    stop = threading.Event()

    def handle(signum, frame):  # noqa: ARG001
        stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)
    while not stop.is_set():
        runner = Runner(cfg, quiet=quiet)
        code = runner.run()
        if code == EXIT_CONFIG:
            return code
        pause = every
        if code == EXIT_AUTH:
            pause = max(every, AUTH_BACKOFF)
        elif code == EXIT_DEFERRED and runner.retry_at:
            pause = max(every, int(runner.retry_at - time.time()) + 1)
        stop.wait(pause)
    return EXIT_OK


# check ------------------------------------------------------------------------------------------

class Checker:
    def __init__(self, out: TextIO):
        self.out = out
        self.failed = False

    def ok(self, msg: str) -> None:
        print(f"[ OK ] {msg}", file=self.out)

    def warn(self, msg: str) -> None:
        print(f"[WARN] {msg}", file=self.out)

    def fail(self, msg: str) -> None:
        self.failed = True
        print(f"[FAIL] {msg}", file=self.out)


def _tail_lines(path: str, count: int = 50) -> List[str]:
    size = os.path.getsize(path)
    start = max(0, size - 256 * 1024)
    lines = [t for t, _, _ in read_lines(path, start) if t is not None]
    if start > 0:
        lines = lines[1:]
    return lines[-count:]


def _owner(path: str) -> str:
    """``owner user:group, mode 640`` of ``path`` (names where known, else numbers)."""
    try:
        st = os.stat(path)
    except OSError as exc:
        return f"not accessible ({exc.strerror})"
    return f"owner {_user_name(st.st_uid)}:{_group_name(st.st_gid)}, mode {st.st_mode & 0o7777:03o}"


def _user_name(uid: int) -> str:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)


def _group_name(gid: int) -> str:
    try:
        import grp

        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return str(gid)


def _identity() -> str:
    """``uid 1001 (web1), groups client1, sshusers`` of this process."""
    uid = os.geteuid()
    gids = [os.getegid()] + [g for g in os.getgroups() if g != os.getegid()]
    return f"uid {uid} ({_user_name(uid)}), groups {', '.join(_group_name(g) for g in gids)}"


def _blocking_dir(path: str) -> Optional[str]:
    """The first directory above ``path`` this process may not enter (no x permission), if any."""
    directory = os.path.dirname(os.path.abspath(path))
    parts: List[str] = []
    while True:
        parts.append(directory)
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    for directory in reversed(parts):
        if os.path.isdir(directory) and not os.access(directory, os.X_OK):
            return directory
    return None


def unreadable_hint(path: str) -> str:
    """Explain to a non-root user why ``path`` cannot be read: owner, group, mode and own groups."""
    blocked = _blocking_dir(path)
    if blocked:
        where = f"directory {blocked} is not accessible ({_owner(blocked)})"
    else:
        where = f"file {_owner(path)}"
    return (f"{where}; this process runs as {_identity()}. Ask your hosting provider for read access "
            f"to your own logs (e.g. a group you belong to) or point [logs] to a copy you can read")


def _glob_root(pattern: str) -> str:
    """Longest leading directory of ``pattern`` without glob characters."""
    head = pattern
    while glob.has_magic(head):
        head = os.path.dirname(head)
    return head or "."


def _hidden_reason(pattern: str) -> Optional[str]:
    """Why ``pattern`` may match nothing for this user: a directory that cannot be entered or listed."""
    top = _glob_root(pattern)
    blocked = _blocking_dir(os.path.join(top, "x"))
    if blocked:
        return f"directory {blocked} cannot be entered: {_owner(blocked)}"
    if glob.has_magic(pattern) and os.path.isdir(top) and not os.access(top, os.R_OK):
        return f"directory {top} cannot be listed: {_owner(top)}"
    return None


def cmd_check(config_path: str, out: TextIO = sys.stdout, client: Optional[IngestClient] = None) -> int:
    c = Checker(out)
    print(f"mavirank-collector {__version__}", file=out)
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        c.fail(str(exc))
        return EXIT_ERROR
    c.ok(f"configuration {config_path}")
    c.ok(f"ingest URL {cfg.api_base}/ingest/logs, token {token_hint(cfg.token)}")
    if cfg.ingest_url.startswith("http://"):
        c.warn("plain http:// is enabled (allow_insecure_http); use https in production")
    try:
        mode = os.stat(config_path).st_mode & 0o777
        if mode & 0o077 and "MAVIRANK_COLLECTOR_TOKEN" not in os.environ:
            c.warn(f"configuration file is readable by others (mode {mode:o}); use chmod 600")
    except OSError:
        pass

    # state directory
    if os.path.isdir(cfg.state_dir):
        if os.access(cfg.state_dir, os.W_OK | os.X_OK):
            c.ok(f"state directory {cfg.state_dir}")
        else:
            c.fail(f"state directory {cfg.state_dir} is not writable")
    else:
        parent = os.path.dirname(cfg.state_dir.rstrip("/")) or "/"
        while not os.path.isdir(parent) and os.path.dirname(parent) != parent:
            parent = os.path.dirname(parent)  # missing parents are created as well
        if os.access(parent, os.W_OK | os.X_OK):
            c.ok(f"state directory {cfg.state_dir} will be created")
        else:
            c.fail(f"state directory {cfg.state_dir} is missing and {parent} is not writable")

    # log files
    root = is_root()
    vhost_seen = False
    for label, patterns, parser in (("access_log", cfg.access_logs, "access"), ("error_log", cfg.error_logs, "error")):
        if not patterns:
            continue
        found = discover(patterns)
        if not found:
            msg = f"{label}: no file matches {', '.join(patterns)}"
            reasons = [] if root else [r for r in map(_hidden_reason, patterns) if r]
            if reasons:
                msg += f" ({reasons[0]}; this process runs as {_identity()})"
            (c.fail if label == "access_log" else c.warn)(msg)
            continue
        if not root:  # a pattern hidden behind a closed directory while others match
            for pattern in patterns:
                reason = None if discover([pattern]) else _hidden_reason(pattern)
                if reason:
                    c.warn(f"{label}: no file matches {pattern} ({reason}; this process runs as {_identity()})")
        for path in found:
            try:
                sample = _tail_lines(path)
            except OSError as exc:
                if not root and isinstance(exc, PermissionError):
                    c.fail(f"{label}: {path} not readable (permission denied): {unreadable_hint(path)}")
                else:
                    c.fail(f"{label}: {path} not readable ({exc.strerror}); add the user to the group of the log files (adm)")
                continue
            if not sample:
                c.ok(f"{label}: {path} readable (empty)")
                continue
            if parser == "access":
                parsed = [parse_access(line) for line in sample]
                good = [p for p in parsed if p is not None]
                vhost_seen = vhost_seen or any(p.vhost for p in good)
            else:
                good = [p for p in (parse_error(line, cfg.tzinfo()) for line in sample) if p is not None]
            msg = f"{label}: {path} readable, {len(good)}/{len(sample)} recent lines recognised"
            if not good:
                c.fail(msg + " (unknown format: use the combined log format)")
            elif len(good) < len(sample) * 0.8:
                c.warn(msg)
            else:
                c.ok(msg)

    # server, token, clock
    if client is None:
        client = IngestClient(HttpClient(build_opener(cfg.ca_file), cfg.timeout), cfg.api_base, cfg.token)
    try:
        resp, body = client.get_config(None)
    except IngestError as exc:
        if exc.kind == "auth":
            c.fail(f"server rejected the token ({exc})")
        else:
            c.fail(f"server not reachable ({exc})")
        print("result: problems found", file=out)
        return EXIT_ERROR
    body = body or {}
    hostnames = [h for h in body.get("hostnames") or [] if isinstance(h, str)]
    c.ok(f"server reachable, token accepted (config version {body.get('configVersion', '?')})")
    settings = body.get("settings") or {}
    c.ok("allowed hostnames: " + (", ".join(hostnames) or "(none)") +
         f"; errorLog={settings.get('errorLog', True)} queryStringMode={settings.get('queryStringMode', 'mask_values')} "
         f"scanNet={settings.get('scanNet', True)}")
    if cfg.domain and hostnames and cfg.domain not in hostnames:
        c.fail(f"[logs] domain {cfg.domain} is not among the allowed hostnames")
    if not vhost_seen and not cfg.domain and len(hostnames) != 1:
        c.fail("log lines carry no virtual host; set [logs] domain to the host name of this website")
    if resp.date is not None:
        skew = time.time() - resp.date
        msg = f"clock difference to the server {skew:+.0f} s"
        if abs(skew) > SKEW_FAIL:
            c.fail(msg + " (lines may be rejected as in_future/too_old; enable NTP)")
        elif abs(skew) > SKEW_WARN:
            c.warn(msg)
        else:
            c.ok(msg)
    else:
        c.warn("server sent no Date header; clock not checked")

    # Googlebot lists
    if cfg.verify_bots:
        if cfg.ranges_file:
            try:
                ranges = GoogleRanges.from_path(cfg.ranges_file)
                c.ok(f"Googlebot ranges from {cfg.ranges_file} ({len(ranges)} networks)")
            except (OSError, ValueError) as exc:
                c.fail(f"[bots] ranges_file not usable: {exc}")
        else:
            try:
                google_json_fetcher(HttpClient(build_opener(), 15))(GOOGLE_RANGE_URLS[0])
                c.ok("Google IP lists reachable (Googlebot verification)")
            except Exception as exc:  # network
                c.warn(f"Google IP lists not reachable ({exc.__class__.__name__}); reverse DNS is used instead")
    print("result: " + ("problems found" if c.failed else "all checks passed")
          + f" ({dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')})", file=out)
    return EXIT_ERROR if c.failed else EXIT_OK
