"""One collector run: config → read → build records → batch → send → commit offsets."""
from __future__ import annotations

import datetime as dt
import gzip
import json
import os
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, TextIO, Tuple

from . import files as filemod
from .config import Config, token_hint
from .privacy import DayKeys, Pseudonymizer
from .records import MAX_ERROR_LINE, MAX_LINE_BYTES, RecordBuilder, Settings
from .rules import ScanRules
from .state import RunLock, State, ensure_dir
from .transport import HttpClient, IngestClient, IngestError, build_opener, google_json_fetcher
from .verify import DnsVerifier, GooglebotVerifier, load_ranges

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_AUTH = 3
EXIT_DEFERRED = 75  # EX_TEMPFAIL: try again later (quota, rate limit, outage, network)

MAX_BATCH_LINES = 50_000
MAX_BATCH_GZIP = 8 * 1024 * 1024
MAX_BATCH_RAW = 16 * 1024 * 1024  # well below the gateway's 32 MiB decompressed limit


@dataclass
class Limits:
    """Batch and line limits; the server may lower them via ``limits`` in ``/ingest/config``."""

    lines: int = MAX_BATCH_LINES
    gzip_bytes: int = MAX_BATCH_GZIP
    raw_bytes: int = MAX_BATCH_RAW
    line_bytes: int = MAX_LINE_BYTES
    per_minute: int = 60
    max_age_seconds: int = 30 * 86400
    error_bytes: int = MAX_ERROR_LINE

    @classmethod
    def from_config(cls, data: Optional[dict]) -> "Limits":
        limits = cls()
        if not isinstance(data, dict):
            return limits

        def pick(names: Tuple[str, ...], current: int, floor: int) -> int:
            for name in names:
                value = data.get(name)
                if isinstance(value, int) and not isinstance(value, bool) and value >= floor:
                    return min(current, value)
            return current

        limits.lines = pick(("maxLines", "maxBatchLines"), limits.lines, 1)
        limits.gzip_bytes = pick(("maxCompressedBytes", "maxBatchBytes"), limits.gzip_bytes, 64 * 1024)
        limits.raw_bytes = pick(("maxBytes", "maxDecompressedBytes"), limits.raw_bytes, 64 * 1024)
        limits.line_bytes = pick(("maxLineBytes",), limits.line_bytes, 1024)
        limits.per_minute = pick(("maxBatchesPerMinute",), limits.per_minute, 1)
        limits.max_age_seconds = pick(("maxAgeSeconds",), limits.max_age_seconds, 3600)
        limits.error_bytes = pick(("errorMessageBytes",), limits.error_bytes, 256)
        return limits


@dataclass
class Batch:
    unit: filemod.Unit
    start: int
    end: int = 0
    lines: List[Tuple[bytes, int]] = field(default_factory=list)  # (ndjson line, end offset of its log line)
    raw: int = 0

    @property
    def batch_id(self) -> str:
        return batch_id(self.unit, self.start, self.end)


def batch_id(unit: filemod.Unit, start: int, end: int) -> str:
    """Deterministic ID from file identity and byte range; ``[A-Za-z0-9._:-]``, at most 128 characters."""
    return f"{unit.batch_prefix}:{start}-{end}"[:128]


def gzip_body(lines: List[Tuple[bytes, int]]) -> bytes:
    return gzip.compress(b"\n".join(line for line, _ in lines) + b"\n", compresslevel=6, mtime=0)


def _int(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


class Stop(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class SendStats:
    batches: int = 0
    lines: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    gzip_bytes: int = 0
    reject_reasons: Dict[str, int] = field(default_factory=dict)


class Runner:
    def __init__(
        self,
        cfg: Config,
        dry_run: bool = False,
        offline: bool = False,
        out: TextIO = sys.stdout,
        err: TextIO = sys.stderr,
        now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
        client: Optional[IngestClient] = None,
        ranges_fetcher: Optional[Callable[[str], dict]] = None,
        dns: Optional[DnsVerifier] = None,
        samples: int = 6,
        quiet: bool = False,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.cfg = cfg
        self.dry_run = dry_run
        self.offline = offline
        self.out = out
        self.err = err
        self.now = now
        self.client = client
        self.ranges_fetcher = ranges_fetcher
        self.dns = dns
        self.sample_limit = samples
        self.quiet = quiet
        self.samples: Dict[str, bytes] = {}
        self.sent = SendStats()
        self.state: Optional[State] = None
        self.limits = Limits()
        self.retry_at: Optional[float] = None
        self.sleep = sleep
        self._posts: Deque[float] = deque()

    # output -------------------------------------------------------------------------------------
    def warn(self, message: str) -> None:
        print(f"mavirank-collector: {message}", file=self.err)

    def info(self, message: str) -> None:
        if not self.quiet:
            print(message, file=self.out)

    # setup --------------------------------------------------------------------------------------
    def _client(self) -> IngestClient:
        if self.client is None:
            http = HttpClient(build_opener(self.cfg.ca_file), self.cfg.timeout)
            self.client = IngestClient(http, self.cfg.api_base, self.cfg.token)
        return self.client

    def _remote_config(self, state: State) -> Optional[dict]:
        cached = state.data.get("config") if isinstance(state.data.get("config"), dict) else None
        if self.offline:
            return cached.get("body") if cached else None
        try:
            resp, body = self._client().get_config(cached.get("etag") if cached else None)
        except IngestError as exc:
            if exc.kind == "auth":
                raise Stop(EXIT_AUTH, f"token rejected by the server ({exc}); token {token_hint(self.cfg.token)}")
            if self.dry_run:
                self.warn(f"config not available ({exc}); dry run continues with local defaults")
                return cached.get("body") if cached else None
            if cached:
                self.warn(f"config not available ({exc}); using the cached copy")
                return cached.get("body")
            raise Stop(EXIT_DEFERRED, f"config not available ({exc})")
        if body is None:  # 304
            return cached.get("body") if cached else None
        state.data["config"] = {"etag": resp.headers.get("etag"), "body": body, "fetchedAt": time.time()}
        return body

    # main ---------------------------------------------------------------------------------------
    def run(self) -> int:
        lock: Optional[RunLock] = None
        if not self.dry_run:
            try:
                ensure_dir(self.cfg.state_dir)
            except OSError as exc:
                self.warn(f"state directory {self.cfg.state_dir} not usable: {exc.strerror}")
                return EXIT_CONFIG
            lock = RunLock(self.cfg.state_dir)
            if not lock.acquire():
                self.warn("another run is in progress; nothing to do")
                return EXIT_OK
        try:
            return self._run()
        except Stop as stop:
            self.warn(str(stop))
            return stop.code
        finally:
            if lock is not None:
                lock.release()

    def _run(self) -> int:
        now = self.now()
        state = State(self.cfg.state_dir if os.path.isdir(self.cfg.state_dir) else None, readonly=self.dry_run)
        self.state = state
        not_before = float(state.data.get("retryNotBefore") or 0)
        if not self.dry_run and not_before > now.timestamp():
            wait = int(not_before - now.timestamp())
            self.warn(f"server asked to wait; next attempt in {wait} s")
            self.retry_at = not_before
            return EXIT_DEFERRED

        remote = self._remote_config(state)
        if remote is None and not self.dry_run:
            raise Stop(EXIT_DEFERRED, "no ingest config available yet")
        remote = remote or {}
        hostnames = remote.get("hostnames")
        if isinstance(hostnames, list):
            hostnames = [str(h).lower() for h in hostnames if isinstance(h, str)]
        elif self.dry_run:
            hostnames = self.cfg.hostnames or None  # None = no filter (offline preview)
        else:
            raise Stop(EXIT_ERROR, "ingest config has no hostnames")
        settings = Settings.from_config(remote.get("settings"))
        rules = ScanRules.from_config(remote.get("scanRules"), str(remote.get("configVersion") or "")) or ScanRules.builtin()
        self.limits = Limits.from_config(remote.get("limits"))

        keys = DayKeys(self.cfg.state_dir, now.date(), ephemeral=self.dry_run)
        verifier = None
        if self.cfg.verify_bots:
            fetcher = None
            if not self.offline:
                fetcher = self.ranges_fetcher or google_json_fetcher(HttpClient(build_opener(), 15))
            ranges = load_ranges(
                self.cfg.state_dir if os.path.isdir(self.cfg.state_dir) else None,
                self.cfg.ranges_file, fetcher, write_cache=not self.dry_run, now=now.timestamp(), warn=self.warn,
            )
            dns = None if self.offline else (self.dns or DnsVerifier())
            verifier = GooglebotVerifier(ranges, dns)
        builder = RecordBuilder(
            settings, hostnames, self.cfg.domain, rules, Pseudonymizer(keys), verifier, now, self.cfg.tzinfo(),
            max_age=dt.timedelta(seconds=self.limits.max_age_seconds), line_bytes=self.limits.line_bytes,
            error_bytes=self.limits.error_bytes,
        )

        paths = [(p, "access") for p in filemod.discover(self.cfg.access_logs)]
        if settings.error_log:
            paths += [(p, "error") for p in filemod.discover(self.cfg.error_logs)]
        if not paths:
            self.warn("no log files found for the configured patterns")
        units = filemod.plan_units(state.files, paths, now.timestamp(), self.warn)

        code = EXIT_OK
        try:
            for unit in units:
                self._process_unit(unit, builder, state)
        except Stop as stop:
            self.warn(str(stop))
            code = stop.code
        finally:
            keys.cleanup()
            state.save()

        self._summary(builder, settings, rules, hostnames, verifier, units, code)
        return code

    def _process_unit(self, unit: filemod.Unit, builder: RecordBuilder, state: State) -> None:
        handle = builder.access if unit.log == "access" else builder.error
        batch = Batch(unit, unit.start, unit.start)
        try:
            for text, _begin, end in filemod.read_lines(unit.path, unit.start):
                batch.end = end
                if text is None:
                    builder.stats.lines += 1
                    builder.stats.skip("too_long")
                    continue
                data, _reason = handle(text)
                if data is None:
                    continue
                self._sample(data)
                batch.lines.append((data, end))
                batch.raw += len(data) + 1
                if len(batch.lines) >= self.limits.lines or batch.raw >= self.limits.raw_bytes:
                    self._flush(batch, state)
                    batch = Batch(unit, end, end)
        except OSError as exc:
            self.warn(f"logs: cannot read {unit.path}: {exc.strerror}")
            return
        self._flush(batch, state)
        if unit.slot == "old":
            filemod.finish_old(state.files, unit)

    def _flush(self, batch: Batch, state: State) -> None:
        if batch.end <= batch.start:
            return
        if not batch.lines:
            filemod.commit(state.files, batch.unit, batch.end)  # only skipped lines
            return
        self._send(batch, state)

    def _send(self, batch: Batch, state: State) -> None:
        body = gzip_body(batch.lines)
        if len(body) > self.limits.gzip_bytes and len(batch.lines) > 1:
            self._split(batch, state)
            return
        if self.dry_run:
            self.sent.batches += 1
            self.sent.lines += len(batch.lines)
            self.sent.gzip_bytes += len(body)
            filemod.commit(state.files, batch.unit, batch.end)
            return
        self._pace()
        try:
            result = self._client().post_logs(batch.batch_id, body)
        except IngestError as exc:
            if exc.kind == "too_large" and len(batch.lines) > 1:
                self._split(batch, state)
                return
            if exc.kind == "auth":
                raise Stop(EXIT_AUTH, f"ingest rejected the token or source ({exc}); token {token_hint(self.cfg.token)}")
            if exc.kind == "defer":
                if exc.retry_after:
                    self.retry_at = self.now().timestamp() + exc.retry_after
                    state.data["retryNotBefore"] = self.retry_at
                raise Stop(EXIT_DEFERRED, f"ingest deferred ({exc}); will retry" + (
                    f" in {exc.retry_after} s" if exc.retry_after else " on the next run"))
            raise Stop(EXIT_ERROR, f"ingest failed ({exc}); batch {batch.batch_id}")
        self.sent.batches += 1
        self.sent.lines += len(batch.lines)
        self.sent.gzip_bytes += len(body)
        if result.get("duplicate") is True:
            self.sent.duplicates += 1
        self.sent.accepted += _int(result.get("accepted"))
        self.sent.rejected += _int(result.get("rejected"))
        reasons = result.get("rejectReasons")
        if isinstance(reasons, dict):
            for key, value in reasons.items():
                if isinstance(value, int):
                    self.sent.reject_reasons[key] = self.sent.reject_reasons.get(key, 0) + value
        state.data["retryNotBefore"] = 0
        filemod.commit(state.files, batch.unit, batch.end)
        state.save()

    def _pace(self) -> None:
        """Stay below the gateway's batches per minute (a little margin for clock jitter)."""
        allowed = max(1, self.limits.per_minute - 2)
        now = time.monotonic()
        while self._posts and now - self._posts[0] >= 60:
            self._posts.popleft()
        if len(self._posts) >= allowed:
            self.sleep(60 - (now - self._posts[0]))
            self._posts.popleft()
        self._posts.append(time.monotonic())

    def _split(self, batch: Batch, state: State) -> None:
        half = len(batch.lines) // 2
        first = Batch(batch.unit, batch.start, batch.lines[half - 1][1], batch.lines[:half])
        second = Batch(batch.unit, first.end, batch.end, batch.lines[half:])
        self._send(first, state)
        self._send(second, state)

    SAMPLE_ORDER = ("googlebot-true", "googlebot-false", "scan", "error", "human", "5xx", "bot-ai", "bot-search",
                    "googlebot-unchecked", "bot-seo", "bot-script", "bot-social", "bot-monitor", "bot-shopping", "bot-other")

    def _sample(self, data: bytes) -> None:
        if not self.dry_run or self.sample_limit <= 0:
            return
        rec = json.loads(data)
        if rec.get("log") == "error":
            kind = "error"
        elif "net" in rec:
            kind = "scan"
        elif rec.get("bot") == "Googlebot":
            kind = "googlebot-" + rec.get("bot_verified", "unchecked")
        elif "bot" in rec:
            kind = "bot-" + rec.get("bot_kind", "other")
        elif rec.get("status", "").startswith("5"):
            kind = "5xx"
        else:
            kind = "human"
        self.samples.setdefault(kind, data)

    # summary ------------------------------------------------------------------------------------
    def _summary(self, builder, settings, rules, hostnames, verifier, units, code) -> None:
        st = builder.stats
        if not self.dry_run:
            if code == EXIT_OK:
                self.info(
                    f"sent {self.sent.lines} lines in {self.sent.batches} batches "
                    f"(accepted {self.sent.accepted}, rejected {self.sent.rejected}, duplicates {self.sent.duplicates}); "
                    f"read {st.lines} lines, skipped {sum(st.skipped.values())}"
                )
            return
        out = []
        out.append("DRY RUN - nothing was sent and no state was written")
        out.append(f"  config:      {'offline (local defaults)' if self.offline else 'server'}; "
                   f"scan rules {rules.version or 'config'} ({len(rules.patterns)})")
        out.append(f"  hostnames:   {', '.join(hostnames) if hostnames else '(no filter, offline preview)'}")
        out.append(f"  settings:    errorLog={settings.error_log} queryStringMode={settings.query_mode} scanNet={settings.scan_net}")
        for unit in units:
            out.append(f"  file:        {unit.path} ({unit.log}, from byte {unit.start})")
        out.append(f"  lines read:  {st.lines}")
        out.append(f"  records:     access {st.records['access']}, error {st.records['error']}")
        if st.skipped:
            out.append("  skipped:     " + ", ".join(f"{k} {v}" for k, v in sorted(st.skipped.items())))
        if st.domains:
            out.append("  domains:     " + ", ".join(f"{k} {v}" for k, v in sorted(st.domains.items())))
        if st.bots:
            top = sorted(st.bots.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
            out.append("  bots:        " + ", ".join(f"{k} {v}" for k, v in top))
        if verifier is not None:
            src = verifier.ranges.source if verifier.ranges is not None else "none"
            out.append(f"  googlebot:   verified {verifier.stats['true']}, not verified {verifier.stats['false']}, "
                       f"unchecked {verifier.stats['unchecked']} (ranges: {src})")
        out.append(f"  scans (net): {st.scans}")
        out.append(f"  batches:     {self.sent.batches} ({self.sent.lines} lines, {self.sent.gzip_bytes} bytes gzip)")
        if self.samples:
            out.append("  samples:")
            kinds = sorted(self.samples, key=lambda k: self.SAMPLE_ORDER.index(k) if k in self.SAMPLE_ORDER else 99)
            for kind in kinds[: self.sample_limit]:
                out.append(f"    [{kind}] {self.samples[kind].decode('utf-8')}")
        for line in out:
            print(line, file=self.out)
