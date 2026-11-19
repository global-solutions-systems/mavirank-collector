import datetime as dt
import gzip
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from helpers import NOW, TOKEN, fixture
from mavirank_collector import __version__
from mavirank_collector.config import load_config
from mavirank_collector.runner import EXIT_AUTH, EXIT_DEFERRED, EXIT_OK, Runner
from mavirank_collector.verify import DnsVerifier

BATCH_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
CONFIG = {
    "configVersion": "3",
    "hostnames": ["example.com", "www.example.com"],
    "settings": {"errorLog": True, "queryStringMode": "mask_values", "scanNet": True},
    # same shape as the backend's IngestGateway::config()
    "scanRules": {"version": "2026-11-12.1", "rules": [
        {"id": "dotenv", "pattern": "(?i)/\\.env(\\.[a-z0-9_-]+)?$", "statuses": "4xx"},
        {"id": "vcs", "pattern": "(?i)/\\.(git|svn|hg|bzr)(/|$)", "statuses": "4xx"},
        {"id": "wordpress", "pattern": "(?i)/(wp-login\\.php|xmlrpc\\.php)", "statuses": "4xx"},
    ]},
    "limits": {"maxCompressedBytes": 8388608, "maxBytes": 33554432, "maxLines": 50000, "maxLineBytes": 8192,
               "maxBatchesPerMinute": 60, "maxParallelRequests": 2, "maxAgeSeconds": 2592000,
               "maxFutureSeconds": 300, "errorMessageBytes": 2048},
}


class Stub(BaseHTTPRequestHandler):
    server_version = "stub"

    def log_message(self, *args):
        pass

    def do_GET(self):
        srv = self.server
        srv.config_requests.append(dict(self.headers))
        if self.path != "/api/v1/ingest/config":
            return self._send(404, {"code": "not_found"})
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self._send(401, {"code": "unauthenticated"})
        if self.headers.get("If-None-Match") == '"v3"':
            self.send_response(304)
            self.end_headers()
            return
        self._send(200, srv.config, {"ETag": '"v3"'})

    def do_POST(self):
        srv = self.server
        body = self.rfile.read(int(self.headers["Content-Length"]))
        lines = gzip.decompress(body).decode("utf-8").splitlines()
        srv.posts.append({"headers": dict(self.headers), "lines": lines, "gzip": len(body)})
        status, payload, headers = srv.responses.pop(0) if srv.responses else (200, None, {})
        if status == 200 and payload is None:
            payload = {"batchId": self.headers["X-Mavirank-Batch-Id"], "duplicate": False, "accepted": len(lines),
                       "rejected": 0, "rejectReasons": {}}
        self._send(status, payload, headers)

    def _send(self, status, payload, headers=None):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if status < 400 else "application/problem+json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class StubCase(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        self.server.posts, self.server.responses, self.server.config_requests = [], [], []
        self.server.config = json.loads(json.dumps(CONFIG))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "access.log")
        shutil.copy(fixture("access.log"), self.log)
        self.errlog = os.path.join(self.tmp.name, "error.log")
        shutil.copy(fixture("error.log"), self.errlog)
        self.state = os.path.join(self.tmp.name, "state")
        self.conf = os.path.join(self.tmp.name, "collector.conf")
        with open(self.conf, "w", encoding="utf-8") as fh:
            fh.write(f"""[mavirank]
ingest_url = http://127.0.0.1:{self.server.server_address[1]}/api/v1/ingest
token = {TOKEN}
allow_insecure_http = true
timeout = 5
[logs]
access_log = {self.log}
error_log = {self.errlog}
domain = example.com
timezone = +01:00
[state]
dir = {self.state}
[bots]
ranges_file = {fixture("google-ranges")}
""")
        self.clock = NOW

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def run_once(self, **kw):
        cfg = load_config(self.conf, environ={})
        err = io.StringIO()
        dns = DnsVerifier(lambda ip: "host.example", lambda h: [], budget=0)
        runner = Runner(cfg, out=io.StringIO(), err=err, now=lambda: self.clock, dns=dns, **kw)
        code = runner.run()
        return code, err.getvalue(), runner

    def offsets(self):
        with open(os.path.join(self.state, "state.json"), encoding="utf-8") as fh:
            files = json.load(fh)["files"]
        return {os.path.basename(k): v["cur"]["offset"] for k, v in files.items()}


class RunnerTest(StubCase):
    def test_sends_everything_with_contract_headers(self):
        code, err, _ = self.run_once()
        self.assertEqual(code, EXIT_OK, err)
        self.assertEqual(len(self.server.posts), 2)  # one batch per file
        for post in self.server.posts:
            h = post["headers"]
            self.assertEqual(h["Authorization"], "Bearer " + TOKEN)
            self.assertEqual(h["Content-Type"], "application/x-ndjson")
            self.assertEqual(h["Content-Encoding"], "gzip")
            self.assertEqual(h["X-Mavirank-Collector"], f"mavirank-collector/{__version__}")
            self.assertRegex(h["X-Mavirank-Batch-Id"], BATCH_ID_RE)
            self.assertLessEqual(len(post["lines"]), 50000)
            for line in post["lines"]:
                rec = json.loads(line)
                self.assertTrue(all(isinstance(v, str) for v in rec.values()))
                self.assertIn(rec["domain"], CONFIG["hostnames"])
        sent = [json.loads(line) for p in self.server.posts for line in p["lines"]]
        self.assertTrue(any(r.get("net") in ("203.0.113.0/24", "2001:db8:dead::/48") for r in sent))
        self.assertTrue(any(r.get("bot_verified") == "true" for r in sent))
        self.assertEqual(self.offsets(), {"access.log": os.path.getsize(self.log), "error.log": os.path.getsize(self.errlog)})
        self.assertNotIn(TOKEN, err)
        # key files exist with 0600, nothing else readable by others
        for name in os.listdir(os.path.join(self.state, "keys")):
            self.assertEqual(os.stat(os.path.join(self.state, "keys", name)).st_mode & 0o077, 0)

        # second run: nothing new, config revalidated with ETag
        code, err, _ = self.run_once()
        self.assertEqual(code, EXIT_OK, err)
        self.assertEqual(len(self.server.posts), 2)
        self.assertEqual(self.server.config_requests[-1].get("If-None-Match"), '"v3"')

        # appended lines only
        with open(self.log, "a", encoding="utf-8") as fh:
            fh.write('192.0.2.10 - - [11/Nov/2026:23:00:00 +0100] "GET /new HTTP/1.1" 200 1 "-" "UA"\n')
        self.run_once()
        self.assertEqual(len(self.server.posts), 3)
        self.assertEqual(len(self.server.posts[-1]["lines"]), 1)

    def test_error_log_disabled_by_settings(self):
        self.server.config["settings"]["errorLog"] = False
        self.run_once()
        self.assertEqual(len(self.server.posts), 1)
        self.assertTrue(all(json.loads(line)["log"] == "access" for line in self.server.posts[0]["lines"]))

    def test_quota_429_retry_after_then_resume(self):
        self.server.responses = [(429, {"code": "log_quota_exceeded", "limit": "log_lines_per_day"}, {"Retry-After": "120"})]
        code, err, runner = self.run_once()
        self.assertEqual(code, EXIT_DEFERRED)
        self.assertIn("log_quota_exceeded", err)
        self.assertEqual(self.offsets()["access.log"], 0)
        first_id = self.server.posts[0]["headers"]["X-Mavirank-Batch-Id"]

        code, err, _ = self.run_once()  # still inside Retry-After: no request at all
        self.assertEqual(code, EXIT_DEFERRED)
        self.assertEqual(len(self.server.posts), 1)

        self.clock = NOW + dt.timedelta(seconds=121)
        code, err, _ = self.run_once()
        self.assertEqual(code, EXIT_OK, err)
        self.assertEqual(self.server.posts[1]["headers"]["X-Mavirank-Batch-Id"], first_id)  # deterministic
        self.assertEqual(self.offsets()["access.log"], os.path.getsize(self.log))

    def test_rate_limited_and_unavailable_defer(self):
        for status, code_name in ((429, "rate_limited"), (503, "logs_unavailable")):
            with self.subTest(status=status):
                self.server.responses = [(status, {"code": code_name}, {"Retry-After": "5"})]
                code, err, _ = self.run_once()
                self.assertEqual(code, EXIT_DEFERRED)
                self.assertIn(code_name, err)
                self.clock += dt.timedelta(seconds=10)
        code, _, _ = self.run_once()
        self.assertEqual(code, EXIT_OK)

    def test_duplicate_counts_as_sent(self):
        self.server.responses = [(200, {"duplicate": True, "accepted": 0, "rejected": 0}, {})]
        code, _, runner = self.run_once()
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(runner.sent.duplicates, 1)
        self.assertEqual(self.offsets()["access.log"], os.path.getsize(self.log))

    def test_413_halves_the_batch(self):
        self.server.responses = [(413, {"code": "payload_too_large", "max": 1}, {})]
        code, err, _ = self.run_once()
        self.assertEqual(code, EXIT_OK, err)
        ids = [p["headers"]["X-Mavirank-Batch-Id"] for p in self.server.posts]
        full, first, second = ids[0], ids[1], ids[2]
        a, b = full.rsplit(":", 1)[1].split("-")
        a1, b1 = first.rsplit(":", 1)[1].split("-")
        a2, b2 = second.rsplit(":", 1)[1].split("-")
        self.assertEqual((a1, b1, b2), (a, a2, b))
        self.assertEqual(len(self.server.posts[1]["lines"]) + len(self.server.posts[2]["lines"]),
                         len(self.server.posts[0]["lines"]))

    def test_unauthorized_stops_without_progress(self):
        self.server.responses = [(401, {"code": "unauthenticated"}, {})]
        code, err, _ = self.run_once()
        self.assertEqual(code, EXIT_AUTH)
        self.assertNotIn(TOKEN, err)
        self.assertIn("mvrk_log_TESTT", err)
        self.assertEqual(self.offsets()["access.log"], 0)

    def test_disabled_source_403(self):
        self.server.responses = [(403, {"code": "log_source_disabled", "reason": "paused_by_plan"}, {})]
        code, err, _ = self.run_once()
        self.assertEqual(code, EXIT_AUTH)
        self.assertIn("paused_by_plan", err)

    def test_pacing_respects_batches_per_minute(self):
        self.server.config["limits"] = {"maxLines": 50, "maxBatchesPerMinute": 3}
        self.server.config["settings"]["errorLog"] = False
        sleeps = []
        cfg = load_config(self.conf, environ={})
        runner = Runner(cfg, out=io.StringIO(), err=io.StringIO(), now=lambda: self.clock, sleep=sleeps.append,
                        dns=DnsVerifier(lambda ip: "x", lambda h: [], budget=0))
        self.assertEqual(runner.run(), EXIT_OK)
        self.assertEqual(len(self.server.posts), 5)
        self.assertEqual(len(sleeps), 4)  # one batch per "minute" (3 - margin 2)
        self.assertTrue(all(0 < s <= 60 for s in sleeps))

    def test_batch_limit_from_config(self):
        self.server.config["limits"] = {"maxLines": 50}
        self.server.config["settings"]["errorLog"] = False
        self.run_once()
        self.assertGreater(len(self.server.posts), 3)
        ranges = [p["headers"]["X-Mavirank-Batch-Id"].rsplit(":", 1)[1].split("-") for p in self.server.posts]
        for (s1, e1), (s2, _e2) in zip(ranges, ranges[1:]):
            self.assertEqual(e1, s2)  # contiguous byte ranges
        self.assertTrue(all(len(p["lines"]) <= 50 for p in self.server.posts))

    def test_dry_run_sends_and_writes_nothing(self):
        out = io.StringIO()
        cfg = load_config(self.conf, environ={})
        code = Runner(cfg, dry_run=True, out=out, err=io.StringIO(), now=lambda: NOW,
                      dns=DnsVerifier(lambda ip: "x", lambda h: [], budget=0)).run()
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.server.posts, [])
        self.assertFalse(os.path.exists(self.state))
        self.assertIn("DRY RUN", out.getvalue())

    def test_lock_prevents_parallel_runs(self):
        from mavirank_collector.state import RunLock
        os.makedirs(self.state)
        lock = RunLock(self.state)
        self.assertTrue(lock.acquire())
        try:
            code, err, _ = self.run_once()
            self.assertEqual(code, EXIT_OK)
            self.assertIn("another run", err)
            self.assertEqual(self.server.posts, [])
        finally:
            lock.release()


class CheckCommandTest(StubCase):
    """Reuses the stub; only the check command is exercised."""

    def test_check_passes_and_hides_token(self):
        from mavirank_collector.cli import cmd_check
        os.chmod(self.conf, 0o600)
        out = io.StringIO()
        code = cmd_check(self.conf, out)
        text = out.getvalue()
        self.assertEqual(code, EXIT_OK, text)
        self.assertIn("token accepted", text)
        self.assertIn("clock difference", text)
        self.assertNotIn(TOKEN, text)

    def test_check_fails_on_wrong_token(self):
        from mavirank_collector.cli import cmd_check
        with open(self.conf, encoding="utf-8") as fh:
            text = fh.read().replace(TOKEN, "mvrk_log_" + "W" * 43)
        with open(self.conf, "w", encoding="utf-8") as fh:
            fh.write(text)
        out = io.StringIO()
        self.assertNotEqual(cmd_check(self.conf, out), EXIT_OK)
        self.assertIn("rejected the token", out.getvalue())

    def test_run_stops_when_config_is_unauthorized(self):
        with open(self.conf, encoding="utf-8") as fh:
            text = fh.read().replace(TOKEN, "mvrk_log_" + "W" * 43)
        with open(self.conf, "w", encoding="utf-8") as fh:
            fh.write(text)
        code, err, _ = self.run_once()
        self.assertEqual(code, EXIT_AUTH)
        self.assertEqual(self.server.posts, [])


class ConfigTest(unittest.TestCase):
    def write(self, text):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_http_requires_flag_and_token_from_env(self):
        from mavirank_collector.config import ConfigError
        path = self.write("[mavirank]\ningest_url = http://x/api/v1/ingest\n[logs]\naccess_log = /x\n")
        with self.assertRaises(ConfigError):
            load_config(path, environ={"MAVIRANK_COLLECTOR_TOKEN": TOKEN})
        path = self.write("[mavirank]\ningest_url = https://x/api/v1/ingest\n[logs]\naccess_log = /x\n")
        cfg = load_config(path, environ={"MAVIRANK_COLLECTOR_TOKEN": TOKEN})
        self.assertEqual(cfg.token, TOKEN)
        self.assertEqual(cfg.api_base, "https://x/api/v1")
        with self.assertRaises(ConfigError) as ctx:
            load_config(path, environ={"MAVIRANK_COLLECTOR_TOKEN": "mvrk_log_short"})
        self.assertNotIn("mvrk_log_short", str(ctx.exception).replace("mvrk_log_short…", ""))

    def test_api_base_variants(self):
        from mavirank_collector.config import api_base
        for url in ("https://a.example/api/v1/ingest", "https://a.example/api/v1/ingest/", "https://a.example/api/v1/ingest/logs",
                    "https://a.example/api/v1", "https://a.example"):
            self.assertEqual(api_base(url), "https://a.example/api/v1")

    def test_invalid_values(self):
        from mavirank_collector.config import ConfigError
        for body in ("[logs]\naccess_log = /x\nformat = json\n", "[logs]\naccess_log = /x\nserver = iis\n", "[logs]\n",
                     "[logs]\naccess_log = /x\ndomain = bad_host!\n", "[logs]\naccess_log = /x\ntimezone = Mars/Base\n"):
            with self.subTest(body=body), self.assertRaises(ConfigError):
                load_config(self.write(body), environ={}, require_remote=False)


if __name__ == "__main__":
    unittest.main()
