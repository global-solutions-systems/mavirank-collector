import datetime as dt
import json
import re
import tempfile
import unittest

from helpers import NOW, fixture, fixture_lines
from mavirank_collector.privacy import PSEUDONYM_RE, DayKeys, Pseudonymizer, contains_raw_ip
from mavirank_collector.records import MAX_LINE_BYTES, RecordBuilder, Settings
from mavirank_collector.rules import ScanRules
from mavirank_collector.verify import GooglebotVerifier, GoogleRanges

ALLOWED = {"_time", "log", "domain", "status", "method", "path", "protocol", "request", "size", "ip", "net", "referer",
           "user_agent", "bot", "bot_kind", "bot_variant", "bot_verified", "level", "module", "server", "_msg"}
TZ = dt.timezone(dt.timedelta(hours=1))


def builder(mode="mask_values", scan_net=True, hostnames=("example.com", "www.example.com"), domain="example.com",
            ranges=True, now=NOW):
    keys = DayKeys(None, now.date(), ephemeral=True)
    verifier = GooglebotVerifier(GoogleRanges.from_path(fixture("google-ranges")) if ranges else None, None)
    return RecordBuilder(Settings(True, mode, scan_net), list(hostnames) if hostnames is not None else None, domain,
                         ScanRules.builtin(), Pseudonymizer(keys), verifier, now, TZ)


def build_all(b):
    out = []
    for line in fixture_lines("access.log") + fixture_lines("vhost_access.log"):
        data, _ = b.access(line)
        if data:
            out.append(json.loads(data))
    for line in fixture_lines("error.log") + fixture_lines("apache_error.log"):
        data, _ = b.error(line)
        if data:
            out.append(json.loads(data))
    return out


class NoRawIpTest(unittest.TestCase):
    def test_no_raw_ip_in_any_field_in_any_mode(self):
        for mode in ("mask_values", "keep", "strip"):
            with self.subTest(mode=mode):
                records = build_all(builder(mode))
                self.assertGreater(len(records), 200)
                for rec in records:
                    for key, value in rec.items():
                        self.assertIsInstance(value, str)
                        if key in ("net", "_time"):
                            continue
                        self.assertFalse(contains_raw_ip(value, user_agent=key == "user_agent"), f"{key}={value!r}")
                    if "ip" in rec:
                        self.assertRegex(rec["ip"], PSEUDONYM_RE)

    def test_known_addresses_absent_from_serialised_output(self):
        blob = "\n".join(json.dumps(r) for r in build_all(builder("keep")))
        for ip in ("192.0.2.10", "192.0.2.44", "198.51.100.7", "66.249.64.10", "2001:db8:1234::5", "10.0.0.5",
                   "2001:db8::50", "203.0.113.9", "192.0.2.58"):
            self.assertNotIn(ip, blob)

    def test_unsplittable_request_is_scrubbed(self):
        b = builder("keep")
        data, _ = b.access('203.0.113.9 - - [11/Nov/2026:07:09:21 +0100] "CONNECT 192.0.2.1:443" 400 157 "-" "-"')
        rec = json.loads(data)
        self.assertNotIn("192.0.2.1", rec["request"])
        self.assertNotIn("192.0.2.1", rec["_msg"])
        self.assertNotIn("method", rec)


class AccessRecordTest(unittest.TestCase):
    def line(self, **kw):
        base = {"client": "192.0.2.10", "time": "11/Nov/2026:10:00:00 +0100", "req": "GET /p?a=1&b=2 HTTP/1.1",
                "status": "200", "ref": "https://ref.example/x?y=1", "ua": "Mozilla/5.0 Firefox/132.0"}
        base.update(kw)
        return f'{base["client"]} - - [{base["time"]}] "{base["req"]}" {base["status"]} 512 "{base["ref"]}" "{base["ua"]}"'

    def test_fields(self):
        data, reason = builder().access(self.line())
        self.assertIsNone(reason)
        rec = json.loads(data)
        self.assertEqual(rec["_time"], "2026-11-11T09:00:00+00:00")
        self.assertEqual((rec["log"], rec["domain"], rec["status"], rec["method"]), ("access", "example.com", "200", "GET"))
        self.assertEqual(rec["path"], "/p?a=x&b=x")
        self.assertEqual(rec["referer"], "https://ref.example/x")
        self.assertEqual(rec["_msg"], "200 GET /p?a=x&b=x")
        self.assertNotIn("bot", rec)
        self.assertNotIn("net", rec)
        self.assertTrue(set(rec) <= ALLOWED)
        self.assertLessEqual(len(data), MAX_LINE_BYTES)

    def test_query_modes(self):
        self.assertEqual(json.loads(builder("strip").access(self.line())[0])["path"], "/p")
        self.assertEqual(json.loads(builder("keep").access(self.line())[0])["path"], "/p?a=1&b=2")

    def test_scan_net_only_for_4xx_scan_and_setting(self):
        scan = self.line(req="GET /.env HTTP/1.1", status="404", client="203.0.113.77")
        self.assertEqual(json.loads(builder().access(scan)[0])["net"], "203.0.113.0/24")
        self.assertNotIn("net", json.loads(builder(scan_net=False).access(scan)[0]))
        ok = self.line(req="GET /wp-login.php HTTP/1.1", status="200")
        self.assertNotIn("net", json.loads(builder().access(ok)[0]))
        v6 = self.line(req="GET /.git/config HTTP/1.1", status="403", client="2001:db8:dead:1::1")
        self.assertEqual(json.loads(builder().access(v6)[0])["net"], "2001:db8:dead::/48")

    def test_config_scan_rules(self):
        rules = ScanRules.from_config({"version": "7", "rules": [{"pattern": "#^/secret#i"}, "\\.env$"]})
        self.assertEqual(rules.version, "7")
        self.assertTrue(rules.matches("404", "/SECRET/x"))
        self.assertTrue(rules.matches("403", "/.env?x=1"))
        self.assertFalse(rules.matches("200", "/.env"))
        self.assertFalse(rules.matches("404", "/public"))

    def test_googlebot_verified_and_fake(self):
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        real = json.loads(builder().access(self.line(client="66.249.64.10", ua=ua))[0])
        fake = json.loads(builder().access(self.line(client="198.51.100.66", ua=ua))[0])
        self.assertEqual((real["bot"], real["bot_variant"], real["bot_verified"]), ("Googlebot", "Desktop", "true"))
        self.assertEqual(fake["bot_verified"], "false")
        unchecked = json.loads(builder(ranges=False).access(self.line(client="66.249.64.10", ua=ua))[0])
        self.assertNotIn("bot_verified", unchecked)
        bing = json.loads(builder().access(self.line(ua="Mozilla/5.0 (compatible; bingbot/2.0)"))[0])
        self.assertNotIn("bot_verified", bing)

    def test_domain_rules(self):
        b = builder(domain=None)
        self.assertEqual(b.access(self.line())[1], "no_domain")
        vh = 'shop.example.net:443 ' + self.line()
        self.assertEqual(builder().access(vh)[1], "domain_not_allowed")
        ip_vhost = '198.51.100.1:443 ' + self.line()
        self.assertEqual(builder().access(ip_vhost)[1], "no_domain")
        www = json.loads(builder(domain=None).access("WWW.Example.com:443 " + self.line())[0])
        self.assertEqual(www["domain"], "www.example.com")
        single = builder(domain=None, hostnames=["example.com"])
        self.assertEqual(json.loads(single.access(self.line())[0])["domain"], "example.com")

    def test_control_characters_are_replaced(self):
        rec = json.loads(builder().access(self.line(ua="Agent\twith\x01ctl"))[0])
        self.assertEqual(rec["user_agent"], "Agent with ctl")
        for value in rec.values():
            self.assertIsNone(re.search(r"[\x00-\x1f\x7f]", value))

    def test_too_old_lines_are_skipped(self):
        old = self.line(time="10/Oct/2026:10:00:00 +0000")
        self.assertEqual(builder().access(old)[1], "too_old")

    def test_long_fields_are_cut(self):
        long_path = "/" + "a" * 5000
        rec = json.loads(builder().access(self.line(req=f"GET {long_path} HTTP/1.1", ua="U" * 900, ref="https://r/" + "b" * 3000))[0])
        self.assertLessEqual(len(rec["path"]), 2048)
        self.assertLessEqual(len(rec["user_agent"]), 512)
        self.assertLessEqual(len(rec["referer"]), 1024)
        self.assertLessEqual(len(rec["_msg"]), 2048)


class ErrorRecordTest(unittest.TestCase):
    def test_nginx_error_record(self):
        line = ('2026/11/11 08:12:03 [error] 1234#1234: *881 open() "/x" failed, client: 192.0.2.23, server: example.com, '
                'request: "GET /x?ref=mail HTTP/1.1", host: "www.example.com", referrer: "https://e.com/?a=1"')
        rec = json.loads(builder().error(line)[0])
        self.assertEqual((rec["log"], rec["level"], rec["server"], rec["domain"]), ("error", "error", "nginx", "www.example.com"))
        self.assertRegex(rec["ip"], PSEUDONYM_RE)
        self.assertNotIn("192.0.2.23", rec["_msg"])
        self.assertIn("/x?ref=x", rec["_msg"])
        self.assertIn('referrer: "https://e.com/"', rec["_msg"])
        self.assertEqual(rec["_time"], "2026-11-11T07:12:03+00:00")

    def test_apache_error_record_uses_default_domain_and_module(self):
        line = "[Wed Nov 11 08:00:01.1 2026] [core:error] [pid 1:tid 2] [client 192.0.2.37:51234] AH00126: " + "x" * 5000
        rec = json.loads(builder().error(line)[0])
        self.assertEqual((rec["domain"], rec["module"], rec["server"]), ("example.com", "core", "apache"))
        self.assertLessEqual(len(rec["_msg"].encode()), 2048)

    def test_error_line_without_any_domain(self):
        line = "2026/11/11 10:00:00 [notice] 1#1: signal process started"
        self.assertEqual(builder(domain=None).error(line)[1], "no_domain")


class RulesShapeTest(unittest.TestCase):
    def test_accepts_plain_list_and_rejects_garbage(self):
        self.assertEqual(len(ScanRules.from_config(["\\.env", "(", 5]).patterns), 1)
        self.assertIsNone(ScanRules.from_config("nope"))
        self.assertTrue(re.compile("x"))


if __name__ == "__main__":
    unittest.main()
