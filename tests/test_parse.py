import datetime as dt
import unittest

from helpers import fixture_lines  # noqa: F401  (sets sys.path)
from mavirank_collector.parse import normalize_level, parse_access, parse_error

UTC = dt.timezone.utc


class AccessParserTest(unittest.TestCase):
    def test_nginx_combined(self):
        line = ('192.0.2.10 - - [10/Nov/2026:13:55:36 +0100] "GET /blog/?a=1 HTTP/1.1" 200 5120 '
                '"https://www.google.com/" "Mozilla/5.0 (X11; Linux x86_64)"')
        p = parse_access(line)
        self.assertIsNotNone(p)
        self.assertIsNone(p.vhost)
        self.assertEqual(p.client, "192.0.2.10")
        self.assertEqual(p.time, dt.datetime(2026, 11, 10, 12, 55, 36, tzinfo=UTC))
        self.assertEqual((p.method, p.target, p.protocol), ("GET", "/blog/?a=1", "HTTP/1.1"))
        self.assertEqual((p.status, p.size), ("200", "5120"))
        self.assertEqual(p.referer, "https://www.google.com/")
        self.assertEqual(p.user_agent, "Mozilla/5.0 (X11; Linux x86_64)")

    def test_apache_combined_with_escaped_quote_and_dash_size(self):
        line = '2001:db8::5 - frank [10/Nov/2026:13:55:36 -0700] "GET /a\\"b HTTP/1.0" 304 - "-" "agent \\"x\\""'
        p = parse_access(line)
        self.assertEqual(p.client, "2001:db8::5")
        self.assertEqual(p.target, '/a"b')
        self.assertEqual(p.size, "0")
        self.assertEqual(p.user_agent, 'agent "x"')
        self.assertEqual(p.time.utcoffset(), dt.timedelta(hours=-7))

    def test_vhost_combined(self):
        line = 'www.example.com:443 192.0.2.10 - - [11/Nov/2026:09:07:00 +0100] "GET / HTTP/2.0" 200 1234 "-" "UA"'
        p = parse_access(line)
        self.assertEqual(p.vhost, "www.example.com:443")
        self.assertEqual(p.client, "192.0.2.10")

    def test_common_log_format_without_referer_and_agent(self):
        p = parse_access('192.0.2.1 - - [11/Nov/2026:09:07:00 +0000] "GET / HTTP/1.1" 200 12')
        self.assertEqual((p.referer, p.user_agent), ("", ""))

    def test_unsplittable_request_kept_as_request(self):
        p = parse_access('203.0.113.9 - - [11/Nov/2026:07:09:21 +0100] "\\x16\\x03\\x01" 400 157 "-" "-"')
        self.assertIsNone(p.method)
        self.assertEqual(p.request, "\\x16\\x03\\x01")

    def test_garbage(self):
        self.assertIsNone(parse_access("this is not a log line"))
        self.assertIsNone(parse_access('192.0.2.1 - - [99/Foo/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1'))

    def test_all_fixture_lines_but_one_parse(self):
        lines = fixture_lines("access.log")
        parsed = [parse_access(line) for line in lines]
        self.assertGreaterEqual(len(lines), 200)
        self.assertEqual(sum(1 for p in parsed if p is None), 1)
        self.assertTrue(all(parse_access(line) for line in fixture_lines("vhost_access.log")))


class ErrorParserTest(unittest.TestCase):
    def test_nginx(self):
        line = ('2026/11/11 08:12:03 [error] 1234#1234: *881 open() "/x" failed (2: No such file or directory), '
                'client: 192.0.2.23, server: example.com, request: "GET /x HTTP/1.1", host: "www.example.com:443"')
        p = parse_error(line, UTC)
        self.assertEqual(p.server, "nginx")
        self.assertEqual(p.level, "error")
        self.assertEqual(p.client, "192.0.2.23")
        self.assertEqual(p.host, "www.example.com:443")
        self.assertEqual(p.time, dt.datetime(2026, 11, 11, 8, 12, 3, tzinfo=UTC))
        self.assertTrue(p.message.startswith("open()"))

    def test_nginx_without_client(self):
        p = parse_error("2026/11/11 10:00:00 [notice] 1#1: signal process started", UTC)
        self.assertEqual((p.level, p.client, p.host), ("notice", None, None))

    def test_apache(self):
        line = ("[Wed Nov 11 08:00:01.123456 2026] [core:error] [pid 2345:tid 140000] [client 192.0.2.37:51234] "
                "AH00126: Invalid URI in request GET /../../etc/passwd HTTP/1.1")
        p = parse_error(line, dt.timezone(dt.timedelta(hours=1)))
        self.assertEqual((p.server, p.module, p.level, p.client), ("apache", "core", "error", "192.0.2.37"))
        self.assertEqual(p.time.astimezone(UTC).hour, 7)
        self.assertTrue(p.message.startswith("AH00126"))

    def test_apache_ipv6_client_and_trace_level(self):
        p = parse_error("[Wed Nov 11 09:00:00.1 2026] [core:trace3] [pid 1:tid 2] [client [2001:db8::1]:5555] x", UTC)
        self.assertEqual(p.client, "2001:db8::1")
        self.assertEqual(p.level, "debug")

    def test_fixture_files(self):
        nginx = [parse_error(line, UTC) for line in fixture_lines("error.log")]
        apache = [parse_error(line, UTC) for line in fixture_lines("apache_error.log")]
        self.assertEqual(sum(1 for p in nginx if p is None), 1)  # the garbage line
        self.assertTrue(all(apache))

    def test_levels(self):
        self.assertEqual(normalize_level("warning"), "warn")
        self.assertEqual(normalize_level("emerg"), "emerg")
        self.assertEqual(normalize_level("whatever"), "notice")


if __name__ == "__main__":
    unittest.main()
