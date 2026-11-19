import os
import unittest

from helpers import fixture
from mavirank_collector.bots import KINDS, VARIANTS, classify
from mavirank_collector.privacy import parse_ip
from mavirank_collector.verify import (
    DnsVerifier, GooglebotVerifier, GoogleRanges, fetch_google_ranges, load_ranges, parse_google_ranges,
)

GB_SMART = ("Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.6723.116 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
GB_DESK = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


class ClassifyTest(unittest.TestCase):
    def test_googlebot_variants(self):
        self.assertEqual(classify(GB_SMART)[:3], ("Googlebot", "search", "Smartphone"))
        self.assertEqual(classify(GB_DESK)[:3], ("Googlebot", "search", "Desktop"))
        self.assertEqual(classify("Googlebot-Image/1.0")[:3], ("Googlebot", "search", "Image"))
        self.assertEqual(classify("Googlebot-Video/1.0")[2], "Video")
        self.assertEqual(classify("Googlebot-News")[2], "News")
        self.assertTrue(classify(GB_DESK).google)

    def test_kinds(self):
        cases = {
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)": ("Bingbot", "search"),
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)": ("GPTBot", "ai"),
            "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)": ("ClaudeBot", "ai"),
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)": ("AhrefsBot", "seo"),
            "facebookexternalhit/1.1": ("Facebook", "social"),
            "Mozilla/5.0 (compatible; idealo-bot)": ("idealo", "shopping"),
            "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)": ("UptimeRobot", "monitor"),
            "curl/8.5.0": ("curl", "script"),
            "python-requests/2.32.3": ("Python", "script"),
            "SomeNewCrawler/1.0": ("Other bots", "other"),
            "Mozilla/5.0 (compatible; AdsBot-Google-Mobile; +http://www.google.com/mobile/adsbot.html)": ("AdsBot-Google", "search"),
        }
        for ua, expected in cases.items():
            with self.subTest(ua=ua):
                m = classify(ua)
                self.assertIsNotNone(m)
                self.assertEqual((m.name, m.kind), expected)
                self.assertIn(m.kind, KINDS)
                self.assertIsNone(m.variant)

    def test_humans(self):
        self.assertIsNone(classify("Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"))
        self.assertIsNone(classify("-"))
        self.assertIsNone(classify(""))

    def test_names_fit_contract(self):
        import re
        from mavirank_collector.bots import RULES
        for rule in RULES:
            self.assertRegex(rule.name, r"^[A-Za-z0-9 ._()/-]{1,60}$")
            self.assertIn(rule.kind, KINDS)
        self.assertEqual(set(VARIANTS), {"Smartphone", "Desktop", "Image", "Video", "News"})
        self.assertTrue(re)


class FakeDns:
    def __init__(self, ptr=None, forward=None, fail=None):
        self.ptr = ptr or {}
        self.fwd = forward or {}
        self.calls = 0

    def reverse(self, ip):
        self.calls += 1
        import socket
        if ip not in self.ptr:
            raise socket.herror(1, "not found")
        return self.ptr[ip]

    def forward(self, host):
        return self.fwd.get(host, [])


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.ranges = GoogleRanges.from_path(fixture("google-ranges"))

    def test_fixture_ranges(self):
        self.assertTrue(self.ranges.contains(parse_ip("66.249.64.10")))
        self.assertTrue(self.ranges.contains(parse_ip("66.249.65.140")))
        self.assertTrue(self.ranges.contains(parse_ip("2001:4860:4801:10::1a")))
        self.assertFalse(self.ranges.contains(parse_ip("198.51.100.66")))

    def test_verifier_with_lists(self):
        v = GooglebotVerifier(self.ranges, None)
        self.assertEqual(v.verify("66.249.64.10"), "true")
        self.assertEqual(v.verify("198.51.100.66"), "false")
        self.assertIsNone(v.verify("not-an-ip.example"))

    def test_dns_fallback_without_lists(self):
        dns = FakeDns(
            ptr={"66.249.66.1": "crawl-66-249-66-1.googlebot.com.", "198.51.100.66": "fake.googlebot.com.evil.example",
                 "192.0.2.5": "crawl-1.googlebot.com"},
            forward={"crawl-66-249-66-1.googlebot.com": ["66.249.66.1"], "crawl-1.googlebot.com": ["192.0.2.99"]},
        )
        v = GooglebotVerifier(None, DnsVerifier(dns.reverse, dns.forward, timeout=1))
        self.assertEqual(v.verify("66.249.66.1"), "true")
        self.assertEqual(v.verify("198.51.100.66"), "false")  # wrong domain
        self.assertEqual(v.verify("192.0.2.5"), "false")  # forward does not confirm
        self.assertEqual(v.verify("192.0.2.6"), "false")  # no PTR

    def test_dns_budget_and_timeout(self):
        import time

        def slow(ip):
            time.sleep(0.5)
            return "x.googlebot.com"

        dns = DnsVerifier(slow, lambda h: [], timeout=0.05, budget=1)
        v = GooglebotVerifier(None, dns)
        self.assertIsNone(v.verify("192.0.2.1"))  # timeout = unchecked
        self.assertIsNone(v.verify("192.0.2.2"))  # budget used up
        self.assertEqual(dns.lookups, 1)

    def test_lists_decide_alone(self):
        # S6-08: a Google Cloud VM with a confirmed *.bc.googleusercontent.com name and a faked user agent.
        lookups = []
        dns = FakeDns(ptr={"198.51.100.66": "66.100.51.198.bc.googleusercontent.com."},
                      forward={"66.100.51.198.bc.googleusercontent.com": ["198.51.100.66"]})

        def reverse(ip):
            lookups.append(ip)
            return dns.reverse(ip)

        v = GooglebotVerifier(self.ranges, DnsVerifier(reverse, dns.forward, timeout=1))
        self.assertEqual(v.verify("198.51.100.66"), "false")
        self.assertEqual(v.verify("66.249.64.10"), "true")
        self.assertEqual(lookups, [], "no DNS lookup while the lists are loaded")

    def test_dns_fallback_rejects_cloud_vms(self):
        dns = FakeDns(
            ptr={"198.51.100.66": "66.100.51.198.bc.googleusercontent.com.", "192.0.2.7": "x.gae.googleusercontent.com"},
            forward={"66.100.51.198.bc.googleusercontent.com": ["198.51.100.66"], "x.gae.googleusercontent.com": ["192.0.2.7"]},
        )
        v = GooglebotVerifier(None, DnsVerifier(dns.reverse, dns.forward, timeout=1))
        self.assertEqual(v.verify("198.51.100.66"), "false")
        self.assertEqual(v.verify("192.0.2.7"), "true")

    def test_dns_budget_with_lists_means_false(self):
        dns = DnsVerifier(lambda ip: "x.example", lambda h: [], budget=0)
        self.assertEqual(GooglebotVerifier(self.ranges, dns).verify("198.51.100.66"), "false")

    def test_load_ranges_cache_and_fallback(self):
        import json
        import tempfile

        with open(os.path.join(fixture("google-ranges"), "common-crawlers.json"), encoding="utf-8") as fh:
            payload = json.load(fh)
        calls = []

        def ok(url):
            calls.append(url)
            return payload

        def broken(url):
            raise OSError("offline")

        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(load_ranges(tmp, None, broken, True, now=1000.0))
            r = load_ranges(tmp, None, ok, True, now=1000.0)
            self.assertEqual(len(calls), 5)
            self.assertTrue(r.contains(parse_ip("66.249.64.10")))
            load_ranges(tmp, None, ok, True, now=2000.0)  # fresh cache, no download
            self.assertEqual(len(calls), 5)
            stale = load_ranges(tmp, None, broken, True, now=1000.0 + 90000)  # stale, download fails
            self.assertIsNotNone(stale)
            self.assertEqual(stale.source, "cache")

    def test_partial_download_is_rejected(self):
        def half(url):
            if url.endswith("special-crawlers.json"):
                raise OSError("boom")
            return {"prefixes": [{"ipv4Prefix": "66.249.64.0/27"}]}

        with self.assertRaises(OSError):
            fetch_google_ranges(half, 0)
        with self.assertRaises(ValueError):
            parse_google_ranges({"prefixes": []})


if __name__ == "__main__":
    unittest.main()
