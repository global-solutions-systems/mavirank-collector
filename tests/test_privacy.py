import datetime as dt
import os
import stat
import tempfile
import unittest

from helpers import NOW
from mavirank_collector.privacy import (
    PSEUDONYM_RE, DayKeys, Pseudonymizer, clean_referer, contains_raw_ip, mask_query, mask_query_in_text, network_of,
    parse_ip,
)

DAY = NOW.date()


class PseudonymTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = DayKeys(self.tmp.name, DAY)
        self.p = Pseudonymizer(self.keys)

    def tearDown(self):
        self.tmp.cleanup()

    def test_format_and_stability(self):
        a = self.p.pseudonym("192.0.2.10", DAY)
        self.assertRegex(a, PSEUDONYM_RE)
        self.assertEqual(a, self.p.pseudonym("192.0.2.10", DAY))
        self.assertNotEqual(a, self.p.pseudonym("192.0.2.11", DAY))
        self.assertRegex(self.p.pseudonym("2001:db8::1", DAY), PSEUDONYM_RE)

    def test_ipv4_mapped_equals_ipv4(self):
        self.assertEqual(self.p.pseudonym("::ffff:192.0.2.10", DAY), self.p.pseudonym("192.0.2.10", DAY))

    def test_different_day_different_pseudonym(self):
        yesterday = DAY - dt.timedelta(days=1)
        self.assertNotEqual(self.p.pseudonym("192.0.2.10", DAY), self.p.pseudonym("192.0.2.10", yesterday))

    def test_key_files_are_private_and_persist(self):
        self.p.pseudonym("192.0.2.10", DAY)
        path = os.path.join(self.tmp.name, "keys", DAY.isoformat() + ".key")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(os.path.getsize(path), 32)
        again = Pseudonymizer(DayKeys(self.tmp.name, DAY))
        self.assertEqual(again.pseudonym("192.0.2.10", DAY), self.p.pseudonym("192.0.2.10", DAY))

    def test_old_days_never_persisted_and_keys_deleted_after_two_days(self):
        old = DAY - dt.timedelta(days=5)
        self.p.pseudonym("192.0.2.10", old)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "keys", old.isoformat() + ".key")))
        self.p.pseudonym("192.0.2.10", DAY - dt.timedelta(days=1))
        self.p.pseudonym("192.0.2.10", DAY)
        self.assertEqual(DayKeys(self.tmp.name, DAY + dt.timedelta(days=1)).cleanup(), 1)  # D-1 is two days old
        self.assertEqual(DayKeys(self.tmp.name, DAY + dt.timedelta(days=2)).cleanup(), 1)  # now D
        self.assertEqual(os.listdir(os.path.join(self.tmp.name, "keys")), [])

    def test_key_of_yesterday_survives_one_day(self):
        self.p.pseudonym("192.0.2.10", DAY - dt.timedelta(days=1))
        DayKeys(self.tmp.name, DAY).cleanup()
        self.assertEqual(len(os.listdir(os.path.join(self.tmp.name, "keys"))), 1)

    def test_ephemeral_keys_write_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            Pseudonymizer(DayKeys(tmp, DAY, ephemeral=True)).pseudonym("192.0.2.1", DAY)
            self.assertEqual(os.listdir(tmp), [])

    def test_scrub_free_text(self):
        text = ('client 192.0.2.10:5555 via [2001:db8::50]:9000, upstream http://10.0.0.5:9000/x, '
                'mapped ::ffff:198.51.100.1, end 203.0.113.9.')
        out = self.p.scrub(text, DAY)
        self.assertFalse(contains_raw_ip(out), out)
        self.assertIn(self.p.pseudonym("192.0.2.10", DAY) + ":5555", out)
        self.assertTrue(out.endswith("."))

    def test_scrub_keeps_versions_and_times(self):
        text = "time 10:00:00 version 1.2.3.4.5 Class::method"
        self.assertEqual(self.p.scrub(text, DAY), text)
        ua = "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36 from 192.0.2.1"
        out = self.p.scrub(ua, DAY, user_agent=True)
        self.assertIn("Chrome/130.0.0.0", out)
        self.assertNotIn("192.0.2.1", out)

    def test_scrub_ipv6_after_word_and_colon(self):
        # S6-01: the former lookbehind missed addresses right after "client:".
        text = "refused, client:2001:db8::1 upstream 10.0.0.5, client: ::ffff:198.51.100.3, host:::1"
        out = self.p.scrub(text, DAY)
        self.assertFalse(contains_raw_ip(out), out)
        self.assertIn("client:" + self.p.pseudonym("2001:db8::1", DAY) + " upstream", out)
        self.assertIn("host:" + self.p.pseudonym("::1", DAY), out)
        self.assertTrue(contains_raw_ip("client:2001:db8::1"))

    def test_scrub_percent_encoded(self):
        for text in ("/track?client=203%2E0%2E113%2E7&v=1", "/t?c=2001%3Adb8%3A%3A1", "/t?c=203%252E0%252E113%252E7"):
            self.assertTrue(contains_raw_ip(text), text)
            out = self.p.scrub(text, DAY)
            self.assertFalse(contains_raw_ip(out), out)
        self.assertEqual(self.p.scrub("/track?client=203%2E0%2E113%2E7&v=1", DAY),
                         "/track?client=" + self.p.pseudonym("203.0.113.7", DAY) + "&v=1")
        plain = "/search?q=hello%20world&x=%2Fpath"
        self.assertEqual(self.p.scrub(plain, DAY), plain)
        self.assertFalse(contains_raw_ip(plain))

    def test_scrub_keeps_words_with_colons(self):
        text = "App\\Foo::bar() std::vector aa:bb:cc:dd:ee:ff 2026-11-12T10:33:00Z"
        self.assertEqual(self.p.scrub(text, DAY), text)

    def test_network(self):
        self.assertEqual(network_of(parse_ip("203.0.113.77")), "203.0.113.0/24")
        self.assertEqual(network_of(parse_ip("2001:db8:dead:beef::1")), "2001:db8:dead::/48")


class QueryTest(unittest.TestCase):
    def test_mask_values(self):
        self.assertEqual(mask_query("/p?color=red&utm_source=news&flag&empty=", "mask_values"),
                         "/p?color=x&utm_source=x&flag&empty=")
        self.assertEqual(mask_query("/p", "mask_values"), "/p")
        self.assertEqual(mask_query("/p?", "mask_values"), "/p")

    def test_keep_and_strip(self):
        self.assertEqual(mask_query("/p?a=1", "keep"), "/p?a=1")
        self.assertEqual(mask_query("/p?a=1", "strip"), "/p")

    def test_referer(self):
        self.assertEqual(clean_referer("https://e.com/b/?email=j%40e.org#top"), "https://e.com/b/")
        self.assertEqual(clean_referer("https://e.com/#frag"), "https://e.com/")
        self.assertIsNone(clean_referer("-"))
        self.assertIsNone(clean_referer(""))

    def test_text(self):
        msg = 'request: "GET /a?id=7&t=abc HTTP/1.1", referrer: "https://e.com/?utm=1"'
        self.assertEqual(mask_query_in_text(msg, "mask_values"),
                         'request: "GET /a?id=x&t=x HTTP/1.1", referrer: "https://e.com/"')
        self.assertEqual(mask_query_in_text(msg, "strip"), 'request: "GET /a HTTP/1.1", referrer: "https://e.com/"')
        self.assertEqual(mask_query_in_text(msg, "keep"), 'request: "GET /a?id=7&t=abc HTTP/1.1", referrer: "https://e.com/"')


if __name__ == "__main__":
    unittest.main()
