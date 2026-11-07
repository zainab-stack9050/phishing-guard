"""Feature extraction: turns (url, html) into one flat dict of numbers.

    from features import extract
    row = extract("https://example.com/login", html_text)

Rules for this file:
  * Only use what a browser extension can see on the page (the URL and the DOM).
    No WHOIS, no extra network requests.
  * Always return the same keys, so every page becomes a row with the same columns.
  * Never crash on bad HTML or a strange URL; fall back to zeros.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urljoin, urlparse

import tldextract
from bs4 import BeautifulSoup

# Offline copy of the public-suffix list: no network, same result every time.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

KEYWORDS = ("login", "signin", "secure", "verify", "account",
            "update", "bank", "confirm", "password", "wallet")

_NO_LINK_PREFIXES = ("#", "javascript:", "mailto:", "tel:", "data:")
_RIGHT_CLICK_RE = re.compile(
    r"oncontextmenu\s*=\s*[\"']?\s*(?:return\s+false|event\.preventDefault)"
    r"|addEventListener\(\s*[\"']contextmenu", re.I)


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


# ---------------------------------------------------------------- URL features
def url_features(url: str) -> dict:
    try:
        p = urlparse(url)
        port = p.port
    except ValueError:
        p, port = urlparse(""), None
    host = (p.hostname or "").lower()
    sub = _EXTRACT(host).subdomain if host and not _is_ip(host) else ""
    digits = sum(ch.isdigit() for ch in url)
    path_query = (p.path + "?" + p.query).lower()
    return {
        "url_len": len(url),
        "host_len": len(host),
        "path_len": len(p.path),
        "n_dots_host": host.count("."),
        "n_hyphens_host": host.count("-"),
        "n_digits": digits,
        "digit_ratio": digits / max(len(url), 1),
        "n_at": url.count("@"),
        "n_qmark": url.count("?"),
        "n_eq": url.count("="),
        "n_amp": url.count("&"),
        "n_slash": url.count("/"),
        "subdomain_depth": len([s for s in sub.split(".") if s]),
        "host_entropy": entropy(host),
        "is_ip_host": int(_is_ip(host)),
        "has_punycode": int("xn--" in host),
        "is_https": int(p.scheme == "https"),
        "has_odd_port": int(port not in (None, 80, 443)),
        "kw_in_host": sum(k in host for k in KEYWORDS),
        "kw_in_path": sum(k in path_query for k in KEYWORDS),
    }


# --------------------------------------------------------------- page features
def _empty_page_features() -> dict:
    return {
        "has_password": 0, "n_forms": 0, "n_inputs": 0, "n_hidden_inputs": 0,
        "form_action_external": 0, "form_action_empty": 0,
        "n_scripts": 0, "n_iframes": 0, "n_hidden_iframes": 0,
        "n_resources": 0, "ext_resource_ratio": 0.0,
        "n_links": 0, "ext_link_ratio": 0.0, "null_link_ratio": 0.0,
        "favicon_external": 0, "rightclick_blocked": 0, "has_meta_refresh": 0,
        "title_len": 0, "text_len": 0,
    }


def page_features(url: str, html: str) -> dict:
    feats = _empty_page_features()
    if not html:
        return feats
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return feats

    page_domain = registered_domain(_host(url))

    def is_external(link) -> bool:
        link = (link or "").strip()
        if not link or link.lower().startswith(_NO_LINK_PREFIXES):
            return False
        try:
            h = urlparse(urljoin(url, link)).hostname
        except ValueError:
            return False
        return bool(h) and registered_domain(h) != page_domain

    # inputs and forms
    inputs = soup.find_all("input")
    feats["n_inputs"] = len(inputs)
    feats["n_hidden_inputs"] = sum((i.get("type") or "").lower() == "hidden" for i in inputs)
    feats["has_password"] = int(any((i.get("type") or "").lower() == "password" for i in inputs))
    forms = soup.find_all("form")
    feats["n_forms"] = len(forms)
    ext_actions = empty_actions = 0
    for form in forms:
        action = (form.get("action") or "").strip().lower()
        if action in ("", "#") or action.startswith("javascript:"):
            empty_actions += 1
        elif is_external(action):
            ext_actions += 1
    feats["form_action_external"] = int(ext_actions > 0)
    feats["form_action_empty"] = int(empty_actions > 0)

    # scripts, iframes, resources
    feats["n_scripts"] = len(soup.find_all("script"))
    iframes = soup.find_all("iframe")
    feats["n_iframes"] = len(iframes)
    hidden = 0
    for fr in iframes:
        style = (fr.get("style") or "").lower().replace(" ", "")
        zero = lambda v: (v or "").strip().lower() in ("0", "0px")
        if (fr.has_attr("hidden") or "display:none" in style
                or "visibility:hidden" in style or zero(fr.get("width")) or zero(fr.get("height"))):
            hidden += 1
    feats["n_hidden_iframes"] = hidden

    resources = ([t.get("src") for t in soup.find_all(["script", "img", "iframe"]) if t.get("src")]
                 + [t.get("href") for t in soup.find_all("link") if t.get("href")])
    feats["n_resources"] = len(resources)
    if resources:
        feats["ext_resource_ratio"] = sum(is_external(r) for r in resources) / len(resources)

    # links
    hrefs = [a.get("href") for a in soup.find_all("a") if a.has_attr("href")]
    feats["n_links"] = len(hrefs)
    if hrefs:
        feats["ext_link_ratio"] = sum(is_external(h) for h in hrefs) / len(hrefs)
        feats["null_link_ratio"] = sum(
            (h or "").strip().lower() in ("", "#") or (h or "").strip().lower().startswith("javascript:")
            for h in hrefs) / len(hrefs)

    # misc
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel and is_external(link.get("href")):
            feats["favicon_external"] = 1
            break
    feats["rightclick_blocked"] = int(bool(_RIGHT_CLICK_RE.search(html)))
    feats["has_meta_refresh"] = int(soup.find(
        "meta", attrs={"http-equiv": re.compile("refresh", re.I)}) is not None)
    title = soup.title.get_text(strip=True) if soup.title else ""
    feats["title_len"] = len(title)
    feats["text_len"] = len(soup.get_text(" ", strip=True))
    return feats


def extract(url: str, html: str) -> dict:
    feats = url_features(url)
    feats.update(page_features(url, html))
    return feats
