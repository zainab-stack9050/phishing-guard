"""Fetch pages from the OpenPhish community feed (label = phish).

Meant to run INSIDE the Docker container (see Dockerfile), not directly on your PC:
    docker build -t phishing-crawler ./crawler
    docker run --rm --read-only --tmpfs /tmp --cap-drop ALL \
        --security-opt no-new-privileges -v ${PWD}/data:/data \
        phishing-crawler --n 50

Output (inside the mounted data folder):
    data/feeds/openphish_<timestamp>.txt   snapshot of the feed (provenance)
    data/raw/phish/<id>.html.txt           raw HTML saved as .txt so it is never rendered
    data/labels.csv                        one row per saved page (shared with legit pages)

Safety: downloads HTML text only. No JavaScript is executed, nothing is rendered,
non-HTML responses are skipped, and every request has a timeout and a size cap.
Re-running resumes: URLs already in labels.csv are skipped.

OpenPhish community feed terms: non-commercial use only.
https://openphish.com/terms.html
"""
import argparse
import csv
import hashlib
import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

# We only download text and send no credentials, so we accept broken certificates;
# many phishing sites have them and skipping those would bias the dataset.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DATA_DIR = Path(os.environ.get("DATA_DIR",
                               Path(__file__).resolve().parent.parent / "data"))
FEED_URL = "https://openphish.com/feed.txt"
RAW_DIR = DATA_DIR / "raw" / "phish"
FEED_DIR = DATA_DIR / "feeds"
LABELS_PATH = DATA_DIR / "labels.csv"

FIELDS = ["url", "final_url", "label", "source", "fetched_at",
          "http_status", "file", "sha256", "bytes"]
MAX_BYTES = 2_000_000
TIMEOUT = (5, 10)
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_safe_target(url: str) -> bool:
    """Only http(s), and never a private/loopback/internal IP literal."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return True  # a normal hostname
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast)


def fetch_feed() -> list[str]:
    resp = requests.get(FEED_URL, timeout=60, headers=HEADERS)
    resp.raise_for_status()
    FEED_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    (FEED_DIR / f"openphish_{stamp}.txt").write_text(resp.text, encoding="utf-8")
    seen, urls = set(), []
    for line in resp.text.splitlines():
        line = line.strip()
        if line and line not in seen and is_safe_target(line):
            seen.add(line)
            urls.append(line)
    return urls


def fetch_url(url: str):
    """Return a label record for one phishing URL, or None if it can't be fetched."""
    session = requests.Session()
    session.max_redirects = 5
    try:
        with session.get(url, timeout=TIMEOUT, headers=HEADERS, stream=True,
                         allow_redirects=True, verify=False) as r:
            ctype = r.headers.get("Content-Type", "").lower()
            if r.status_code != 200 or "html" not in ctype:
                return None
            chunks, size = [], 0
            for chunk in r.iter_content(65536):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BYTES:
                    break
            body = b"".join(chunks)[:MAX_BYTES]
            final_url, status = r.url, r.status_code
    except requests.RequestException:
        return None

    if not body.strip():
        return None
    digest = hashlib.sha256(body).hexdigest()
    file_name = f"{hashlib.sha1(url.encode()).hexdigest()[:16]}.html.txt"
    (RAW_DIR / file_name).write_bytes(body)
    return {
        "url": url, "final_url": final_url, "label": "phish",
        "source": "openphish", "fetched_at": now_iso(),
        "http_status": status, "file": file_name,
        "sha256": digest, "bytes": len(body),
    }


def load_done_urls() -> set:
    if not LABELS_PATH.exists():
        return set()
    with open(LABELS_PATH, newline="", encoding="utf-8") as f:
        return {row["url"] for row in csv.DictReader(f)}


def main() -> None:
    p = argparse.ArgumentParser(description="Crawl pages from the OpenPhish feed")
    p.add_argument("--n", type=int, default=50, help="max new URLs to try this run")
    p.add_argument("--workers", type=int, default=16)
    args = p.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    done = load_done_urls()
    print("Downloading OpenPhish feed ...")
    feed = fetch_feed()
    todo = [u for u in feed if u not in done][: args.n]
    print(f"Feed has {len(feed)} URLs; trying {len(todo)} new ones "
          f"({len(done)} pages already saved)")

    new_file = not LABELS_PATH.exists()
    saved = 0
    with open(LABELS_PATH, "a", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(fetch_url, u) for u in todo]
            for i, fut in enumerate(as_completed(futures), 1):
                rec = fut.result()
                if rec:
                    writer.writerow(rec)
                    out.flush()
                    saved += 1
                if i % 25 == 0 or i == len(todo):
                    print(f"  {i}/{len(todo)} tried, {saved} pages saved")

    print(f"Done. Saved {saved} phishing pages (many are already taken down; that's normal).")


if __name__ == "__main__":
    main()
