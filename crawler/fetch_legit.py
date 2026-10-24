"""Fetch homepage + login pages for a sample of Tranco domains (label = legit).

Run from the repo root with the venv active, after fetch_tranco.py:
    python crawler/fetch_legit.py --n 50          # small test run first
    python crawler/fetch_legit.py --n 1000        # real run

Output:
    data/raw/legit/<id>.html.txt   raw HTML (saved as .txt so it is never opened as a web page)
    data/labels.csv                one row per saved page

Safety: downloads HTML text only. No JavaScript is executed, nothing is rendered,
downloads/non-HTML responses are skipped, and every request has a timeout and size cap.
Re-running resumes: URLs already in labels.csv are skipped.
"""
import argparse
import csv
import hashlib
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
TRANCO_PATH = ROOT / "data" / "tranco_top.csv"
RAW_DIR = ROOT / "data" / "raw" / "legit"
LABELS_PATH = ROOT / "data" / "labels.csv"

FIELDS = ["url", "final_url", "label", "source", "fetched_at",
          "http_status", "file", "sha256", "bytes"]
PATHS = ["/", "/login", "/signin"]
MAX_BYTES = 2_000_000          # cap per page
TIMEOUT = (5, 10)              # connect, read (seconds)
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 "
                   "phishing-guard-research/0.1"),
    "Accept": "text/html,application/xhtml+xml",
}


def fetch_page(url: str):
    """Return (final_url, status, body_bytes) for an HTML 200 response, else None."""
    try:
        with requests.get(url, timeout=TIMEOUT, headers=HEADERS,
                          stream=True, allow_redirects=True) as r:
            ctype = r.headers.get("Content-Type", "").lower()
            if r.status_code != 200 or "html" not in ctype:
                return None
            chunks, size = [], 0
            for chunk in r.iter_content(65536):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BYTES:
                    break
            return r.url, r.status_code, b"".join(chunks)[:MAX_BYTES]
    except requests.RequestException:
        return None


def fetch_domain(domain: str):
    """Fetch the homepage (and login pages) of one domain. Returns a list of records."""
    records, seen_hashes = [], set()
    base = None
    for prefix in (f"https://{domain}", f"https://www.{domain}"):
        if fetch_page(prefix + "/") is not None:
            base = prefix
            break
    if base is None:
        return records

    for path in PATHS:
        url = base + path
        result = fetch_page(url)
        if result is None:
            continue
        final_url, status, body = result
        digest = hashlib.sha256(body).hexdigest()
        if digest in seen_hashes:   # e.g. /login just redirected to the homepage
            continue
        seen_hashes.add(digest)
        file_id = hashlib.sha1(url.encode()).hexdigest()[:16]
        file_name = f"{file_id}.html.txt"
        (RAW_DIR / file_name).write_bytes(body)
        records.append({
            "url": url, "final_url": final_url, "label": "legit",
            "source": "tranco",
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "http_status": status, "file": file_name,
            "sha256": digest, "bytes": len(body),
        })
    return records


def load_done_urls() -> set:
    if not LABELS_PATH.exists():
        return set()
    with open(LABELS_PATH, newline="", encoding="utf-8") as f:
        return {row["url"] for row in csv.DictReader(f)}


def load_domains(min_rank: int, max_rank: int) -> list:
    with open(TRANCO_PATH, newline="", encoding="utf-8") as f:
        return [row["domain"] for row in csv.DictReader(f)
                if min_rank <= int(row["rank"]) <= max_rank]


def main() -> None:
    p = argparse.ArgumentParser(description="Crawl legit pages from Tranco domains")
    p.add_argument("--n", type=int, default=50, help="how many domains to sample")
    p.add_argument("--min-rank", type=int, default=1)
    p.add_argument("--max-rank", type=int, default=10000)
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    if not TRANCO_PATH.exists():
        raise SystemExit("Run crawler/fetch_tranco.py first.")

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    done = load_done_urls()
    domains = load_domains(args.min_rank, args.max_rank)
    random.Random(args.seed).shuffle(domains)
    todo = [d for d in domains if f"https://{d}/" not in done
            and f"https://www.{d}/" not in done][: args.n]
    print(f"Sampling {len(todo)} domains ({len(done)} pages already saved)")

    new_file = not LABELS_PATH.exists()
    saved = ok_domains = 0
    with open(LABELS_PATH, "a", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(fetch_domain, d): d for d in todo}
            for i, fut in enumerate(as_completed(futures), 1):
                recs = fut.result()
                if recs:
                    ok_domains += 1
                    writer.writerows(recs)
                    out.flush()
                    saved += len(recs)
                if i % 25 == 0 or i == len(todo):
                    print(f"  {i}/{len(todo)} domains tried, "
                          f"{ok_domains} reachable, {saved} pages saved")

    print(f"Done. Saved {saved} pages to {RAW_DIR}")
    print(f"Labels: {LABELS_PATH}")


if __name__ == "__main__":
    main()
