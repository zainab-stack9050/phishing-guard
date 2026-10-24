"""Download the Tranco top-sites list and save the top N domains.

Run from the repo root with the venv active:
    python crawler/fetch_tranco.py             # top 10,000 (default)
    python crawler/fetch_tranco.py --n 5000

Output: data/tranco_top.csv  (columns: rank,domain)

This only downloads a CSV of domain names. It never visits any of the sites.
"""
import argparse
import csv
import io
import zipfile
from pathlib import Path

import requests

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "data" / "tranco_top.csv"


def download_zip(url: str) -> bytes:
    resp = requests.get(
        url,
        timeout=60,
        headers={"User-Agent": "phishing-guard-research/0.1"},
    )
    resp.raise_for_status()
    return resp.content


def read_top_n(zip_bytes: bytes, n: int) -> list[tuple[int, str]]:
    rows = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        with zf.open(zf.namelist()[0]) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            for row in reader:
                if len(row) < 2:
                    continue
                try:
                    rank = int(row[0])
                except ValueError:
                    continue  # skip a header row if there is one
                rows.append((rank, row[1].strip().lower()))
                if len(rows) >= n:
                    break
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch top N Tranco domains")
    parser.add_argument("--n", type=int, default=10000, help="how many domains to keep")
    args = parser.parse_args()

    print(f"Downloading {TRANCO_URL} ...")
    data = download_zip(TRANCO_URL)
    print(f"Downloaded {len(data) / 1e6:.1f} MB")

    rows = read_top_n(data, args.n)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["rank", "domain"])
        writer.writerows(rows)

    print(f"Saved {len(rows)} domains to {OUT_PATH}")
    print("First 5:", [d for _, d in rows[:5]])


if __name__ == "__main__":
    main()
