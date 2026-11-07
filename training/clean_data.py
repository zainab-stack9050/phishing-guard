"""Clean the crawled dataset and report counts.

Run from the repo root with the venv active:
    python training/clean_data.py

Reads : data/labels.csv  and  data/raw/{legit,phish}/*.html.txt
Writes: data/labels_clean.csv   pages that passed every check
        data/dropped.csv        pages removed, with the reason

This only reads text files. It never renders or runs anything.
"""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
LABELS_PATH = DATA / "labels.csv"
CLEAN_PATH = DATA / "labels_clean.csv"
DROPPED_PATH = DATA / "dropped.csv"

MIN_BYTES = 300          # smaller than this is basically an empty page
SMALL_PAGE = 8000        # junk phrases only count on small pages
HTML_HINTS = ("<html", "<body", "<form", "<input", "<script", "<div")

# Takedown, parked, default-server and error pages. Checked on small pages only,
# so a big real page that happens to say "coming soon" somewhere is not dropped.
JUNK_PHRASES = (
    "account suspended", "this account has been suspended", "site has been suspended",
    "domain is parked", "parked domain", "this domain is for sale", "buy this domain",
    "domain may be for sale", "default web server page", "apache2 ubuntu default page",
    "welcome to nginx", "it works!", "index of /", "403 forbidden", "404 not found",
    "page not found", "the requested url was not found", "website is under construction",
    "under construction", "coming soon", "deceptive site ahead", "this site has been blocked",
    "service unavailable", "bandwidth limit exceeded", "website is temporarily unavailable",
)


def read_text(label: str, file_name: str):
    path = DATA / "raw" / label / file_name
    if not path.exists():
        return None
    return path.read_bytes().decode("utf-8", errors="ignore").lower()


def page_problem(label: str, file_name: str):
    """Return a reason string if the page should be dropped, else None."""
    text = read_text(label, str(file_name))
    if text is None:
        return "missing_file"
    if len(text.strip()) < MIN_BYTES:
        return "too_small"
    if not any(hint in text for hint in HTML_HINTS):
        return "no_html"
    if len(text) < SMALL_PAGE and any(p in text for p in JUNK_PHRASES):
        return "junk_page"
    return None


def main() -> None:
    if not LABELS_PATH.exists():
        raise SystemExit("data/labels.csv not found. Run the crawlers first.")

    df = pd.read_csv(LABELS_PATH)
    df["fetched_at"] = pd.to_datetime(df["fetched_at"], utc=True, errors="coerce")
    df = df.sort_values("fetched_at").reset_index(drop=True)
    df["reason"] = [page_problem(lab, f) for lab, f in zip(df["label"], df["file"])]

    # Same content labelled as both legit and phish: ambiguous, drop all copies.
    ok = df[df["reason"].isna()]
    labels_per_hash = ok.groupby("sha256")["label"].nunique()
    conflicting = set(labels_per_hash[labels_per_hash > 1].index)
    df.loc[df["reason"].isna() & df["sha256"].isin(conflicting), "reason"] = "label_conflict"

    # Exact duplicates within a class: keep the earliest copy.
    ok = df[df["reason"].isna()]
    dup_idx = ok[ok.duplicated(subset=["label", "sha256"], keep="first")].index
    df.loc[dup_idx, "reason"] = "duplicate"

    kept = df[df["reason"].isna()].drop(columns="reason")
    dropped = df[df["reason"].notna()]

    kept.to_csv(CLEAN_PATH, index=False)
    dropped.to_csv(DROPPED_PATH, index=False)

    print("\n=== Before cleaning ===")
    print(df["label"].value_counts().to_string())
    print("\n=== Dropped, by reason ===")
    if dropped.empty:
        print("(nothing dropped)")
    else:
        print(pd.crosstab(dropped["reason"], dropped["label"]).to_string())
    print("\n=== After cleaning ===")
    print(kept["label"].value_counts().to_string())

    if not kept.empty:
        weeks = kept["fetched_at"].dt.strftime("%G-W%V")
        print("\n=== Kept pages per week ===")
        print(pd.crosstab(weeks, kept["label"]).to_string())

    print(f"\nWrote {CLEAN_PATH.name} ({len(kept)} rows) and {DROPPED_PATH.name} ({len(dropped)} rows)")


if __name__ == "__main__":
    main()
