"""Turn every cleaned page into a row of features.

Run from the repo root with the venv active (after clean_data.py):
    python training/build_features.py

Reads : data/labels_clean.csv + data/raw/<label>/<file>
Writes: data/features.csv   (metadata columns + one column per feature)

Features are computed from the URL the page was actually loaded at (final_url),
because that is what the extension will see in the browser.
This only reads text files; nothing is rendered or run.
"""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import extract  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CLEAN_PATH = DATA / "labels_clean.csv"
OUT_PATH = DATA / "features.csv"
META = ["file", "label", "fetched_at", "url"]
SHOW = ["has_password", "form_action_external", "form_action_empty", "is_ip_host",
        "is_https", "kw_in_host", "ext_resource_ratio", "n_hidden_iframes"]


def main() -> None:
    if not CLEAN_PATH.exists():
        raise SystemExit("data/labels_clean.csv not found. Run training/clean_data.py first.")

    labels = pd.read_csv(CLEAN_PATH)
    rows, failed = [], 0
    for rec in labels.itertuples(index=False):
        path = DATA / "raw" / rec.label / rec.file
        try:
            html = path.read_bytes().decode("utf-8", errors="ignore")
            url = rec.final_url if isinstance(rec.final_url, str) and rec.final_url else rec.url
            row = {"file": rec.file, "label": rec.label,
                   "fetched_at": rec.fetched_at, "url": url}
            row.update(extract(url, html))
            rows.append(row)
        except Exception as exc:  # keep going; report at the end
            failed += 1
            print(f"  failed on {rec.file}: {exc}")

    df = pd.DataFrame(rows)
    df.to_csv(OUT_PATH, index=False)
    n_feats = len(df.columns) - len(META)
    print(f"\nWrote {OUT_PATH.name}: {len(df)} rows, {n_feats} features ({failed} failed)")
    print("\n=== Class counts ===")
    print(df["label"].value_counts().to_string())
    print("\n=== Average of a few features per class (sanity check) ===")
    print(df.groupby("label")[SHOW].mean().round(3).T.to_string())


if __name__ == "__main__":
    main()
