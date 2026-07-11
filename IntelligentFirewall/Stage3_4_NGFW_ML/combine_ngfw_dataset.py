"""
combine_datasets.py — FIXED VERSION
=====================================
Combines CICIDS2017 + UNSW-NB15 into one clean master CSV.

Bugs fixed vs original script:
  BUG 1: COLUMN_MAPPING now uses stripped names (no leading spaces)
  BUG 2: Added 'Protocol' -> 'protocol' mapping for CICIDS
  BUG 3: Label check now handles BENIGN (CICIDS) AND Normal/0 (UNSW)
  BUG 4: Missing columns filled with 0 after concat, not dropped
  BUG 5: DATA_FOLDER corrected to data/raw/

Usage:
    python combine_datasets.py

Output:
    data/processed/master_firewall_data.csv
"""

import os
import glob
import pandas as pd
import numpy as np

# ── Config ────────────────────────────────────────────────────────────
DATA_FOLDER = "./CICIDS2017"                           # FIX 5: correct folder
OUTPUT_FILE = "./data/processed/master_firewall_data.csv"

os.makedirs("./data/processed/", exist_ok=True)

# ── FIX 1 + FIX 2: All keys use STRIPPED names (no leading spaces) ───
# After df.columns.str.strip(), ' Label' becomes 'Label', etc.
# We also add 'Protocol' which was missing entirely.

COLUMN_MAPPING = {
    # ── CICIDS-2017 stripped names → standard names ──────────────────
    "Destination Port"               : "dst_port",
    "Flow Duration"                  : "duration",
    "Total Length of Fwd Packets"    : "src_bytes",
    "Total Length of Bwd Packets"    : "dst_bytes",
    "Total Fwd Packets"              : "src_packets",
    "Total Backward Packets"         : "dst_packets",
    "Protocol"                       : "protocol",   # FIX 2: was missing
    "Label"                          : "label",       # FIX 1: no leading space

    # ── UNSW-NB15 names → standard names ─────────────────────────────
    "dur"                            : "duration",
    "sbytes"                         : "src_bytes",
    "dbytes"                         : "dst_bytes",
    "spkts"                          : "src_packets",
    "dpkts"                          : "dst_packets",
    "proto"                          : "protocol",
    "label"                          : "label",
    "dsport"                         : "dst_port",
    "sport"                          : "src_port",
}

# All standard column names we want in the final dataset
MASTER_COLUMNS = [
    "dst_port", "src_port", "duration",
    "src_bytes", "dst_bytes",
    "src_packets", "dst_packets",
    "protocol", "label",
]

# ── FIX 3: All normal-traffic labels across both datasets ─────────────
# CICIDS2017: normal traffic is labeled "BENIGN"
# UNSW-NB15:  normal traffic is labeled 0 (integer) or "Normal" (string)
NORMAL_LABELS = {"benign", "normal", "0"}


def is_normal(val) -> bool:
    """Return True if this label value means normal/benign traffic."""
    return str(val).strip().lower() in NORMAL_LABELS


def clean_and_map(df: pd.DataFrame, filename: str) -> pd.DataFrame:
    """
    Strip column names, map to standard names, normalize label,
    fill missing standard columns with 0 (FIX 4 — no NaN flood).
    """
    # Step 1: Strip ALL whitespace from column names
    df.columns = df.columns.str.strip()

    # Step 2: Keep only columns that exist in our mapping
    cols_to_keep = [c for c in df.columns if c in COLUMN_MAPPING]

    if not cols_to_keep:
        print(f"  WARNING: No mappable columns found in {filename}")
        print(f"  Available columns: {list(df.columns[:8])}")
        return pd.DataFrame()

    df = df[cols_to_keep].copy()

    # Step 3: Rename to standard names
    df = df.rename(columns=COLUMN_MAPPING)

    # Step 4: Remove Inf values (replace with NaN first)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Step 5: Drop rows where label is missing (we can't train without it)
    if "label" in df.columns:
        df = df.dropna(subset=["label"])
    else:
        print(f"  WARNING: 'label' column not found after mapping in {filename}")
        print(f"  Columns after mapping: {list(df.columns)}")
        return pd.DataFrame()

    # Step 6: FIX 3 — correct binary labeling
    #   0 = normal/benign,  1 = any attack
    df["label"] = df["label"].apply(lambda x: 0 if is_normal(x) else 1)

    # Step 7: FIX 4 — add any missing master columns as 0
    #   (prevents NaN flood when concatenating CICIDS + UNSW)
    for col in MASTER_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    # Step 8: Keep only master columns
    df = df[MASTER_COLUMNS]

    # Step 9: Drop rows with NaN in numeric columns (after filling missing cols)
    df = df.dropna()

    # Step 10: Ensure correct dtypes
    for col in MASTER_COLUMNS:
        if col == "protocol":
            # protocol can be string (e.g. "tcp") or int — keep as string
            df[col] = df[col].astype(str)
        elif col == "label":
            df[col] = df[col].astype(int)
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    return df


def detect_dataset_type(df: pd.DataFrame) -> str:
    """Detect whether this is CICIDS2017 or UNSW-NB15 based on column names."""
    cols = set(df.columns.str.strip())
    if "Label" in cols or "Flow Duration" in cols:
        return "CICIDS2017"
    elif "dur" in cols or "sbytes" in cols:
        return "UNSW-NB15"
    return "UNKNOWN"


def combine_data():
    print("\n====== COMBINING DATASETS ======\n")

    # Verify folder exists
    if not os.path.exists(DATA_FOLDER):
        print(f"ERROR: DATA_FOLDER not found: {DATA_FOLDER}")
        print(f"Please create it and copy your CSV files there.")
        return

    all_files = sorted(glob.glob(os.path.join(DATA_FOLDER, "*.csv")))

    if not all_files:
        print(f"ERROR: No CSV files found in {DATA_FOLDER}")
        return

    print(f"Found {len(all_files)} CSV file(s):\n")

    combined_list = []
    stats = []

    for filename in all_files:
        fname = os.path.basename(filename)
        size_mb = os.path.getsize(filename) / (1024 * 1024)
        print(f"Reading  : {fname}  ({size_mb:.0f} MB)")

        try:
            df_raw = pd.read_csv(
                filename,
                encoding="cp1252",    # handles CICIDS2017 encoding
                low_memory=False,
                on_bad_lines="skip",  # skip malformed rows instead of crashing
            )
        except UnicodeDecodeError:
            df_raw = pd.read_csv(filename, encoding="utf-8", low_memory=False,
                                 on_bad_lines="skip")
        except Exception as e:
            print(f"  ERROR reading {fname}: {e}")
            continue

        dataset_type = detect_dataset_type(df_raw)
        print(f"  Type    : {dataset_type}")
        print(f"  Raw rows: {len(df_raw):,}")

        clean_df = clean_and_map(df_raw, fname)

        if clean_df.empty:
            print(f"  SKIPPED (no usable rows after cleaning)\n")
            continue

        normal_count = (clean_df["label"] == 0).sum()
        attack_count = (clean_df["label"] == 1).sum()

        print(f"  Clean rows : {len(clean_df):,}")
        print(f"  Normal (0) : {normal_count:,}  ({100*normal_count/len(clean_df):.1f}%)")
        print(f"  Attack (1) : {attack_count:,}  ({100*attack_count/len(clean_df):.1f}%)")
        print()

        stats.append({
            "file": fname,
            "type": dataset_type,
            "rows": len(clean_df),
            "normal": int(normal_count),
            "attack": int(attack_count),
        })

        combined_list.append(clean_df)

    if not combined_list:
        print("ERROR: No data was successfully loaded. Check your file paths and formats.")
        return

    # ── Merge ──────────────────────────────────────────────────────────
    print("Merging all datasets …")
    master_df = pd.concat(combined_list, axis=0, ignore_index=True)

    # Final shuffle
    master_df = master_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # ── Summary ────────────────────────────────────────────────────────
    print("\n====== FINAL SUMMARY ======\n")
    print(f"{'File':<55} {'Type':<12} {'Rows':>10} {'Normal':>10} {'Attack':>10}")
    print("-" * 100)
    for s in stats:
        print(f"{s['file']:<55} {s['type']:<12} {s['rows']:>10,} {s['normal']:>10,} {s['attack']:>10,}")

    total_normal = (master_df["label"] == 0).sum()
    total_attack = (master_df["label"] == 1).sum()
    total        = len(master_df)

    print("-" * 100)
    print(f"{'TOTAL':<55} {'COMBINED':<12} {total:>10,} {total_normal:>10,} {total_attack:>10,}")
    print(f"\nClass ratio: {total_normal:,} normal  vs  {total_attack:,} attacks")
    print(f"Attack percentage: {100*total_attack/total:.1f}%")
    print(f"\nColumns in master dataset: {list(master_df.columns)}")
    print(f"\nSample rows:")
    print(master_df.head(3).to_string())

    # ── Save ───────────────────────────────────────────────────────────
    master_df.to_csv(OUTPUT_FILE, index=False)
    out_size = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    print(f"\nSaved: {OUTPUT_FILE}  ({out_size:.1f} MB)")
    print("\nDONE — Run step2_preprocess.py next\n")

    return master_df


if __name__ == "__main__":
    combine_data()