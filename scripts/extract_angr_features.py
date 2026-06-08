"""
Extract per-function angr CFG features from all ELF binaries in ai_sec_lab/binaries/.

Produces ai_sec_lab/angr_dataset.csv with columns:
    binary, function, <features...>, label

Label comes from labels.csv (binary-level ground truth). Every function in a
vulnerable binary receives label=1, every function in a safe binary label=0.
This allows the RF to detect ALL vulnerability types — including race conditions
and use-after-free — where the vulnerable function is not named "vuln*".

Run:
    python scripts/extract_angr_features.py
"""

import os
import sys
import csv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.static.angr_engine import extract_binary_features, FEATURES

BASE_DIR    = "ai_sec_lab"
BIN_DIR     = os.path.join(BASE_DIR, "binaries")
OUTPUT_FILE = os.path.join(BASE_DIR, "angr_dataset.csv")
LABEL_FILE  = os.path.join(BASE_DIR, "labels.csv")

FIELDNAMES = ["binary", "function"] + FEATURES + ["label"]


def main():
    binary_labels = {}
    with open(LABEL_FILE, newline="") as f:
        for row in csv.DictReader(f):
            binary_labels[row["filename"]] = int(row["label"])

    binaries = sorted(
        f for f in os.listdir(BIN_DIR)
        if os.path.isfile(os.path.join(BIN_DIR, f))
    )
    print(f"Processing {len(binaries)} binaries...")

    rows = []
    skipped = 0

    for i, binary_name in enumerate(binaries, 1):
        path = os.path.join(BIN_DIR, binary_name)
        print(f"  [{i:4d}/{len(binaries)}] {binary_name}", end="", flush=True)

        functions = extract_binary_features(path)
        if not functions:
            print(" — skipped")
            skipped += 1
            continue

        label = binary_labels.get(binary_name, 0)
        for func in functions:
            row = {"binary": binary_name, "label": label}
            row.update({k: v for k, v in func.items() if k in set(FIELDNAMES)})
            rows.append(row)

        print(f" — {len(functions)} functions")

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved {len(rows)} rows -> {OUTPUT_FILE}")
    vuln = sum(1 for r in rows if r["label"] == 1)
    print(f"  {vuln} vulnerable  /  {len(rows) - vuln} safe  (skipped {skipped} binaries)")


if __name__ == "__main__":
    main()
