"""
Extract per-function opcode token sequences from ELF binaries.

Produces ai_sec_lab/opcode_dataset_semantic.csv with columns:
    binary, function, tokens, label

One row per function (not per binary). Label comes from labels.csv
(binary-level ground truth): every function in a vulnerable binary
receives label=1, every function in a safe binary label=0. This
covers vulnerability types (race, use_after_free) where the vulnerable
function is not named "vuln*".
"""

import os
import csv
import sys

# Support running as `python scripts/extract_opcodes.py` (script mode)
# or `python -m scripts.extract_opcodes` (module mode) from project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.opcode_utils import extract_functions_from_binary

BASE_DIR = "ai_sec_lab"
BIN_DIR = os.path.join(BASE_DIR, "binaries")
LABEL_FILE = os.path.join(BASE_DIR, "labels.csv")
OUTPUT_FILE = os.path.join(BASE_DIR, "opcode_dataset_semantic.csv")


def main():
    # Binary-level labels used as fallback for stripped binaries
    binary_labels = {}
    with open(LABEL_FILE, newline="") as f:
        for row in csv.DictReader(f):
            binary_labels[row["filename"]] = int(row["label"])

    rows = []
    skipped = 0

    for binary_name in sorted(os.listdir(BIN_DIR)):
        path = os.path.join(BIN_DIR, binary_name)
        if not os.path.isfile(path):
            continue

        functions = extract_functions_from_binary(path)

        if functions:
            label = binary_labels.get(binary_name, 0)
            for func in functions:
                rows.append([binary_name, func["function"], func["tokens"], label])
        else:
            # Stripped binary — fall back to whole-binary label
            bin_label = binary_labels.get(binary_name)
            if bin_label is None:
                skipped += 1
                continue
            # Import whole-binary extraction inline to avoid circular deps
            from elftools.elf.elffile import ELFFile
            from scripts.opcode_utils import build_plt_symbol_map, normalize_instruction, _md
            try:
                with open(path, "rb") as f:
                    elf = ELFFile(f)
                    text = elf.get_section_by_name(".text")
                    if not text:
                        skipped += 1
                        continue
                    sym_map = build_plt_symbol_map(elf)
                    tokens = [
                        normalize_instruction(insn, sym_map)
                        for insn in _md.disasm(text.data(), text["sh_addr"])
                    ]
                if tokens:
                    rows.append([binary_name, "<whole_binary>", " ".join(tokens[:4000]), bin_label])
                else:
                    skipped += 1
            except Exception:
                skipped += 1

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["binary", "function", "tokens", "label"])
        writer.writerows(rows)

    print(f"Saved {len(rows)} rows to {OUTPUT_FILE}")
    vuln = sum(1 for r in rows if r[3] == 1)
    print(f"  {vuln} vulnerable  /  {len(rows) - vuln} safe  (skipped {skipped})")


if __name__ == "__main__":
    main()
