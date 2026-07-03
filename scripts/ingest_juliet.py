"""
Ingest the NIST Juliet Test Suite for C/C++ into VIEL's binary dataset
format.

Compiles single-file Juliet test cases into separate "bad" (vulnerable)
and "good" (safe) ELF binaries. Unlike the ~30 synthetic templates in
ai_sec_lab/, this pulls in real NIST-curated C code spanning ~118 CWE
categories -- far more diverse vulnerability shapes for the model to
learn from than one-line strcpy/gets templates.

Requires a Linux gcc toolchain (WSL2/Docker on Windows, same requirement
as scripts/generate_dataset.py) and a local clone of the Juliet source:

    git clone https://github.com/arichardson/juliet-test-suite-c

Each Juliet test case file defines a "<testcase>_bad()" function guarded
by #ifndef OMITBAD, and "good*()" functions guarded by #ifndef OMITGOOD,
plus a main() guarded by #ifdef INCLUDEMAIN that calls whichever wasn't
omitted. Compiling once with -DOMITGOOD and once with -DOMITBAD (both
with -DINCLUDEMAIN) yields two binaries, each with an unambiguous single
vulnerable-or-safe function -- no per-template lookup table needed (see
analysis/static/juliet_labels.py), because the sibling function is
entirely absent from the binary that doesn't want it.

Scope (v1): only single-file test cases are ingested -- multi-file flow
variants (e.g. "..._11a.c" / "..._11b.c", which need multiple
translation units linked together) and Windows-only sources are skipped.

Run (inside WSL2/Docker, from the repo root):
    python3 scripts/ingest_juliet.py \\
        --juliet-src ~/juliet_src/juliet-test-suite-c \\
        --cwes CWE121_Stack_Based_Buffer_Overflow CWE122_Heap_Based_Buffer_Overflow \\
        --per-cwe-limit 25 --opt-levels O0 O2

Then build graphs the same way as the synthetic dataset:
    python scripts/build_graphs.py --dataset juliet
"""

import argparse
import csv
import re
import subprocess
from pathlib import Path

# Single-file flow variant: "..._01.c", "..._11.c" (no trailing a/b/c letter)
SINGLE_FILE_RE = re.compile(r"_\d+\.c$")

OUT_BASE = Path("ai_sec_lab") / "juliet"


def find_single_file_testcases(juliet_src: Path, cwe: str):
    cwe_dir = juliet_src / "testcases" / cwe
    if not cwe_dir.is_dir():
        raise FileNotFoundError(f"No such CWE directory: {cwe_dir}")
    for path in sorted(cwe_dir.rglob("*.c")):
        if "w32" in path.name.lower():
            continue  # Windows-API-only variant
        if not SINGLE_FILE_RE.search(path.name):
            continue  # multi-file flow variant, e.g. "..._11a.c"
        yield path


def compile_variant(src: Path, support_dir: Path, out_path: Path, opt: str, omit_flag: str) -> bool:
    cmd = [
        "gcc", str(src),
        "-o", str(out_path),
        f"-{opt}",
        "-DINCLUDEMAIN", f"-D{omit_flag}",
        "-I", str(support_dir),
        str(support_dir / "io.c"),
        str(support_dir / "std_thread.c"),
        "-fno-stack-protector", "-no-pie",
        "-lpthread", "-lm",
        "-w",  # Juliet sources deliberately trigger compiler warnings
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--juliet-src", required=True, help="Path to a cloned juliet-test-suite-c checkout")
    ap.add_argument("--cwes", nargs="+", required=True, help="CWE directory names under testcases/")
    ap.add_argument("--per-cwe-limit", type=int, default=None, help="Max testcases to ingest per CWE (default: all)")
    ap.add_argument("--opt-levels", nargs="+", default=["O0", "O2"])
    args = ap.parse_args()

    juliet_src  = Path(args.juliet_src)
    support_dir = juliet_src / "testcasesupport"
    bin_dir     = OUT_BASE / "binaries"
    bin_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    compiled, failed = 0, 0

    for cwe in args.cwes:
        testcases = list(find_single_file_testcases(juliet_src, cwe))
        if args.per_cwe_limit:
            testcases = testcases[: args.per_cwe_limit]
        print(f"{cwe}: {len(testcases)} single-file testcases", flush=True)

        for src in testcases:
            stem = src.stem
            for opt in args.opt_levels:
                for variant, omit_flag in (("bad", "OMITGOOD"), ("good", "OMITBAD")):
                    out_name = f"{stem}__{opt}__{variant}"
                    out_path = bin_dir / out_name
                    if compile_variant(src, support_dir, out_path, opt, omit_flag):
                        rows.append((out_name, 1 if variant == "bad" else 0))
                        compiled += 1
                    else:
                        failed += 1

    labels_path = OUT_BASE / "labels.csv"
    with open(labels_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["filename", "label"])
        writer.writerows(rows)

    total = compiled + failed
    rate  = compiled / total * 100 if total else 0.0
    print(f"\nCompiled {compiled}/{total} binaries ({rate:.1f}%) -> {bin_dir}")
    print(f"Labels written -> {labels_path}")


if __name__ == "__main__":
    main()
