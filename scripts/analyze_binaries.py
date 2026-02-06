import angr
import json
import os
import subprocess
from analysis.symbolic.symbolic_features import extract_symbolic_features


BIN_DIRS = [
    "binaries/vulnerable",
    "binaries/safe"
]

OUTPUT_FILE = "datasets/processed/features.json"

UNSAFE_FUNCS = ["gets", "strcpy", "sprintf", "scanf", "strcat"]

all_features = []

def is_elf(path):
    try:
        out = subprocess.check_output(["file", path]).decode()
        return "ELF" in out
    except:
        return False

def analyze_binary(binary_path):
    print(f"[+] Analyzing {binary_path}")
    proj = angr.Project(binary_path, auto_load_libs=False)

    proj.analyses.CFGFast(normalize=True)

    for func in proj.kb.functions.values():
        has_unsafe = 0

        for block in func.blocks:
            for ins in block.capstone.insns:
                if ins.mnemonic == "call":
                    if any(u in ins.op_str for u in UNSAFE_FUNCS):
                        has_unsafe = 1

        feature = {
            "binary": os.path.basename(binary_path),
            "function": func.name,
            "size": func.size,
            "basic_blocks": len(list(func.blocks)),
            "unsafe_call": has_unsafe,
        }

        sym_feats = extract_symbolic_features(binary_path)

        feature.update(sym_feats)

        all_features.append(feature)

def main():
    for bin_dir in BIN_DIRS:
        for file in os.listdir(bin_dir):
            full_path = os.path.join(bin_dir, file)

            if not os.path.isfile(full_path):
                continue

            if not is_elf(full_path):
                print(f"[~] Skipping non-ELF: {file}")
                continue

            try:
                analyze_binary(full_path)
            except Exception as e:
                print(f"[!] Failed on {file}: {e}")

    os.makedirs("datasets/processed", exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_features, f, indent=2)

    print(f"[✓] Feature extraction complete")
    print(f"[✓] Total functions analyzed: {len(all_features)}")

if __name__ == "__main__":
    main()
