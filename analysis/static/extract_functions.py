import angr
import json
import sys
import os

if len(sys.argv) < 2:
    print("Usage: python extract_functions.py <binary>")
    sys.exit(1)

binary_path = sys.argv[1]

proj = angr.Project(binary_path, auto_load_libs=False)

proj.analyses.CFGFast()

functions = []
for addr, func in proj.kb.functions.items():
    functions.append({
        "name": func.name,
        "address": hex(addr),
        "size": func.size,
        "blocks": len(list(func.blocks))
    })

os.makedirs("datasets/raw", exist_ok=True)

output = {
    "binary": binary_path,
    "functions": functions
}

with open("datasets/raw/functions.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"[+] Extracted functions")
