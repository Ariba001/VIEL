import os
import subprocess
import itertools

TEMPLATE_DIR = r"/home/giyu20/viel/templates"
IR_DIR = r"/home/giyu20/viel/ir"

OPT_FLAGS = ["-O0", "-O1", "-O2", "-O3"]

os.makedirs(IR_DIR + "/vuln", exist_ok=True)
os.makedirs(IR_DIR + "/safe", exist_ok=True)

def compile_ir(src, out_dir):
    base = os.path.basename(src).replace(".c", "")
    for opt in OPT_FLAGS:
        out = f"{out_dir}/{base}_{opt.replace('-', '')}.ll"
        cmd = [
            "clang",
            "-emit-llvm",
            "-S",
            opt,
            src,
            "-o",
            out
        ]
        subprocess.run(cmd, check=True)

for label in ["vuln", "safe"]:
    src_dir = os.path.join(TEMPLATE_DIR, label)
    out_dir = os.path.join(IR_DIR, label)

    for fname in os.listdir(src_dir):
        if fname.endswith(".c"):
            compile_ir(os.path.join(src_dir, fname), out_dir)
print("IR generation complete.")
