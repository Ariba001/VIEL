from capstone import *
import os

def extract_opcodes(binary_path):
    with open(binary_path, "rb") as f:
        code = f.read()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    opcodes = []

    for instruction in md.disasm(code, 0x1000):
        opcodes.append(instruction.mnemonic)

    return opcodes


if __name__ == "__main__":
    binary = "binaries/vuln1_vuln"
    ops = extract_opcodes(binary)
    print(ops[:50])