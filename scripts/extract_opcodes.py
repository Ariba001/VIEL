import os
import csv
from capstone import *
from elftools.elf.elffile import ELFFile

BASE_DIR = "ai_sec_lab"
BIN_DIR = os.path.join(BASE_DIR, "binaries")
LABEL_FILE = os.path.join(BASE_DIR, "labels.csv")
OUTPUT_FILE = os.path.join(BASE_DIR, "opcode_dataset_semantic.csv")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# -------------------------------------------------
# Build PLT address → symbol name mapping
# -------------------------------------------------

def build_plt_symbol_map(elf):
    symbol_map = {}

    plt_section = elf.get_section_by_name(".plt")
    rel_plt = elf.get_section_by_name(".rela.plt") or elf.get_section_by_name(".rel.plt")
    dynsym = elf.get_section_by_name(".dynsym")

    if not plt_section or not rel_plt or not dynsym:
        return symbol_map

    plt_addr = plt_section["sh_addr"]
    entry_size = 16

    for idx, rel in enumerate(rel_plt.iter_relocations()):
        symbol_idx = rel.entry["r_info_sym"]
        symbol = dynsym.get_symbol(symbol_idx)
        symbol_name = symbol.name

        plt_entry_addr = plt_addr + (idx + 1) * entry_size

        symbol_map[plt_entry_addr] = symbol_name

    return symbol_map


# -------------------------------------------------
# Normalize instruction (with semantic calls)
# -------------------------------------------------

def normalize_instruction(insn, symbol_map):
    mnemonic = insn.mnemonic

    if mnemonic == "call":
        if insn.operands and insn.operands[0].type == CS_OP_IMM:
            target = insn.operands[0].imm

            if target in symbol_map:
                return f"call_{symbol_map[target]}"
            else:
                return "call_internal"

        return "call_indirect"


    operand_types = []

    for op in insn.operands:
        if op.type == CS_OP_REG:
            operand_types.append("reg")
        elif op.type == CS_OP_IMM:
            operand_types.append("imm")
        elif op.type == CS_OP_MEM:
            operand_types.append("mem")

    if operand_types:
        return f"{mnemonic}_{'_'.join(operand_types)}"

    return mnemonic


# -------------------------------------------------
# Load labels
# -------------------------------------------------

labels = {}
with open(LABEL_FILE, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        labels[row["filename"]] = row["label"]


rows = []

for binary in os.listdir(BIN_DIR):

    path = os.path.join(BIN_DIR, binary)

    if not os.path.isfile(path):
        continue

    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)

            text_section = elf.get_section_by_name(".text")
            if not text_section:
                continue

            symbol_map = build_plt_symbol_map(elf)

            code = text_section.data()
            addr = text_section["sh_addr"]

            tokens = []

            for insn in md.disasm(code, addr):
                token = normalize_instruction(insn, symbol_map)
                tokens.append(token)

            if not tokens:
                continue

            token_string = " ".join(tokens[:4000])
            label = labels.get(binary)

            if label is None:
                continue

            rows.append([binary, token_string, label])

    except Exception as e:
        print(f"Error processing {binary}: {e}")

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["filename", "tokens", "label"])
    writer.writerows(rows)

print("Semantic dataset with PLT resolution created.")