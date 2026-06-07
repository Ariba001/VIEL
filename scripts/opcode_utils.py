"""
Shared utilities for per-function opcode extraction from ELF binaries.
Used by extract_opcodes.py (dataset generation) and predict.py (inference).
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_REG, CS_OP_MEM
from elftools.elf.elffile import ELFFile

_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True


def build_plt_symbol_map(elf):
    """Map PLT entry addresses to their library symbol names (e.g. strcpy, printf)."""
    symbol_map = {}
    plt_section = elf.get_section_by_name(".plt")
    rel_plt = elf.get_section_by_name(".rela.plt") or elf.get_section_by_name(".rel.plt")
    dynsym = elf.get_section_by_name(".dynsym")
    if not plt_section or not rel_plt or not dynsym:
        return symbol_map
    plt_addr = plt_section["sh_addr"]
    entry_size = 16
    for idx, rel in enumerate(rel_plt.iter_relocations()):
        sym = dynsym.get_symbol(rel.entry["r_info_sym"])
        symbol_map[plt_addr + (idx + 1) * entry_size] = sym.name
    return symbol_map


def normalize_instruction(insn, symbol_map):
    """
    Turn a capstone instruction into a normalised token.
    Calls are resolved to their library name when possible (call_strcpy, call_printf …).
    Operand types are appended so mov eax,ebx → mov_reg_reg.
    """
    mnemonic = insn.mnemonic

    if mnemonic == "call":
        if insn.operands and insn.operands[0].type == CS_OP_IMM:
            target = insn.operands[0].imm
            if target in symbol_map:
                return f"call_{symbol_map[target]}"
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


def extract_functions_from_binary(binary_path, max_tokens=4000):
    """
    Extract per-function opcode token sequences from an ELF binary.

    Uses the .symtab section to find function boundaries, then disassembles
    each function's code range from .text with Capstone.

    Returns a list of dicts:
        {"function": str, "tokens": str}

    Returns an empty list if the file is not ELF, is stripped (no .symtab),
    or has no .text section.
    """
    results = []
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)

            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return results

            text_section = elf.get_section_by_name(".text")
            if text_section is None:
                return results

            text_addr = text_section["sh_addr"]
            text_data = text_section.data()
            symbol_map = build_plt_symbol_map(elf)

            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue
                func_addr = sym["st_value"]
                func_size = sym["st_size"]
                if func_size < 5 or not sym.name:
                    continue

                offset = func_addr - text_addr
                if offset < 0 or offset + func_size > len(text_data):
                    continue

                func_code = text_data[offset : offset + func_size]
                tokens = [
                    normalize_instruction(insn, symbol_map)
                    for insn in _md.disasm(func_code, func_addr)
                ]
                if not tokens:
                    continue

                results.append({
                    "function": sym.name,
                    "tokens": " ".join(tokens[:max_tokens]),
                })

    except Exception:
        pass

    return results
