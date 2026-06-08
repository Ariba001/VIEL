"""
angr-based per-function feature extractor for ELF binaries.

Public API:
    FEATURES  — ordered list of feature column names
    extract_binary_features(binary_path) -> list[dict]
        Each dict has "function" (str) + one key per entry in FEATURES.
"""

import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)

import angr  # noqa: E402

UNSAFE_FUNCS = frozenset({
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "snprintf",
    "scanf", "fscanf", "sscanf", "system", "popen",
    "memcpy", "memmove", "strncpy",
})

COND_JUMP_MNEMONICS = frozenset({
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
})

FEATURES = [
    "instructions", "basic_blocks", "edges", "calls", "indirect_calls",
    "unsafe_call_count", "has_unsafe_call", "loops", "cyclomatic_complexity",
    "avg_bb_size", "max_bb_size", "mem_ops", "stack_ops",
    "cond_jumps", "ret_count",
]

_SKIP_PREFIXES = ("__", "_dl_", "_start", "_init", "_fini", "deregister_", "register_")


def _count_back_edges(graph):
    """Count back-edges via iterative DFS — approximates loop count."""
    visited, in_stack = set(), set()
    count = 0

    for start in list(graph.nodes()):
        if start in visited:
            continue
        stack = [(start, iter(graph.successors(start)))]
        visited.add(start)
        in_stack.add(start)

        while stack:
            node, children = stack[-1]
            try:
                child = next(children)
                if child not in visited:
                    visited.add(child)
                    in_stack.add(child)
                    stack.append((child, iter(graph.successors(child))))
                elif child in in_stack:
                    count += 1
            except StopIteration:
                in_stack.discard(node)
                stack.pop()

    return count


def _extract_function_features(proj, func, plt_name_map):
    """Return a feature dict for one Function, or None if the function is empty."""
    blocks = list(func.blocks)
    if not blocks:
        return None

    graph = func.graph
    n_blocks = max(graph.number_of_nodes(), len(blocks))
    n_edges = graph.number_of_edges()
    loops = _count_back_edges(graph)
    cyclomatic = max(n_edges - n_blocks + 2, 1)

    bb_sizes = []
    total_insns = 0
    direct_calls = 0
    indirect_calls = 0
    unsafe_calls = 0
    mem_ops = 0
    stack_ops = 0
    cond_jumps = 0
    ret_count = 0

    for block in blocks:
        try:
            insns = block.capstone.insns
        except Exception:
            bb_sizes.append(0)
            continue

        bb_sizes.append(len(insns))
        total_insns += len(insns)

        for insn in insns:
            mnemonic = insn.mnemonic.lower()
            op_str = insn.op_str.strip()

            if mnemonic == "call":
                if op_str.startswith("0x"):
                    direct_calls += 1
                    try:
                        target = int(op_str, 16)
                        target_name = plt_name_map.get(target)
                        if target_name is None:
                            tf = proj.kb.functions.get(target)
                            target_name = tf.name if tf else None
                        if target_name and target_name in UNSAFE_FUNCS:
                            unsafe_calls += 1
                    except (ValueError, KeyError):
                        pass
                else:
                    indirect_calls += 1

            elif mnemonic in ("ret", "retn", "retf", "retfq"):
                ret_count += 1

            elif mnemonic in COND_JUMP_MNEMONICS or (
                mnemonic.startswith("j") and mnemonic != "jmp"
            ):
                cond_jumps += 1

            if "[" in insn.op_str:
                mem_ops += 1
                lo = insn.op_str.lower()
                if any(r in lo for r in ("rbp", "rsp", "ebp", "esp")):
                    stack_ops += 1

    if total_insns == 0:
        return None

    return {
        "instructions": total_insns,
        "basic_blocks": n_blocks,
        "edges": n_edges,
        "calls": direct_calls,
        "indirect_calls": indirect_calls,
        "unsafe_call_count": unsafe_calls,
        "has_unsafe_call": int(unsafe_calls > 0),
        "loops": loops,
        "cyclomatic_complexity": cyclomatic,
        "avg_bb_size": round(sum(bb_sizes) / len(bb_sizes), 3) if bb_sizes else 0.0,
        "max_bb_size": max(bb_sizes) if bb_sizes else 0,
        "mem_ops": mem_ops,
        "stack_ops": stack_ops,
        "cond_jumps": cond_jumps,
        "ret_count": ret_count,
    }


def extract_features_from_project(proj):
    """
    Extract per-function features from an already-loaded and analysed Project.

    Each returned dict has "function" (str), "addr" (int), and one key per
    FEATURES entry. Exposed so callers that already hold a Project (e.g.
    graph_builder) can avoid loading the binary a second time.
    """
    plt_name_map = {
        addr: func.name
        for addr, func in proj.kb.functions.items()
        if func.is_plt and func.name
    }

    results = []
    for func_addr, func in proj.kb.functions.items():
        if func.is_plt or func.is_syscall:
            continue
        if not func.name or func.name.startswith(_SKIP_PREFIXES):
            continue

        features = _extract_function_features(proj, func, plt_name_map)
        if features is None:
            continue

        features["function"] = func.name
        features["addr"] = func_addr
        results.append(features)

    return results


def extract_binary_features(binary_path):
    """
    Extract per-function CFG and instruction-level features from an ELF binary.

    Returns a list of dicts, each containing "function" (str), "addr" (int),
    and one key per FEATURES entry. Returns [] if angr cannot load the binary.
    """
    try:
        proj = angr.Project(str(binary_path), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=False)
    except Exception:
        return []

    return extract_features_from_project(proj)
