"""
Build binary-level function call graphs (FCG) from ELF binaries using angr.

Graph representation (upgraded):
    User function nodes  [N_user]: 15 angr features + is_library=0, is_unsafe_lib=0
    Library function nodes [N_lib]: zeros + is_library=1, is_unsafe_lib={0,1}

    Directed edges:
        user  -> user     inter-function calls within user code
        user  -> library  calls to imported PLT functions (strcpy, malloc, ...)

    Adding library nodes exposes structural patterns like
        main -> vulnerable -> strcpy
    as graph topology rather than encoding it only as a node feature.

GRAPH_NODE_FEATURES = len(FEATURES) + 2  (exported for model/trainer use)

Per-node labels (y_node):
    Each Data object also carries y_node [N] — a 0/1 label per node
    identifying which *function* carries the injected vuln/safe pattern
    (see analysis.static.vuln_labels). Library nodes are always 0. This
    enables function-level localization (node classification) in addition
    to the existing binary-level (graph classification) task.
"""

import logging
from pathlib import Path

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)

import angr
import torch
from torch_geometric.data import Data

from analysis.static.angr_engine import extract_features_from_project, FEATURES, UNSAFE_FUNCS
from analysis.static.vuln_labels import node_labels

# Node feature dimension: 15 per-function angr features + 2 node-type flags
GRAPH_NODE_FEATURES = len(FEATURES) + 2


def build_binary_graph(binary_path, label):
    """
    Build a PyG Data object for one binary.

    User-defined functions become nodes with 15 angr features.
    Called PLT library functions are added as extra nodes with zero CFG
    features and two type flags (is_library=1, is_unsafe_lib={0,1}).
    Edges cover both user->user and user->library call relationships.

    Returns None if angr cannot load the binary or no user functions exist.
    """
    try:
        proj = angr.Project(str(binary_path), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=False)
    except Exception:
        return None

    func_features = extract_features_from_project(proj)
    if not func_features:
        return None

    # User function address -> node index  (0 .. N_user-1)
    addr_to_idx = {f["addr"]: i for i, f in enumerate(func_features)}

    # PLT address -> symbol name
    plt_name_map = {
        addr: func.name
        for addr, func in proj.kb.functions.items()
        if func.is_plt and func.name
    }

    # Discover library function nodes that user functions actually call.
    # lib_addr -> node index  (N_user .. N_user+N_lib-1)
    lib_addr_to_idx = {}
    lib_nodes = []  # (name, is_unsafe)

    try:
        for src_addr, dst_addr in proj.kb.callgraph.edges():
            if src_addr not in addr_to_idx:
                continue
            if dst_addr in addr_to_idx or dst_addr in lib_addr_to_idx:
                continue
            lib_name = plt_name_map.get(dst_addr)
            if lib_name is None:
                continue
            lib_addr_to_idx[dst_addr] = len(addr_to_idx) + len(lib_nodes)
            lib_nodes.append((lib_name, lib_name in UNSAFE_FUNCS))
    except Exception:
        pass

    # ── Node feature matrix [N_user + N_lib, GRAPH_NODE_FEATURES] ────────────
    N = len(func_features) + len(lib_nodes)
    x = torch.zeros(N, GRAPH_NODE_FEATURES, dtype=torch.float)

    for i, f in enumerate(func_features):
        for j, feat_name in enumerate(FEATURES):
            x[i, j] = float(f[feat_name])
        # x[i, -2] = 0  (is_library)
        # x[i, -1] = 0  (is_unsafe_lib)

    for i, (lib_name, is_unsafe) in enumerate(lib_nodes):
        idx = len(func_features) + i
        x[idx, -2] = 1.0             # is_library
        x[idx, -1] = float(is_unsafe)  # is_unsafe_lib

    # ── Directed call edges (user->user and user->library) ────────────────────
    edge_src, edge_dst = [], []
    try:
        for src_addr, dst_addr in proj.kb.callgraph.edges():
            si = addr_to_idx.get(src_addr)
            if si is None:
                continue
            di = addr_to_idx.get(dst_addr)
            if di is None:
                di = lib_addr_to_idx.get(dst_addr)
            if di is not None and si != di:
                edge_src.append(si)
                edge_dst.append(di)
    except Exception:
        pass

    edge_index = (
        torch.tensor([edge_src, edge_dst], dtype=torch.long)
        if edge_src
        else torch.zeros((2, 0), dtype=torch.long)
    )

    # ── Per-function (node-level) vulnerability labels ────────────────────────
    binary_name = Path(binary_path).name
    func_names = [f["function"] for f in func_features] + [name for name, _ in lib_nodes]
    y_node = torch.tensor(
        node_labels(binary_name, label, func_names), dtype=torch.long
    )
    # True for user-function nodes, False for library nodes — only user
    # functions are eligible localization targets.
    is_user_mask = torch.zeros(N, dtype=torch.bool)
    is_user_mask[: len(func_features)] = True

    return Data(
        x=x,
        edge_index=edge_index,
        y=torch.tensor([label], dtype=torch.long),
        y_node=y_node,
        is_user_mask=is_user_mask,
        func_names=func_names,
        binary_name=binary_name,
    )
