"""
Build binary-level function call graphs (FCG) from ELF binaries using angr.

Each binary → one PyTorch Geometric Data object:
    x          : [N, 15]  node features (per-function angr features)
    edge_index : [2, E]   directed call edges (caller → callee)
    y          : [1]      binary-level vulnerability label (0=safe, 1=vuln)
"""

import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)

import angr
import torch
from torch_geometric.data import Data

from analysis.static.angr_engine import extract_features_from_project, FEATURES


def build_binary_graph(binary_path, label):
    """
    Build a PyG Data object for one binary.

    Loads the binary with angr, runs CFGFast, extracts per-function node
    features, and builds directed edges from angr's call graph.

    Returns None if the binary cannot be loaded or yields no user functions.
    """
    try:
        proj = angr.Project(str(binary_path), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=False)
    except Exception:
        return None

    func_features = extract_features_from_project(proj)
    if not func_features:
        return None

    # Map function address → node index (avoids name-collision issues)
    addr_to_idx = {f["addr"]: i for i, f in enumerate(func_features)}

    # Node feature matrix [N, len(FEATURES)]
    x = torch.tensor(
        [[f[feat] for feat in FEATURES] for f in func_features],
        dtype=torch.float,
    )

    # Directed call edges from angr's call graph (caller → callee)
    edge_src, edge_dst = [], []
    try:
        for src_addr, dst_addr in proj.kb.callgraph.edges():
            si = addr_to_idx.get(src_addr)
            di = addr_to_idx.get(dst_addr)
            if si is not None and di is not None and si != di:
                edge_src.append(si)
                edge_dst.append(di)
    except Exception:
        pass

    edge_index = (
        torch.tensor([edge_src, edge_dst], dtype=torch.long)
        if edge_src
        else torch.zeros((2, 0), dtype=torch.long)
    )

    return Data(
        x=x,
        edge_index=edge_index,
        y=torch.tensor([label], dtype=torch.long),
    )
