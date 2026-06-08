"""
Build binary-level function call graphs for all ELF binaries.

Produces ai_sec_lab/graphs.pt — a list of PyTorch Geometric Data objects,
one per binary, with:
    x          : per-function node features  [N, 15]
    edge_index : directed call edges         [2, E]
    y          : binary-level label          [1]

Run:
    python scripts/build_graphs.py
"""

import os
import sys
import csv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch

from analysis.static.graph_builder import build_binary_graph

BASE_DIR    = "ai_sec_lab"
BIN_DIR     = os.path.join(BASE_DIR, "binaries")
LABEL_FILE  = os.path.join(BASE_DIR, "labels.csv")
OUTPUT_FILE = os.path.join(BASE_DIR, "graphs.pt")


def main():
    # Load binary-level labels
    binary_labels = {}
    with open(LABEL_FILE, newline="") as f:
        for row in csv.DictReader(f):
            binary_labels[row["filename"]] = int(row["label"])

    binaries = sorted(
        f for f in os.listdir(BIN_DIR)
        if os.path.isfile(os.path.join(BIN_DIR, f)) and f in binary_labels
    )
    print(f"Building graphs for {len(binaries)} labelled binaries...")

    graphs = []
    skipped = 0
    node_counts, edge_counts = [], []

    for i, binary_name in enumerate(binaries, 1):
        path  = os.path.join(BIN_DIR, binary_name)
        label = binary_labels[binary_name]
        print(f"  [{i:4d}/{len(binaries)}] {binary_name}", end="", flush=True)

        g = build_binary_graph(path, label)
        if g is None:
            print(" — skipped")
            skipped += 1
            continue

        graphs.append(g)
        node_counts.append(g.num_nodes)
        edge_counts.append(g.num_edges)
        print(f" — {g.num_nodes} nodes, {g.num_edges} edges, label={label}")

    torch.save(graphs, OUTPUT_FILE)

    vuln  = sum(1 for g in graphs if g.y.item() == 1)
    safe  = len(graphs) - vuln
    print(f"\nSaved {len(graphs)} graphs -> {OUTPUT_FILE}  (skipped {skipped})")
    print(f"  Labels  : {vuln} vulnerable / {safe} safe")
    if node_counts:
        print(f"  Nodes   : avg={sum(node_counts)/len(node_counts):.1f}  "
              f"min={min(node_counts)}  max={max(node_counts)}")
        print(f"  Edges   : avg={sum(edge_counts)/len(edge_counts):.1f}  "
              f"min={min(edge_counts)}  max={max(edge_counts)}")


if __name__ == "__main__":
    main()
