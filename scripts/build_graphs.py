"""
Build binary-level function call graphs for all ELF binaries in a dataset.

Produces <dataset>/graphs.pt — a list of PyTorch Geometric Data objects,
one per binary, with:
    x          : per-function node features  [N, 15]
    edge_index : directed call edges         [2, E]
    y          : binary-level label          [1]
    y_node     : per-function label          [N]

Two datasets are supported:
    synthetic (default) — ai_sec_lab/{binaries,labels.csv,graphs.pt}
    juliet               — ai_sec_lab/juliet/{binaries,labels.csv,graphs.pt}
                            (see scripts/ingest_juliet.py)

Run:
    python scripts/build_graphs.py
    python scripts/build_graphs.py --dataset juliet
"""

import os
import sys
import csv
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch

from analysis.static.graph_builder import build_binary_graph
from analysis.static.vuln_labels import node_labels as synthetic_node_labels
from analysis.static.juliet_labels import node_labels as juliet_node_labels

DATASETS = {
    "synthetic": dict(base="ai_sec_lab", node_label_fn=synthetic_node_labels),
    "juliet":    dict(base=os.path.join("ai_sec_lab", "juliet"), node_label_fn=juliet_node_labels),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", choices=DATASETS, default="synthetic")
    args = ap.parse_args()

    cfg          = DATASETS[args.dataset]
    bin_dir      = os.path.join(cfg["base"], "binaries")
    label_file   = os.path.join(cfg["base"], "labels.csv")
    output_file  = os.path.join(cfg["base"], "graphs.pt")
    node_label_fn = cfg["node_label_fn"]

    binary_labels = {}
    with open(label_file, newline="") as f:
        for row in csv.DictReader(f):
            binary_labels[row["filename"]] = int(row["label"])

    binaries = sorted(
        f for f in os.listdir(bin_dir)
        if os.path.isfile(os.path.join(bin_dir, f)) and f in binary_labels
    )
    print(f"Building graphs for {len(binaries)} labelled binaries ({args.dataset})...")

    graphs = []
    skipped = 0
    node_counts, edge_counts = [], []

    for i, binary_name in enumerate(binaries, 1):
        path  = os.path.join(bin_dir, binary_name)
        label = binary_labels[binary_name]
        print(f"  [{i:4d}/{len(binaries)}] {binary_name}", end="", flush=True)

        g = build_binary_graph(path, label, node_label_fn=node_label_fn)
        if g is None:
            print(" — skipped")
            skipped += 1
            continue

        graphs.append(g)
        node_counts.append(g.num_nodes)
        edge_counts.append(g.num_edges)
        print(f" — {g.num_nodes} nodes, {g.num_edges} edges, label={label}")

    torch.save(graphs, output_file)

    vuln  = sum(1 for g in graphs if g.y.item() == 1)
    safe  = len(graphs) - vuln
    print(f"\nSaved {len(graphs)} graphs -> {output_file}  (skipped {skipped})")
    print(f"  Labels  : {vuln} vulnerable / {safe} safe")
    if node_counts:
        print(f"  Nodes   : avg={sum(node_counts)/len(node_counts):.1f}  "
              f"min={min(node_counts)}  max={max(node_counts)}")
        print(f"  Edges   : avg={sum(edge_counts)/len(edge_counts):.1f}  "
              f"min={min(edge_counts)}  max={max(edge_counts)}")


if __name__ == "__main__":
    main()
