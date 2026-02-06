import json
import csv
import os

NODE_CSV = "csv/nodes.csv"
EDGE_CSV = "csv/edges.csv"

os.makedirs("csv", exist_ok=True)

with open(NODE_CSV, "w", newline="") as nf, open(EDGE_CSV, "w", newline="") as ef:
    node_writer = csv.writer(nf)
    edge_writer = csv.writer(ef)

    node_writer.writerow([
        "binary", "node_id", "size", "basic_blocks", "label"
    ])
    edge_writer.writerow([
        "binary", "src", "dst"
    ])

    for binary in os.listdir("ghidra_output"):
        with open(f"ghidra_output/{binary}/functions.json") as f:
            funcs = json.load(f)

        for fdata in funcs:
            node_writer.writerow([
                binary,
                fdata["entry"],
                fdata["size"],
                fdata["basic_blocks"],
                1 if "vuln" in binary else 0
            ])

            for callee in fdata["calls"]:
                edge_writer.writerow([
                    binary,
                    fdata["entry"],
                    callee
                ])
