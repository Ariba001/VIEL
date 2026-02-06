import os
import csv
import re
from collections import Counter

IR_DIR = "ir"
CSV_DIR = "csv"
os.makedirs(CSV_DIR, exist_ok=True)

node_writer = csv.writer(open(f"{CSV_DIR}/nodes.csv", "w", newline=""))
edge_writer = csv.writer(open(f"{CSV_DIR}/edges.csv", "w", newline=""))

node_writer.writerow([
    "graph_id", "node_id",
    "num_blocks",
    "num_calls",
    "alloca", "load", "store", "br", "icmp",
    "dangerous_calls",
    "label"
])

edge_writer.writerow(["graph_id", "src", "dst"])

FUNC_RE = re.compile(r"define .* @(\w+)\(")
BLOCK_RE = re.compile(r"^\s*(\w+):")
CALL_RE = re.compile(r"call .* @(\w+)")
INST_RE = re.compile(r"^\s*(\w+)")

DANGEROUS = {"strcpy", "gets", "printf", "scanf", "malloc", "free"}

for label in ["vuln", "safe"]:
    y = 1 if label == "vuln" else 0
    base = os.path.join(IR_DIR, label)

    for fname in os.listdir(base):
        graph_id = fname.replace(".ll", "")
        with open(os.path.join(base, fname)) as f:
            lines = f.readlines()

        current_func = None
        blocks = set()
        insts = Counter()
        calls = []

        for line in lines:
            m = FUNC_RE.search(line)
            if m:
                current_func = m.group(1)
                blocks.clear()
                insts.clear()
                calls.clear()
                continue

            if current_func:
                if BLOCK_RE.match(line):
                    blocks.add(line.strip())

                inst = INST_RE.match(line)
                if inst:
                    insts[inst.group(1)] += 1

                cm = CALL_RE.search(line)
                if cm:
                    calls.append(cm.group(1))

        dangerous_count = sum(insts[d] for d in DANGEROUS if d in insts)

        node_writer.writerow([
            graph_id, current_func,
            len(blocks),
            len(calls),
            insts["alloca"],
            insts["load"],
            insts["store"],
            insts["br"],
            insts["icmp"],
            dangerous_count,
            y
        ])

        for c in calls:
            edge_writer.writerow([graph_id, current_func, c])
