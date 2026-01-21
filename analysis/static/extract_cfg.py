import angr
import networkx as nx
import json
import sys

proj = angr.Project(sys.argv[1], auto_load_libs=False)
cfg = proj.analyses.CFGFast()

edges = []
for src, dst in cfg.graph.edges():
    edges.append({
        "from": hex(src.addr),
        "to": hex(dst.addr)
    })

with open("datasets/raw/cfg.json", "w") as f:
    json.dump(edges, f, indent=2)

print("[+] CFG extracted")
