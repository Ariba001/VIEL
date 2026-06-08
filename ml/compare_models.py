"""
Cross-model comparison report for VIEL vulnerability detection.

Common hold-out test set: last 20% of sorted binaries from labels.csv (240 bins).

Function-level models (TF-IDF, angr RF, Ghidra RF):
  Trained with function-name labels (1 if "vuln" in name).
  Aggregated to binary level via max-probability across functions.
  NOTE: race and use_after_free binaries have no function named "vuln*"
  (angr couldn't recover debug symbol names for those templates), so
  function-level models cannot learn to detect those vulnerability types.
  This is a dataset labeling limitation, not a model deficiency.

GraphSAGE:
  Trained with binary-level labels from labels.csv (ground-truth correct).
  Evaluated on-the-fly for each test binary (no data leakage from the
  random training split used in gstrain.py).

Outputs:
    models/comparison_metrics.csv
    models/comparison_roc.png
    models/comparison_confusion.png
    models/comparison_by_type.png     F1 per vulnerability type
    models/comparison_by_optlevel.png F1 per optimisation level

Run:
    python ml/compare_models.py
"""

import os
import sys
import re
import csv
import warnings
warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    roc_auc_score, roc_curve, confusion_matrix,
)

MODELS_DIR = Path("models")

# ── Common hold-out test set ──────────────────────────────────────────────────
binary_labels = {}
with open("ai_sec_lab/labels.csv") as f:
    for row in csv.DictReader(f):
        binary_labels[row["filename"]] = int(row["label"])

all_binaries  = sorted(binary_labels.keys())
split         = int(0.8 * len(all_binaries))
test_names    = all_binaries[split:]
test_label_map = {b: binary_labels[b] for b in test_names}

print(f"Hold-out test set : {len(test_names)} binaries")
vuln_n = sum(binary_labels[b] for b in test_names)
print(f"  {vuln_n} vulnerable / {len(test_names)-vuln_n} safe")
print()


def vuln_type(name):
    m = re.match(r"^(.+?)_(safe|vuln)_", name)
    return m.group(1) if m else "unknown"

def opt_level(name):
    m = re.search(r"_O(\d)$", name)
    return f"O{m.group(1)}" if m else "?"


# results[name] = {labels, probs, preds, binary_names}
results = {}


# ── TF-IDF + Logistic Regression ─────────────────────────────────────────────
def eval_tfidf():
    if not (MODELS_DIR / "lr_tfidf.pkl").exists():
        print("  [skip] TF-IDF model not found"); return

    df = pd.read_csv("ai_sec_lab/opcode_dataset_semantic.csv")
    df = df[df["binary"].isin(set(test_names))].copy()
    if df.empty:
        print("  [skip] No TF-IDF test data"); return

    model = joblib.load(MODELS_DIR / "lr_tfidf.pkl")
    vec   = joblib.load(MODELS_DIR / "vectorizer.pkl")
    df["prob_vuln"] = model.predict_proba(vec.transform(df["tokens"].fillna("")))[:, 1]

    agg   = df.groupby("binary")["prob_vuln"].max().reindex(test_names).dropna()
    probs = agg.values.tolist()
    labs  = [binary_labels[b] for b in agg.index]
    preds = [int(p > 0.5) for p in probs]

    results["TF-IDF + LR"] = dict(labels=labs, probs=probs, preds=preds,
                                   binary_names=list(agg.index))
    print(f"  TF-IDF + LR  : {len(labs)} binaries")


# ── angr Random Forest ────────────────────────────────────────────────────────
def eval_angr():
    if not (MODELS_DIR / "angr_rf.pkl").exists():
        print("  [skip] angr RF not found"); return

    df   = pd.read_csv("ai_sec_lab/angr_dataset.csv")
    df   = df[df["binary"].isin(set(test_names))].copy()
    feat = joblib.load(MODELS_DIR / "angr_features.pkl")
    rf   = joblib.load(MODELS_DIR / "angr_rf.pkl")
    df["prob_vuln"] = rf.predict_proba(
        df[feat].apply(pd.to_numeric, errors="coerce").fillna(0).values
    )[:, 1]

    agg   = df.groupby("binary")["prob_vuln"].max().reindex(test_names).dropna()
    probs = agg.values.tolist()
    labs  = [binary_labels[b] for b in agg.index]
    preds = [int(p > 0.5) for p in probs]

    results["angr RF"] = dict(labels=labs, probs=probs, preds=preds,
                               binary_names=list(agg.index))
    print(f"  angr RF      : {len(labs)} binaries")


# ── Ghidra Random Forest ──────────────────────────────────────────────────────
def eval_ghidra():
    report = Path("analysis/autoghidra/analysed_output/report.csv")
    if not (MODELS_DIR / "ghidra_rf.pkl").exists() or not report.exists():
        print("  [skip] Ghidra RF or report.csv missing"); return

    GHIDRA_FEAT = [
        "instructions", "basic_blocks", "edges", "calls", "indirect_calls",
        "jumps", "loops", "mem_reads", "mem_writes", "stack_size",
        "avg_bb_size", "max_bb_size", "call_density", "mem_write_ratio", "jump_density",
    ]
    df  = pd.read_csv(report)
    df  = df[df["binary"].isin(set(test_names))].copy()
    rf  = joblib.load(MODELS_DIR / "ghidra_rf.pkl")
    df["prob_vuln"] = rf.predict_proba(
        df[GHIDRA_FEAT].apply(pd.to_numeric, errors="coerce").fillna(0).values
    )[:, 1]

    agg   = df.groupby("binary")["prob_vuln"].max()
    agg   = agg[agg.index.isin(set(test_names))].reindex(test_names).dropna()
    probs = agg.values.tolist()
    labs  = [binary_labels[b] for b in agg.index]
    preds = [int(p > 0.5) for p in probs]

    results["Ghidra RF"] = dict(labels=labs, probs=probs, preds=preds,
                                 binary_names=list(agg.index))
    print(f"  Ghidra RF    : {len(labs)} binaries (partial coverage)")


# ── GraphSAGE GNN — retrained on the same sorted split ───────────────────────
def eval_graphsage():
    graphs_pt = Path("ai_sec_lab/graphs.pt")
    if not graphs_pt.exists():
        print("  [skip] ai_sec_lab/graphs.pt not found"); return

    import random as _random
    import torch, torch.nn.functional as F
    from torch_geometric.loader import DataLoader as GDataLoader
    from analysis.static.graph_builder import GRAPH_NODE_FEATURES
    from ml.vuln_detection.graphsage import GraphSAGEClassifier

    _SEED, _HIDDEN, _DROPOUT = 42, 64, 0.3
    _LR, _WD, _EPOCHS, _BS, _PAT = 1e-3, 1e-4, 120, 32, 15
    _CACHED = MODELS_DIR / "graphsage_comparison.pt"

    # graphs.pt is built in sorted(binary_labels) order — same order as all_binaries.
    # Use the same 80/20 sorted split as every other eval function.
    all_graphs = torch.load(graphs_pt, weights_only=False)
    train_graphs = list(all_graphs[:split])
    test_graphs  = list(all_graphs[split:])

    # Feature normalisation — fit on training nodes only
    all_x = torch.cat([g.x for g in train_graphs], dim=0)
    mean  = all_x.mean(dim=0)
    std   = all_x.std(dim=0).clamp(min=1e-8)

    def _norm(lst):
        for g in lst:
            g.x = (g.x - mean) / std
        return lst

    if _CACHED.exists():
        print("  [GraphSAGE] using cached comparison weights (models/graphsage_comparison.pt)")
        model = GraphSAGEClassifier(in_channels=GRAPH_NODE_FEATURES, hidden=_HIDDEN, dropout=_DROPOUT)
        model.load_state_dict(torch.load(_CACHED, weights_only=True))
        model.eval()
        test_graphs = _norm(test_graphs)
    else:
        print("  [GraphSAGE] retraining on sorted 80/20 split — may take ~2 min...", flush=True)
        _random.seed(_SEED); torch.manual_seed(_SEED)
        train_graphs = _norm(train_graphs)
        test_graphs  = _norm(test_graphs)

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model  = GraphSAGEClassifier(in_channels=GRAPH_NODE_FEATURES, hidden=_HIDDEN, dropout=_DROPOUT).to(device)
        optim  = torch.optim.Adam(model.parameters(), lr=_LR, weight_decay=_WD)

        n_vuln  = sum(1 for g in train_graphs if g.y.item() == 1)
        n_safe  = len(train_graphs) - n_vuln
        cw = (1.0 / torch.tensor([n_safe, n_vuln], dtype=torch.float))
        cw = (cw / cw.sum()).to(device)

        tr_loader = GDataLoader(train_graphs, batch_size=_BS, shuffle=True)

        best_loss, patience_ctr = float("inf"), 0
        for epoch in range(1, _EPOCHS + 1):
            model.train(); ep_loss = 0.0
            for b in tr_loader:
                b = b.to(device); optim.zero_grad()
                out  = model(b.x, b.edge_index, b.batch)
                loss = F.cross_entropy(out, b.y.view(-1), weight=cw)
                loss.backward(); optim.step()
                ep_loss += loss.item() * b.num_graphs
            ep_loss /= len(tr_loader.dataset)
            if ep_loss < best_loss - 1e-4:
                best_loss = ep_loss; patience_ctr = 0
                torch.save(model.state_dict(), _CACHED)
            else:
                patience_ctr += 1
            if epoch % 20 == 0:
                print(f"    epoch {epoch:3d}  loss={ep_loss:.4f}  best={best_loss:.4f}", flush=True)
            if patience_ctr >= _PAT:
                print(f"    early stop at epoch {epoch}"); break

        model.load_state_dict(torch.load(_CACHED, weights_only=True))
        model.eval()

    ts_loader = GDataLoader(test_graphs, batch_size=_BS, shuffle=False)
    labs, probs, preds = [], [], []
    with torch.no_grad():
        for b in ts_loader:
            out  = model(b.x, b.edge_index, b.batch)
            prob = F.softmax(out, dim=1)
            preds.extend(out.argmax(dim=1).tolist())
            labs.extend(b.y.view(-1).tolist())
            probs.extend(prob[:, 1].tolist())

    results["GraphSAGE"] = dict(labels=labs, probs=probs, preds=preds,
                                 binary_names=test_names[:len(labs)])
    print(f"  GraphSAGE    : {len(labs)} binaries (sorted split, no data leakage)")


# ── Run evaluations ───────────────────────────────────────────────────────────
print("Evaluating models...")
eval_tfidf()
eval_angr()
eval_ghidra()
eval_graphsage()
print()


# ── Compute and print metrics ─────────────────────────────────────────────────
def compute_metrics(r):
    labs, probs, preds = r["labels"], r["probs"], r["preds"]
    return {
        "accuracy":   round(accuracy_score(labs, preds), 4),
        "precision":  round(precision_score(labs, preds, zero_division=0), 4),
        "recall":     round(recall_score(labs, preds, zero_division=0), 4),
        "f1":         round(f1_score(labs, preds, zero_division=0), 4),
        "roc_auc":    round(roc_auc_score(labs, probs), 4),
        "n_binaries": len(labs),
    }

summary = {name: compute_metrics(r) for name, r in results.items()}

print("=" * 72)
print(f"{'Model':<16}  {'Acc':>7}  {'Prec':>7}  {'Rec':>7}  {'F1':>7}  {'AUC':>7}  {'N':>5}")
print("-" * 72)
for name, m in summary.items():
    print(f"{name:<16}  {m['accuracy']:>7.4f}  {m['precision']:>7.4f}  "
          f"{m['recall']:>7.4f}  {m['f1']:>7.4f}  {m['roc_auc']:>7.4f}  "
          f"{m['n_binaries']:>5}")
print("=" * 72)
print()
print("NOTE: race / use_after_free vulnerable functions are named sub_XXXX")
print("      (angr lost debug symbols for those templates), so function-")
print("      level models were never trained to detect them.")
print("      GraphSAGE uses binary-level labels and does not have this gap.")
print()

pd.DataFrame([{"model": k, **v} for k, v in summary.items()]).to_csv(
    MODELS_DIR / "comparison_metrics.csv", index=False)
print("Saved -> models/comparison_metrics.csv")


COLORS = ["#2196F3", "#4CAF50", "#FF9800", "#9C27B0"]

# ── Plot 1: ROC curves ────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 6))
ax.plot([0, 1], [0, 1], "k--", alpha=0.4, label="Random")
for (name, r), color in zip(results.items(), COLORS):
    fpr, tpr, _ = roc_curve(r["labels"], r["probs"])
    auc = summary[name]["roc_auc"]
    ax.plot(fpr, tpr, color=color, lw=2, label=f"{name}  (AUC={auc:.3f})")
ax.set_xlabel("False Positive Rate")
ax.set_ylabel("True Positive Rate")
ax.set_title("ROC Curves — All Models")
ax.legend(loc="lower right")
ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(MODELS_DIR / "comparison_roc.png", dpi=150, bbox_inches="tight")
plt.close()
print("Saved -> models/comparison_roc.png")


# ── Plot 2: Confusion matrices ────────────────────────────────────────────────
n = len(results)
fig, axes = plt.subplots(1, n, figsize=(4 * n, 4))
if n == 1: axes = [axes]
for ax, (name, r), color in zip(axes, results.items(), COLORS):
    cm = confusion_matrix(r["labels"], r["preds"])
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax,
                xticklabels=["safe", "vuln"], yticklabels=["safe", "vuln"],
                cbar=False)
    f1 = summary[name]["f1"]
    ax.set_title(f"{name}\nF1={f1:.3f}", fontsize=10)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
plt.suptitle("Confusion Matrices (binary-level)", fontsize=12, y=1.03)
plt.tight_layout()
plt.savefig(MODELS_DIR / "comparison_confusion.png", dpi=150, bbox_inches="tight")
plt.close()
print("Saved -> models/comparison_confusion.png")


# ── Plot 3: F1 by vulnerability type ─────────────────────────────────────────
test_types = sorted({vuln_type(b) for b in test_names})
model_names = list(results.keys())
f1_grid = np.full((len(test_types), len(model_names)), np.nan)

for j, (name, r) in enumerate(results.items()):
    for i, vtype in enumerate(test_types):
        mask  = [vuln_type(b) == vtype for b in r["binary_names"]]
        labs  = [l for l, m in zip(r["labels"], mask) if m]
        preds = [p for p, m in zip(r["preds"],  mask) if m]
        if len(labs) >= 2 and len(set(labs)) > 1:
            f1_grid[i, j] = f1_score(labs, preds, zero_division=0)

fig, ax = plt.subplots(figsize=(max(8, len(model_names)*2), max(4, len(test_types)*0.6 + 1)))
mask_nan = np.isnan(f1_grid)
sns.heatmap(f1_grid, annot=True, fmt=".2f", cmap="RdYlGn", vmin=0, vmax=1,
            xticklabels=model_names, yticklabels=test_types,
            mask=mask_nan, ax=ax, linewidths=0.5)
ax.set_title("F1 Score per Vulnerability Type")
ax.set_xlabel("Model"); ax.set_ylabel("Vulnerability Type")
plt.xticks(rotation=20, ha="right")
plt.tight_layout()
plt.savefig(MODELS_DIR / "comparison_by_type.png", dpi=150, bbox_inches="tight")
plt.close()
print("Saved -> models/comparison_by_type.png")


# ── Plot 4: F1 by optimisation level ─────────────────────────────────────────
opt_levels = ["O0", "O1", "O2", "O3"]
f1_by_opt = {m: [] for m in model_names}
for opt in opt_levels:
    for name, r in results.items():
        mask  = [opt_level(b) == opt for b in r["binary_names"]]
        labs  = [l for l, m in zip(r["labels"], mask) if m]
        preds = [p for p, m in zip(r["preds"],  mask) if m]
        val = f1_score(labs, preds, zero_division=0) if len(set(labs)) > 1 else float("nan")
        f1_by_opt[name].append(val)

x     = np.arange(len(opt_levels))
width = 0.8 / len(model_names)
fig, ax = plt.subplots(figsize=(9, 5))
for i, (name, color) in enumerate(zip(model_names, COLORS)):
    ax.bar(x + i * width - 0.4 + width / 2, f1_by_opt[name],
           width, label=name, color=color, alpha=0.85)
ax.set_xticks(x); ax.set_xticklabels([f"GCC -{o}" for o in opt_levels])
ax.set_ylabel("F1 Score"); ax.set_ylim(0, 1.05)
ax.set_title("F1 Score by Optimisation Level")
ax.legend(loc="lower left"); ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(MODELS_DIR / "comparison_by_optlevel.png", dpi=150, bbox_inches="tight")
plt.close()
print("Saved -> models/comparison_by_optlevel.png")

print("\nDone.")
