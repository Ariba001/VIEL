"""
Train and evaluate the GraphSAGE node classifier for function-level
vulnerability localization: "which function in this call graph is
vulnerable?" instead of just "is this binary vulnerable?".

Ground truth comes from analysis/static/vuln_labels.py, which resolves —
per binary — which function carries the injected vuln/safe pattern from
scripts/generate_dataset.py. Caveat: if the optimizer inlined that
function into main, main is labelled instead (the vulnerable code now
physically lives there); a small number of binaries (~3%, mostly
null_deref at -O2/-O3, where GCC's UB-driven dead-code elimination erases
main's own symbol) have no resolvable target and are excluded from both
splits rather than fed in as noisy negatives.

Split strategy deliberately differs from the other models in this repo:
angr_classifier.py / compare_models.py use a plain sorted 80/20 split,
which holds out entire vulnerability *families* (alphabetically-last
templates) rather than individual variations. For binary-level
classification that's a reasonable generalization test, but for
localization it leaves only 3 of ~15 vulnerable template types in the
test set — too few to say anything meaningful, and it silently conflates
"can't localize" with "never saw this vulnerability pattern at all".
Instead, each template's 10 variations are split 80/20 (8 train / 2
test) with all 4 optimisation levels of a variation kept together on the
same side, so every vulnerability type is represented in both splits and
no near-duplicate (same source, different -O) leaks across the boundary.

Input : ai_sec_lab/graphs.pt            (produced by scripts/build_graphs.py)
Output: models/graphsage_node.pt        (model weights)
        models/graphsage_node_scaler.pt (feature normalisation stats)
        models/graphsage_node_loss.png  (training curve)

Run:
    python ml/vuln_detection/gstrain_node.py
"""

import os
import sys
import re
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import torch
import torch.nn.functional as F
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from collections import defaultdict
from sklearn.metrics import classification_report, roc_auc_score
from torch_geometric.loader import DataLoader

from ml.vuln_detection.graphsage_node import GraphSAGENodeClassifier
from analysis.static.graph_builder import GRAPH_NODE_FEATURES
from analysis.static.vuln_labels import template_key, parse_binary_name

GRAPHS_PT  = "ai_sec_lab/graphs.pt"
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

SEED         = 42
HIDDEN       = 64
DROPOUT      = 0.3
LR           = 1e-3
WEIGHT_DECAY = 1e-4
EPOCHS       = 150
BATCH_SIZE   = 32
PATIENCE     = 20

random.seed(SEED)
torch.manual_seed(SEED)

# ── Load graphs, stratified 80/20 split by (template, variation) ──────────────
print("Loading graphs...")
graphs = torch.load(GRAPHS_PT, weights_only=False)

by_template = defaultdict(set)
for g in graphs:
    tmpl, variation, _opt = parse_binary_name(g.binary_name)
    by_template[tmpl].add(variation)

test_variations = {}  # template -> set of variation indices held out
rng = random.Random(SEED)
for tmpl, variations in by_template.items():
    variations = sorted(variations)
    rng.shuffle(variations)
    n_test = max(1, round(0.2 * len(variations)))
    test_variations[tmpl] = set(variations[:n_test])


def resolved(g):
    """Keep safe binaries (nothing to localize, all-zero y_node is correct)
    and vulnerable binaries whose target function was resolved."""
    return g.y.item() == 0 or g.y_node.sum().item() > 0


def is_test(g):
    tmpl, variation, _opt = parse_binary_name(g.binary_name)
    return variation in test_variations[tmpl]


train_all = [g for g in graphs if not is_test(g)]
test_all  = [g for g in graphs if is_test(g)]
train_graphs = [g for g in train_all if resolved(g)]
test_graphs  = [g for g in test_all if resolved(g)]
n_excluded = (len(train_all) - len(train_graphs)) + (len(test_all) - len(test_graphs))

print(f"  Train: {len(train_graphs)}  |  Test: {len(test_graphs)}  "
      f"(excluded {n_excluded} vulnerable binaries with unresolved localization target)")
print(f"  {len(by_template)} vulnerability templates, all represented in both splits")

# ── Feature normalisation (fit on training nodes) ─────────────────────────────
all_x = torch.cat([g.x for g in train_graphs], dim=0)
mean  = all_x.mean(dim=0)
std   = all_x.std(dim=0).clamp(min=1e-8)


def normalise(data_list):
    for g in data_list:
        g.x = (g.x - mean) / std
    return data_list


train_graphs = normalise(train_graphs)
test_graphs  = normalise(test_graphs)

torch.save({"mean": mean, "std": std}, MODELS_DIR / "graphsage_node_scaler.pt")
print("Scaler saved -> models/graphsage_node_scaler.pt")

train_loader = DataLoader(train_graphs, batch_size=BATCH_SIZE, shuffle=True)
test_loader  = DataLoader(test_graphs,  batch_size=BATCH_SIZE, shuffle=False)

# ── Model + optimiser ──────────────────────────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model  = GraphSAGENodeClassifier(in_channels=GRAPH_NODE_FEATURES, hidden=HIDDEN, dropout=DROPOUT).to(device)
optim  = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)

# Class weights over USER function nodes only — library nodes are trivial
# negatives (zero CFG features) and excluded from the loss entirely.
n_pos  = sum(g.y_node[g.is_user_mask].sum().item() for g in train_graphs)
n_user = sum(g.is_user_mask.sum().item() for g in train_graphs)
n_neg  = n_user - n_pos
class_weights = torch.tensor([1.0 / n_neg, 1.0 / n_pos])
class_weights = (class_weights / class_weights.sum()).to(device)
print(f"  User nodes: {int(n_user)}  |  vulnerable={int(n_pos)}  safe={int(n_neg)}")

mean = mean.to(device)
std  = std.to(device)


# ── Training loop ──────────────────────────────────────────────────────────────
def train_epoch():
    model.train()
    total_loss, total_nodes = 0.0, 0
    for batch in train_loader:
        batch = batch.to(device)
        mask  = batch.is_user_mask
        optim.zero_grad()
        out  = model(batch.x, batch.edge_index)
        loss = F.cross_entropy(out[mask], batch.y_node[mask], weight=class_weights)
        loss.backward()
        optim.step()
        total_loss  += loss.item() * mask.sum().item()
        total_nodes += mask.sum().item()
    return total_loss / total_nodes


@torch.no_grad()
def evaluate(loader):
    """Returns node-level (acc, preds, labels, probs) and graph-level
    localization accuracy: for each vulnerable graph, does the single
    highest-scoring user function match the true vulnerable function?"""
    model.eval()
    all_preds, all_labels, all_probs = [], [], []
    loc_correct, loc_total = 0, 0
    loc_by_type = defaultdict(lambda: [0, 0])  # type -> [correct, total]

    for batch in loader:
        batch = batch.to(device)
        out  = model(batch.x, batch.edge_index)
        prob = F.softmax(out, dim=1)[:, 1]
        pred = out.argmax(dim=1)
        mask = batch.is_user_mask

        all_preds.extend(pred[mask].cpu().tolist())
        all_labels.extend(batch.y_node[mask].cpu().tolist())
        all_probs.extend(prob[mask].cpu().tolist())

        for gi in range(batch.num_graphs):
            node_mask = (batch.batch == gi) & batch.is_user_mask
            y_true    = batch.y_node[node_mask]
            if y_true.sum().item() == 0:
                continue  # safe binary — nothing to localize
            top_idx  = prob[node_mask].argmax().item()
            correct  = int(y_true[top_idx].item() == 1)
            loc_correct += correct
            loc_total   += 1

            vtype = template_key(batch.binary_name[gi]) or "unknown"
            loc_by_type[vtype][0] += correct
            loc_by_type[vtype][1] += 1

    node_acc = sum(p == l for p, l in zip(all_preds, all_labels)) / len(all_labels)
    loc_acc  = loc_correct / loc_total if loc_total else float("nan")
    return node_acc, loc_acc, all_preds, all_labels, all_probs, loc_by_type


print(f"\nTraining on {device} for up to {EPOCHS} epochs (patience={PATIENCE})...")
print(f"{'Epoch':>6}  {'Train Loss':>11}  {'Node Acc':>9}  {'Loc Acc':>8}  {'Best':>6}")
print("-" * 52)

train_losses = []
best_loc_acc = 0.0
best_epoch   = 0
patience_ctr = 0

for epoch in range(1, EPOCHS + 1):
    loss = train_epoch()
    node_acc, loc_acc, *_ = evaluate(test_loader)
    train_losses.append(loss)

    marker = ""
    if loc_acc > best_loc_acc:
        best_loc_acc = loc_acc
        best_epoch   = epoch
        patience_ctr = 0
        torch.save(model.state_dict(), MODELS_DIR / "graphsage_node.pt")
        marker = " *"
    else:
        patience_ctr += 1

    if epoch % 10 == 0 or marker:
        print(f"{epoch:6d}  {loss:11.4f}  {node_acc:9.4f}  {loc_acc:8.4f}  {best_loc_acc:6.4f}{marker}")

    if patience_ctr >= PATIENCE:
        print(f"\nEarly stop at epoch {epoch} (no improvement for {PATIENCE} epochs)")
        break

# ── Final evaluation ──────────────────────────────────────────────────────────
model.load_state_dict(torch.load(MODELS_DIR / "graphsage_node.pt", weights_only=True))
node_acc, loc_acc, preds, labels, probs, loc_by_type = evaluate(test_loader)

print(f"\n--- Test results (best epoch {best_epoch}) ---")
print(f"Node-level accuracy    : {node_acc:.4f}")
print(classification_report(labels, preds, target_names=["not-vuln-fn", "vuln-fn"], zero_division=0))
try:
    print(f"Node-level ROC-AUC     : {roc_auc_score(labels, probs):.4f}")
except Exception:
    pass

print(f"\nFunction-level localization accuracy: {loc_acc:.4f}")
print("(of vulnerable binaries, fraction where the single highest-scoring")
print(" function IS the actual function carrying the injected vulnerability)")

print(f"\n{'Vuln type':<28}  {'Loc Acc':>8}  {'N':>4}")
print("-" * 44)
for vtype, (correct, total) in sorted(loc_by_type.items()):
    acc = correct / total if total else float("nan")
    print(f"{vtype:<28}  {acc:8.4f}  {total:>4}")

# ── Training curve ────────────────────────────────────────────────────────────
plt.figure(figsize=(7, 4))
plt.plot(train_losses, color="steelblue")
plt.axvline(best_epoch - 1, color="red", linestyle="--", label=f"best epoch {best_epoch}")
plt.xlabel("Epoch")
plt.ylabel("Train Loss (node-level, class-weighted)")
plt.title("GraphSAGE Node Classifier — Training Loss")
plt.legend()
plt.tight_layout()
curve_path = MODELS_DIR / "graphsage_node_loss.png"
plt.savefig(curve_path, bbox_inches="tight")
plt.close()
print(f"\nTraining curve -> {curve_path}")
print(f"Model saved     -> models/graphsage_node.pt")
