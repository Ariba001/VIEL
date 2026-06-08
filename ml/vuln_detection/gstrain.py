"""
Train and evaluate the GraphSAGE binary vulnerability classifier.

Input : ai_sec_lab/graphs.pt        (produced by scripts/build_graphs.py)
Output: models/graphsage.pt         (model weights)
        models/graphsage_scaler.pt  (feature normalisation stats)
        models/graphsage_loss.png   (training curve)

Run:
    python ml/vuln_detection/gstrain.py
"""

import os
import sys
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import torch
import torch.nn.functional as F
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import classification_report, roc_auc_score
from torch_geometric.loader import DataLoader

from ml.vuln_detection.graphsage import GraphSAGEClassifier
from analysis.static.angr_engine import FEATURES

GRAPHS_PT  = "ai_sec_lab/graphs.pt"
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

SEED        = 42
HIDDEN      = 64
DROPOUT     = 0.3
LR          = 1e-3
WEIGHT_DECAY = 1e-4
EPOCHS      = 120
BATCH_SIZE  = 32
PATIENCE    = 15

random.seed(SEED)
torch.manual_seed(SEED)

# ── Load graphs ───────────────────────────────────────────────────────────────
print("Loading graphs...")
graphs = torch.load(GRAPHS_PT, weights_only=False)
print(f"  {len(graphs)} graphs  |  features: {len(FEATURES)}")

vuln = sum(1 for g in graphs if g.y.item() == 1)
safe = len(graphs) - vuln
print(f"  Labels: {vuln} vulnerable / {safe} safe")

# ── Train / test split (80/20, stratified by label) ───────────────────────────
vuln_graphs = [g for g in graphs if g.y.item() == 1]
safe_graphs = [g for g in graphs if g.y.item() == 0]
random.shuffle(vuln_graphs)
random.shuffle(safe_graphs)

v_split = int(0.8 * len(vuln_graphs))
s_split = int(0.8 * len(safe_graphs))
train_graphs = vuln_graphs[:v_split] + safe_graphs[:s_split]
test_graphs  = vuln_graphs[v_split:] + safe_graphs[s_split:]
random.shuffle(train_graphs)

print(f"  Train: {len(train_graphs)}  |  Test: {len(test_graphs)}")

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

torch.save({"mean": mean, "std": std}, MODELS_DIR / "graphsage_scaler.pt")
print("Scaler saved -> models/graphsage_scaler.pt")

# ── Data loaders ──────────────────────────────────────────────────────────────
train_loader = DataLoader(train_graphs, batch_size=BATCH_SIZE, shuffle=True)
test_loader  = DataLoader(test_graphs,  batch_size=BATCH_SIZE, shuffle=False)

# ── Model + optimiser ─────────────────────────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model  = GraphSAGEClassifier(in_channels=len(FEATURES), hidden=HIDDEN, dropout=DROPOUT).to(device)
optim  = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)

# Class weights to handle imbalance
class_counts = torch.tensor([safe, vuln], dtype=torch.float)
class_weights = (1.0 / class_counts) / (1.0 / class_counts).sum()
class_weights = class_weights.to(device)

mean   = mean.to(device)
std    = std.to(device)

# ── Training loop ─────────────────────────────────────────────────────────────
def train_epoch():
    model.train()
    total_loss = 0.0
    for batch in train_loader:
        batch = batch.to(device)
        optim.zero_grad()
        out  = model(batch.x, batch.edge_index, batch.batch)
        loss = F.cross_entropy(out, batch.y.view(-1), weight=class_weights)
        loss.backward()
        optim.step()
        total_loss += loss.item() * batch.num_graphs
    return total_loss / len(train_loader.dataset)


@torch.no_grad()
def evaluate(loader):
    model.eval()
    all_preds, all_labels, all_probs = [], [], []
    for batch in loader:
        batch = batch.to(device)
        out   = model(batch.x, batch.edge_index, batch.batch)
        prob  = F.softmax(out, dim=1)
        pred  = out.argmax(dim=1)
        all_preds.extend(pred.cpu().tolist())
        all_labels.extend(batch.y.view(-1).cpu().tolist())
        all_probs.extend(prob[:, 1].cpu().tolist())
    correct = sum(p == l for p, l in zip(all_preds, all_labels))
    acc = correct / len(all_labels)
    return acc, all_preds, all_labels, all_probs


print(f"\nTraining on {device} for up to {EPOCHS} epochs (patience={PATIENCE})...")
print(f"{'Epoch':>6}  {'Train Loss':>11}  {'Val Acc':>8}  {'Best':>6}")
print("-" * 42)

train_losses = []
best_acc     = 0.0
best_epoch   = 0
patience_ctr = 0

for epoch in range(1, EPOCHS + 1):
    loss = train_epoch()
    acc, _, _, _ = evaluate(test_loader)
    train_losses.append(loss)

    marker = ""
    if acc > best_acc:
        best_acc   = acc
        best_epoch = epoch
        patience_ctr = 0
        torch.save(model.state_dict(), MODELS_DIR / "graphsage.pt")
        marker = " *"
    else:
        patience_ctr += 1

    if epoch % 10 == 0 or patience_ctr == 0:
        print(f"{epoch:6d}  {loss:11.4f}  {acc:8.4f}  {best_acc:6.4f}{marker}")

    if patience_ctr >= PATIENCE:
        print(f"\nEarly stop at epoch {epoch} (no improvement for {PATIENCE} epochs)")
        break

# ── Final evaluation ──────────────────────────────────────────────────────────
model.load_state_dict(torch.load(MODELS_DIR / "graphsage.pt", weights_only=True))
_, preds, labels, probs = evaluate(test_loader)

print(f"\n--- Test results (best epoch {best_epoch}, acc={best_acc:.4f}) ---")
print(classification_report(labels, preds, target_names=["safe", "vuln"], zero_division=0))
try:
    auc = roc_auc_score(labels, probs)
    print(f"ROC-AUC: {auc:.4f}")
except Exception:
    pass

# ── Training curve ────────────────────────────────────────────────────────────
plt.figure(figsize=(7, 4))
plt.plot(train_losses, color="steelblue")
plt.axvline(best_epoch - 1, color="red", linestyle="--", label=f"best epoch {best_epoch}")
plt.xlabel("Epoch")
plt.ylabel("Train Loss")
plt.title("GraphSAGE — Training Loss")
plt.legend()
plt.tight_layout()
curve_path = MODELS_DIR / "graphsage_loss.png"
plt.savefig(curve_path, bbox_inches="tight")
plt.close()
print(f"Training curve -> {curve_path}")
print(f"Model saved     -> models/graphsage.pt")
