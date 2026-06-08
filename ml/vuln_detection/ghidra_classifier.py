"""
Train a Random Forest classifier on Ghidra's 17 CFG features.

Input : analysis/autoghidra/analysed_output/report.csv
        ai_sec_lab/labels.csv  (binary-level ground truth)
Output: models/ghidra_rf.pkl  (saved model)
        models/ghidra_feature_importance.png

Labels come from labels.csv (binary-level). Every function row in a
vulnerable binary receives label=1, every function in a safe binary
label=0. This replaces the old function-name heuristic and allows the
model to detect race conditions and use-after-free vulnerabilities.

Run:
    python ml/vuln_detection/ghidra_classifier.py
"""

import os
import csv
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns

REPORT_CSV = "analysis/autoghidra/analysed_output/report.csv"
LABEL_FILE = "ai_sec_lab/labels.csv"
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

FEATURES = [
    "instructions", "basic_blocks", "edges",
    "calls", "indirect_calls", "jumps", "loops",
    "mem_reads", "mem_writes", "stack_size",
    "avg_bb_size", "max_bb_size",
    "call_density", "mem_write_ratio", "jump_density",
]

print("Loading Ghidra report...")
df = pd.read_csv(REPORT_CSV)
print(f"  {len(df)} functions  |  columns: {list(df.columns)}")

# Replace report.csv labels with binary-level ground truth from labels.csv
binary_labels = {}
with open(LABEL_FILE, newline="") as f:
    for row in csv.DictReader(f):
        binary_labels[row["filename"]] = int(row["label"])
df["label"] = df["binary"].map(binary_labels).fillna(0).astype(int)

df[FEATURES] = df[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0)

# Sorted 80/20 split — same split used by compare_models.py
all_binaries = sorted(df["binary"].unique())
split_idx    = int(0.8 * len(all_binaries))
train_bins   = set(all_binaries[:split_idx])
test_bins    = set(all_binaries[split_idx:])

train_df = df[df["binary"].isin(train_bins)]
test_df  = df[df["binary"].isin(test_bins)]

X      = train_df[FEATURES].values
y      = train_df["label"].values
X_test = test_df[FEATURES].values
y_test = test_df["label"].values

print(f"  Train: {len(train_df)} functions ({len(train_bins)} binaries)")
print(f"  Test : {len(test_df)} functions ({len(test_bins)} binaries)")
print(f"  Train label dist: safe={sum(y==0)}, vuln={sum(y==1)}")

# ── 5-fold cross-validation on training set ───────────────────────────────────
print("\nRunning 5-fold cross-validation (train set)...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)

for metric in ("f1", "precision", "recall", "accuracy"):
    scores = cross_val_score(rf, X, y, cv=cv, scoring=metric)
    print(f"  {metric:10s}: {scores.mean():.3f} ± {scores.std():.3f}")

# ── Train on training set and save ───────────────────────────────────────────
print("\nTraining on training set...")
rf.fit(X, y)
joblib.dump(rf,       MODELS_DIR / "ghidra_rf.pkl")
joblib.dump(FEATURES, MODELS_DIR / "ghidra_features.pkl")
print(f"Model saved -> {MODELS_DIR}/ghidra_rf.pkl")

# ── Feature importance ────────────────────────────────────────────────────────
importances = rf.feature_importances_
order = np.argsort(importances)[::-1]

print("\nFeature importances:")
for i in order:
    print(f"  {FEATURES[i]:20s}  {importances[i]:.4f}")

plt.figure(figsize=(8, 5))
plt.barh([FEATURES[i] for i in reversed(order)],
         [importances[i] for i in reversed(order)],
         color="steelblue")
plt.xlabel("Importance")
plt.title("Ghidra RF — Feature Importances")
plt.tight_layout()
fi_path = MODELS_DIR / "ghidra_feature_importance.png"
plt.savefig(fi_path, bbox_inches="tight")
plt.close()
print(f"Feature importance chart saved -> {fi_path}")

# ── Hold-out evaluation ───────────────────────────────────────────────────────
print("\n--- Hold-out evaluation (last 20% of sorted binaries) ---")
y_pred = rf.predict(X_test)
print(classification_report(y_test, y_pred, target_names=["safe", "vuln"], zero_division=0))
