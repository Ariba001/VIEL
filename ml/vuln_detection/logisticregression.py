import os
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")  # non-interactive — save to file instead of opening a window
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

BASE_DIR = "ai_sec_lab"
DATASET_PATH = os.path.join(BASE_DIR, "opcode_dataset_semantic.csv")
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

print("Loading dataset...")
df = pd.read_csv(DATASET_PATH).dropna()
print(f"Dataset size: {len(df)}  |  columns: {list(df.columns)}")

# Support both old format (filename) and new per-function format (binary)
binary_col = "binary" if "binary" in df.columns else "filename"

print("\nSplitting dataset by template...")
df["template"] = df[binary_col].apply(lambda x: "_".join(x.split("_")[:-3]))

templates = df["template"].unique()
train_templates = templates[: int(0.8 * len(templates))]
test_templates  = templates[int(0.8 * len(templates)):]

train_df = df[df["template"].isin(train_templates)]
test_df  = df[df["template"].isin(test_templates)]

X_train, y_train = train_df["tokens"], train_df["label"].astype(int)
X_test,  y_test  = test_df["tokens"],  test_df["label"].astype(int)

print(f"Train: {len(train_df)} rows ({len(train_templates)} templates)")
print(f"Test : {len(test_df)} rows ({len(test_templates)} templates)")
print(f"Train label dist: {dict(y_train.value_counts())}")
print(f"Test  label dist: {dict(y_test.value_counts())}")

print("\nApplying TF-IDF...")
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 3), token_pattern=r"\S+")
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)
print(f"Feature matrix: {X_train_vec.shape}")

print("\nTraining Logistic Regression (class_weight=balanced)...")
model = LogisticRegression(max_iter=1000, class_weight="balanced")
model.fit(X_train_vec, y_train)

# Save model and vectorizer
joblib.dump(model,      MODELS_DIR / "lr_tfidf.pkl")
joblib.dump(vectorizer, MODELS_DIR / "vectorizer.pkl")
print(f"Model saved -> {MODELS_DIR}/lr_tfidf.pkl")
print(f"Vectorizer saved -> {MODELS_DIR}/vectorizer.pkl")

print("\nEvaluating...")
y_pred = model.predict(X_test_vec)
test_df = test_df.copy()
test_df["pred"] = y_pred

print("\n===== METRICS =====")
print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
print(f"Recall   : {recall_score(y_test, y_pred, zero_division=0):.4f}")
print(f"F1 Score : {f1_score(y_test, y_pred, zero_division=0):.4f}")
print()
print(classification_report(y_test, y_pred, zero_division=0))

fp = test_df[(test_df["label"] == 0) & (test_df["pred"] == 1)]
fn = test_df[(test_df["label"] == 1) & (test_df["pred"] == 0)]
print(f"False Positives: {len(fp)}")
print(f"False Negatives: {len(fn)}")

# Confusion matrix — saved to file, never blocks on headless
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Safe", "Vuln"], yticklabels=["Safe", "Vuln"])
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
cm_path = MODELS_DIR / "confusion_matrix.png"
plt.savefig(cm_path, bbox_inches="tight")
plt.close()
print(f"\nConfusion matrix saved -> {cm_path}")

# Top opcode features
feature_names  = vectorizer.get_feature_names_out()
coefficients   = model.coef_[0]
top_pos = np.argsort(coefficients)[-20:]
top_neg = np.argsort(coefficients)[:20]

print("\nTop Vulnerability-Indicative Opcodes:")
for idx in reversed(top_pos):
    print(f"  {feature_names[idx]:40s} {coefficients[idx]:+.4f}")

print("\nTop Safe-Indicative Opcodes:")
for idx in top_neg:
    print(f"  {feature_names[idx]:40s} {coefficients[idx]:+.4f}")

print("\n--- Accuracy per Template ---")
template_perf = test_df.groupby("template").apply(
    lambda x: np.mean(x["label"] == x["pred"]),
    include_groups=False,
)
print(template_perf.sort_values().to_string())


def top_tokens(df_subset, top_n=10):
    tokens = []
    for text in df_subset["tokens"]:
        tokens.extend(str(text).split())
    return Counter(tokens).most_common(top_n)


if len(fn) > 0:
    print("\nTop tokens in False Negatives (missed vulnerabilities):")
    print(top_tokens(fn))
if len(fp) > 0:
    print("\nTop tokens in False Positives (false alarms):")
    print(top_tokens(fp))
