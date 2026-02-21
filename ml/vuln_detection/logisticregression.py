import pandas as pd
import numpy as np
import os
import numpy as np
from collections import Counter
from sklearn.model_selection import train_test_split
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
import matplotlib.pyplot as plt
import seaborn as sns

BASE_DIR = "ai_sec_lab"
DATASET_PATH = os.path.join(BASE_DIR, "opcode_dataset_semantic.csv")

print("Loading dataset...")
df = pd.read_csv(DATASET_PATH)

print("Dataset size:", len(df))
print(df.head())

df = df.dropna()

X = df["tokens"]
y = df["label"].astype(int)

print("\nSplitting dataset...")
df["template"] = df["filename"].apply(lambda x: "_".join(x.split("_")[:-3]))

templates = df["template"].unique()

train_templates = templates[: int(0.8 * len(templates))]
test_templates = templates[int(0.8 * len(templates)) :]

train_df = df[df["template"].isin(train_templates)]
test_df = df[df["template"].isin(test_templates)]

X_train = train_df["tokens"]
y_train = train_df["label"].astype(int)

X_test = test_df["tokens"]
y_test = test_df["label"].astype(int)

print("Train templates:", len(train_templates))
print("Test templates:", len(test_templates))

print("\nApplying TF-IDF...")

vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 3),
    token_pattern=r"\S+"
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print("Feature matrix shape:", X_train_vec.shape)

print("\nTraining Logistic Regression...")

model = LogisticRegression(
    max_iter=1000
)

model.fit(X_train_vec, y_train)

print("\nEvaluating model...")

y_pred = model.predict(X_test_vec)

test_df = test_df.copy()
test_df["pred"] = y_pred

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n===== METRICS =====")
print("Accuracy :", round(acc, 4))
print("Precision:", round(prec, 4))
print("Recall   :", round(recall_score(y_test, y_pred), 4))
print("F1 Score :", round(f1, 4))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

fp = test_df[(test_df["label"] == 0) & (test_df["pred"] == 1)]

fn = test_df[(test_df["label"] == 1) & (test_df["pred"] == 0)]

print("\n========== ERROR ANALYSIS ==========")
print(f"False Positives: {len(fp)}")
print(f"False Negatives: {len(fn)}")

cm = confusion_matrix(y_test, y_pred)

plt.figure()
sns.heatmap(cm, annot=True, fmt="d")
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()

feature_names = vectorizer.get_feature_names_out()
coefficients = model.coef_[0]

top_positive_idx = np.argsort(coefficients)[-20:]
top_negative_idx = np.argsort(coefficients)[:20]

print("\nTop Vulnerability-Indicative Opcodes:")
for idx in reversed(top_positive_idx):
    print(feature_names[idx], "->", round(coefficients[idx], 4))

print("\nTop Safe-Indicative Opcodes:")
for idx in top_negative_idx:
    print(feature_names[idx], "->", round(coefficients[idx], 4))

print("\n--- Performance per Template ---")
template_perf = test_df.groupby("template").apply(
    lambda x: np.mean(x["label"] == x["pred"])
)

print(template_perf.sort_values())

def top_tokens(df_subset, top_n=20):
    tokens = []
    for text in df_subset["tokens"]:
        tokens.extend(text.split())
    return Counter(tokens).most_common(top_n)

print("\n--- Top Tokens in False Positives ---")
print(top_tokens(fp))

print("\n--- Top Tokens in False Negatives ---")
print(top_tokens(fn))