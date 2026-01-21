import json
import pandas as pd

FEATURES_FILE = "datasets/processed/features.json"
LABELS_FILE = "datasets/processed/labels.json"
OUTPUT_FILE = "datasets/processed/final_dataset.csv"

with open(FEATURES_FILE) as f:
    features = json.load(f)

with open(LABELS_FILE) as f:
    labels_list = json.load(f)

# 🔥 FIX: convert labels list → dict
labels = {
    f"{item['binary']}:{item['function']}": item["label"]
    for item in labels_list
}

rows = []

for feat in features:
    key = f"{feat['binary']}:{feat['function']}"
    label = labels.get(key, 0)   # default = safe

    rows.append({
        "binary": feat["binary"],
        "function": feat["function"],
        "size": feat["size"],
        "basic_blocks": feat["basic_blocks"],
        "unsafe_call": feat["unsafe_call"],
        "label": label
    })

df = pd.DataFrame(rows)
df.to_csv(OUTPUT_FILE, index=False)

print("[✓] Dataset built")
print(df["label"].value_counts())
