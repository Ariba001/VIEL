import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

DATASET = "datasets/processed/final_dataset.csv"

df = pd.read_csv(DATASET)

X = df[["size", "basic_blocks", "unsafe_call"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

importances = model.feature_importances_
features = X.columns

print("\n=== Feature Importance ===")
for f, imp in zip(features, importances):
    print(f"{f}: {imp:.4f}")

print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred))

print("\n=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))
