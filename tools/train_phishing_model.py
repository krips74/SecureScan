import os
import json
from pathlib import Path

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
import joblib


ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "dataset_phishing.csv"
MODEL_DIR = ROOT / "models"
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"
METRICS_PATH = MODEL_DIR / "phishing_model_metrics.json"


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH)

    # Basic inspection
    print(f"Loaded dataset: {DATASET_PATH}")
    print(f"Shape: {df.shape}")
    print("Columns:")
    print(df.columns.tolist())

    missing = df.isna().sum().sort_values(ascending=False)
    print("\nMissing values (top 20):")
    print(missing.head(20))

    if "status" not in df.columns:
        raise ValueError("Expected label column 'status' not found")

    y_raw = df["status"].astype(str).str.strip().str.lower()
    label_map = {"phishing": 1, "legitimate": 0}
    if not set(y_raw.unique()).issubset(set(label_map.keys())):
        raise ValueError(f"Unexpected labels in 'status': {sorted(set(y_raw.unique()))}")

    y = y_raw.map(label_map).astype(int)
    print("\nClass distribution (label=1 phishing, 0 legit):")
    print(y.value_counts(dropna=False))

    drop_cols = ["status"]
    if "url" in df.columns:
        drop_cols.append("url")

    X = df.drop(columns=drop_cols)

    # Ensure all feature columns are numeric; coerce if needed
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            X[c] = pd.to_numeric(X[c], errors="coerce")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=400,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
        max_depth=None,
    )

    pipe = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("model", model),
        ]
    )

    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\nEvaluation:")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1-score : {f1:.4f}")
    print("\nConfusion matrix [ [tn, fp], [fn, tp] ]:")
    print(cm)
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, digits=4, zero_division=0))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    artifact = {
        "sklearn_pipeline": pipe,
        "feature_columns": X.columns.tolist(),
        "label_map": label_map,
        "dataset": str(DATASET_PATH),
    }

    joblib.dump(artifact, MODEL_PATH)

    metrics = {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": cm,
        "n_rows": int(df.shape[0]),
        "n_features": int(X.shape[1]),
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved model: {MODEL_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")


if __name__ == "__main__":
    main()
