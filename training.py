"""
training.py

Loads a labeled URL dataset, extracts features using
feature_extractor.py (the SAME module used by app.py for live
predictions), trains a Random Forest Classifier, evaluates it, and
saves the trained model to model/phishing_model.pkl.

Usage:
    python training.py

Dataset format:
    A CSV file located at dataset/phishtank_data.csv with at least
    two columns:
        - a URL column, named one of: URL, url
        - a label column, named one of: Label, label
    Label values may be:
        - 1 / 0
        - "phishing" / "safe" (or "legitimate", "good", "bad")
"""

import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from feature_extractor import FEATURE_NAMES, extract_features

RANDOM_STATE = 42
DATASET_PATH = os.path.join("dataset", "phishtank_data.csv")
MODEL_DIR = "model"
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")

# Accepted column name variants.
URL_COLUMN_CANDIDATES = ["URL", "url", "Url"]
LABEL_COLUMN_CANDIDATES = ["Label", "label", "LABEL"]

# Maps text label values to 1 (phishing) / 0 (safe).
LABEL_TEXT_MAP = {
    "phishing": 1,
    "bad": 1,
    "malicious": 1,
    "1": 1,
    "safe": 0,
    "legitimate": 0,
    "good": 0,
    "benign": 0,
    "0": 0,
}


def find_column(df: pd.DataFrame, candidates: list) -> str:
    """Return the first matching column name found in df, else None."""
    for name in candidates:
        if name in df.columns:
            return name
    return None


def load_dataset(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        print(f"ERROR: Dataset not found at '{path}'.")
        print("Please place your CSV file there, or see README.md "
              "for the expected format and a sample dataset.")
        sys.exit(1)

    df = pd.read_csv(path)

    url_col = find_column(df, URL_COLUMN_CANDIDATES)
    label_col = find_column(df, LABEL_COLUMN_CANDIDATES)

    if url_col is None or label_col is None:
        print("ERROR: Could not find required columns in the dataset.")
        print(f"Looked for a URL column in: {URL_COLUMN_CANDIDATES}")
        print(f"Looked for a label column in: {LABEL_COLUMN_CANDIDATES}")
        print(f"Found columns: {list(df.columns)}")
        sys.exit(1)

    df = df[[url_col, label_col]].copy()
    df.columns = ["url", "label"]
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Drop empty rows and normalize the label column to 0/1."""
    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]

    def normalize_label(value):
        text = str(value).strip().lower()
        if text in LABEL_TEXT_MAP:
            return LABEL_TEXT_MAP[text]
        try:
            num = float(text)
            return 1 if num >= 1 else 0
        except ValueError:
            return None

    df["label"] = df["label"].apply(normalize_label)
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    df = df.drop_duplicates(subset=["url"])
    return df.reset_index(drop=True)


def build_feature_matrix(urls: pd.Series) -> np.ndarray:
    rows = []
    total = len(urls)
    for i, url in enumerate(urls):
        rows.append(extract_features(url))
        if (i + 1) % 500 == 0 or (i + 1) == total:
            print(f"  Extracted features for {i + 1}/{total} URLs...")
    return np.array(rows)


def main():
    print("=" * 60)
    print("PhishGuard - Model Training")
    print("=" * 60)

    print(f"\nLoading dataset from '{DATASET_PATH}'...")
    df = load_dataset(DATASET_PATH)
    print(f"Loaded {len(df)} raw rows.")

    print("\nCleaning dataset...")
    df = clean_dataset(df)
    print(f"{len(df)} rows remain after cleaning.")

    if len(df) < 20:
        print("ERROR: Not enough usable data to train a model "
              "(need at least 20 rows). Please provide a larger dataset.")
        sys.exit(1)

    print(f"\nClass balance:\n{df['label'].value_counts().to_string()}")

    print("\nExtracting features (this uses the same logic as live "
          "prediction in app.py)...")
    X = build_feature_matrix(df["url"])
    y = df["label"].values

    print("\nSplitting into train/test sets (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    print(f"  Training samples: {len(X_train)}")
    print(f"  Testing samples:  {len(X_test)}")

    print("\nTraining Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    print("\nEvaluating model on the held-out test set...")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "-" * 60)
    print("EVALUATION RESULTS")
    print("-" * 60)
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print("\nConfusion Matrix:")
    print("                 Predicted Safe   Predicted Phishing")
    print(f"Actual Safe          {cm[0][0]:<15} {cm[0][1]}")
    print(f"Actual Phishing      {cm[1][0]:<15} {cm[1][1]}")
    print("-" * 60)

    print("\nFeature importances:")
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda pair: pair[1],
        reverse=True,
    )
    for name, importance in importances:
        print(f"  {name:<25} {importance:.4f}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to '{MODEL_PATH}'.")
    print("\nDone! You can now run 'python app.py' to start the web app.")


if __name__ == "__main__":
    main()
