#!/usr/bin/env python3
"""
OSINT-ThreatLink Module 3: XGBoost Training Pipeline

Trains a binary XGBoost classifier (malicious=1 / benign=0) on the
labelled dataset produced by dataset_builder.py.

Outputs:
  - ml_model/xgb_malicious_site_model.pkl   (trained model + metadata)
  - data/shap_feature_importance.png        (SHAP bar chart)

Usage:
    python ml_model/train_model.py
    python ml_model/train_model.py --dataset data/my_dataset.csv
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")   # headless — no display required
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
import xgboost as xgb

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
import config

# Optional SHAP — skip gracefully if not installed
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger("train_model")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RANDOM_SEED  = 42
TEST_SIZE    = 0.20
META_COLS    = ["label", "source", "domain"]

MODEL_PATH   = Path(config.BASE_DIR) / "ml_model" / "xgb_malicious_site_model.pkl"
SHAP_PLOT    = Path(config.DATA_DIR)  / "shap_feature_importance.png"
METRICS_JSON = Path(config.DATA_DIR)  / "ml_metrics.json"
DATASET_PATH = Path(config.DATA_DIR)  / "ml_training_dataset.csv"

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Load CSV, separate features / labels, return (X, y, feature_names)."""
    logger.info("[LOAD] Reading dataset: %s", path)
    df = pd.read_csv(path)
    logger.info("[LOAD] Shape: %s | Label distribution:\n%s", df.shape, df["label"].value_counts().to_string())

    y = df["label"].astype(int)
    X = df.drop(columns=[c for c in META_COLS if c in df.columns])
    feature_names = list(X.columns)

    # Fill any remaining NaN
    X = X.fillna(0.0)
    return X, y, feature_names


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(X_train, y_train, X_val, y_val) -> xgb.XGBClassifier:
    """Train XGBoost with early stopping on validation AUC."""
    # Handle class imbalance
    neg = (y_train == 0).sum()
    pos = (y_train == 1).sum()
    scale = neg / max(pos, 1)
    logger.info("[TRAIN] scale_pos_weight = %.2f  (neg=%d, pos=%d)", scale, neg, pos)

    model = xgb.XGBClassifier(
        n_estimators          = 500,
        max_depth             = 6,
        learning_rate         = 0.05,
        subsample             = 0.8,
        colsample_bytree      = 0.8,
        scale_pos_weight      = scale,
        eval_metric           = "auc",
        early_stopping_rounds = 30,
        random_state          = RANDOM_SEED,
        verbosity             = 0,
        n_jobs                = -1,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    best = model.best_iteration
    logger.info("[TRAIN] Best iteration: %d", best)
    return model


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(model: xgb.XGBClassifier, X_test, y_test) -> dict:
    """Print and return evaluation metrics."""
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc   = accuracy_score(y_test, y_pred)
    auc   = roc_auc_score(y_test, y_proba)
    cm    = confusion_matrix(y_test, y_pred)
    report= classification_report(y_test, y_pred, target_names=["Benign", "Malicious"])

    logger.info("=" * 60)
    logger.info("TEST SET RESULTS")
    logger.info("=" * 60)
    logger.info("  Accuracy  : %.4f", acc)
    logger.info("  AUC-ROC   : %.4f", auc)
    logger.info("\nClassification Report:\n%s", report)
    logger.info("Confusion Matrix:\n%s", str(cm))
    logger.info("=" * 60)

    return {
        "accuracy": round(acc, 4),
        "auc_roc":  round(auc, 4),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
    }


# ---------------------------------------------------------------------------
# SHAP feature importance
# ---------------------------------------------------------------------------

def plot_shap(model: xgb.XGBClassifier, X_test: pd.DataFrame, save_path: Path) -> None:
    """Generate and save a SHAP summary bar plot."""
    if not SHAP_AVAILABLE:
        logger.warning("[SHAP] shap not installed — skipping SHAP plot.")
        return

    logger.info("[SHAP] Computing SHAP values…")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test)

    # shap_values may be a list [class0, class1] for binary XGBoost
    if isinstance(shap_values, list):
        shap_vals = shap_values[1]
    else:
        shap_vals = shap_values

    mean_abs = np.abs(shap_vals).mean(axis=0)
    feature_names = X_test.columns.tolist()
    importance_df = pd.DataFrame({"feature": feature_names, "importance": mean_abs})
    importance_df = importance_df.sort_values("importance", ascending=True).tail(20)

    fig, ax = plt.subplots(figsize=(9, 7))
    ax.barh(importance_df["feature"], importance_df["importance"], color="#E05A5A")
    ax.set_xlabel("Mean |SHAP value|", fontsize=12)
    ax.set_title("Top 20 Feature Importances (SHAP)", fontsize=14, fontweight="bold")
    ax.tick_params(labelsize=9)
    plt.tight_layout()
    save_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(save_path, dpi=150)
    plt.close(fig)
    logger.info("[SHAP] Plot saved → %s", save_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Train XGBoost malicious site classifier")
    parser.add_argument(
        "--dataset", "-d",
        default=str(DATASET_PATH),
        help="Path to ml_training_dataset.csv (default: data/ml_training_dataset.csv)"
    )
    parser.add_argument(
        "--rebuild-dataset", action="store_true",
        help="Re-run dataset_builder.py before training"
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)

    # Optionally rebuild dataset
    if args.rebuild_dataset or not dataset_path.exists():
        logger.info("[SETUP] Building dataset…")
        from ml_model.dataset_builder import build_dataset
        build_dataset(dataset_path)

    if not dataset_path.exists():
        logger.error("Dataset not found: %s  — run dataset_builder.py first.", dataset_path)
        sys.exit(1)

    # ---- Load ----
    X, y, feature_names = load_dataset(dataset_path)

    # ---- Split: 80% train+val, 20% test ----
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_SEED
    )
    # Inner split: 75% train, 25% val (of train+val)
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=0.20, stratify=y_trainval, random_state=RANDOM_SEED
    )

    logger.info("[SPLIT] Train: %d | Val: %d | Test: %d", len(X_train), len(X_val), len(X_test))

    # ---- Train ----
    model = train(X_train, y_train, X_val, y_val)

    # ---- Evaluate ----
    metrics = evaluate(model, X_test, y_test)

    # ---- SHAP ----
    plot_shap(model, X_test, SHAP_PLOT)

    # ---- Save model + metadata ----
    artifact = {
        "model":         model,
        "feature_names": feature_names,
        "metrics":       metrics,
        "best_iteration": model.best_iteration,
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, MODEL_PATH)
    logger.info("[SAVE] Model saved → %s", MODEL_PATH)

    # Save metrics JSON
    metrics_out = {k: v for k, v in metrics.items() if k != "classification_report"}
    METRICS_JSON.parent.mkdir(parents=True, exist_ok=True)
    with METRICS_JSON.open("w") as f:
        json.dump(metrics_out, f, indent=2)
    logger.info("[SAVE] Metrics saved → %s", METRICS_JSON)

    logger.info("")
    logger.info("✅ Training complete!")
    logger.info("   Model      : %s", MODEL_PATH)
    logger.info("   AUC-ROC    : %.4f", metrics["auc_roc"])
    logger.info("   Accuracy   : %.4f", metrics["accuracy"])
    if SHAP_PLOT.exists():
        logger.info("   SHAP plot  : %s", SHAP_PLOT)


if __name__ == "__main__":
    main()
