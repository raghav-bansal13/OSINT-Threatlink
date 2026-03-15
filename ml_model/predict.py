#!/usr/bin/env python3
"""
OSINT-ThreatLink Module 3: Inference CLI
Predicts whether a domain is MALICIOUS or BENIGN from an osint_results JSON.

Usage:
    python ml_model/predict.py <path_to_osint_results.json>
    python ml_model/predict.py data/osint_results_github.com_20251027_163304.json
    python ml_model/predict.py data/osint_results_github.com_20251027_163304.json --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Fix Windows console encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
import config
from ml_model.feature_extractor import extract_from_file

# Optional SHAP
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger("predict")

MODEL_PATH = Path(config.BASE_DIR) / "ml_model" / "xgb_malicious_site_model.pkl"

# ---------------------------------------------------------------------------
# Colour helpers (Windows-safe via colorama if available, else plain text)
# ---------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    RED    = Fore.RED    + Style.BRIGHT
    GREEN  = Fore.GREEN  + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    CYAN   = Fore.CYAN
    RESET  = Style.RESET_ALL
except ImportError:
    RED = GREEN = YELLOW = CYAN = RESET = ""


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def load_model(model_path: Path) -> dict:
    """Load the saved model artifact dict."""
    if not model_path.exists():
        print(f"[ERROR] Model not found at: {model_path}")
        print("        Run first: python ml_model/train_model.py")
        sys.exit(1)
    return joblib.load(model_path)


def predict(osint_json_path: str | Path, model_path: Path = MODEL_PATH, verbose: bool = False) -> dict:
    """
    Run inference on a single osint_results JSON.

    Returns:
        dict with keys: domain, label, confidence, features, shap_top5
    """
    json_path = Path(osint_json_path)
    if not json_path.exists():
        print(f"[ERROR] File not found: {json_path}")
        sys.exit(1)

    # Load model
    artifact      = load_model(model_path)
    model         = artifact["model"]
    feature_names = artifact["feature_names"]
    metrics       = artifact.get("metrics", {})

    # Extract features
    raw_feats = extract_from_file(json_path)

    # Align to training feature order (fill missing with 0)
    row = {f: raw_feats.get(f, 0.0) for f in feature_names}
    X = pd.DataFrame([row])[feature_names]

    # Predict
    label      = int(model.predict(X)[0])
    proba      = float(model.predict_proba(X)[0][1])  # P(malicious)
    confidence = proba if label == 1 else (1.0 - proba)

    # SHAP for top-5 driving features
    shap_top5 = []
    if SHAP_AVAILABLE:
        try:
            explainer   = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X)
            sv = shap_values[1] if isinstance(shap_values, list) else shap_values
            sv = np.array(sv).flatten()
            top_idx  = np.argsort(np.abs(sv))[::-1][:5]
            shap_top5 = [(feature_names[i], float(sv[i])) for i in top_idx]
        except Exception:
            pass

    # Load domain name for display
    try:
        with json_path.open("r", encoding="utf-8") as f:
            domain = json.load(f).get("target", json_path.stem)
    except Exception:
        domain = json_path.stem

    return {
        "domain":     domain,
        "label":      label,
        "confidence": confidence,
        "proba_malicious": proba,
        "features":   row,
        "shap_top5":  shap_top5,
        "model_auc":  metrics.get("auc_roc", "N/A"),
    }


def print_report(result: dict, verbose: bool = False) -> None:
    """Pretty-print the prediction result."""
    label      = result["label"]
    domain     = result["domain"]
    confidence = result["confidence"] * 100
    proba      = result["proba_malicious"] * 100

    verdict_str  = "MALICIOUS" if label == 1 else "BENIGN"
    verdict_clr  = RED if label == 1 else GREEN
    verdict_icon = "[!!!]" if label == 1 else "[OK] "

    print()
    print("=" * 55)
    print(f" {CYAN}OSINT-ThreatLink - Malicious Site Classifier{RESET}")
    print("=" * 55)
    print(f"  Target Domain : {YELLOW}{domain}{RESET}")
    print(f"  Verdict       : {verdict_clr}{verdict_icon}  {verdict_str}{RESET}")
    print(f"  Confidence    : {confidence:.1f}%")
    print(f"  P(malicious)  : {proba:.1f}%")
    print(f"  Model AUC-ROC : {result['model_auc']}")

    if result["shap_top5"]:
        print("\n  Top 5 Contributing Features:")
        for feat, val in result["shap_top5"]:
            direction = "(+risk)" if val > 0 else "(-risk)"
            color     = RED if val > 0 else GREEN
            print(f"    {color}{feat:<35} SHAP={val:+.4f}  {direction}{RESET}")

    if verbose:
        print(f"\n  All Extracted Features:")
        for k, v in sorted(result["features"].items()):
            print(f"    {k:<35} {v:.4f}")

    print(f"{'=' * 55}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Predict malicious/benign from an OSINT results JSON"
    )
    parser.add_argument("json_file", help="Path to osint_results_*.json")
    parser.add_argument(
        "--model", "-m", default=str(MODEL_PATH),
        help="Path to trained model .pkl (default: ml_model/xgb_malicious_site_model.pkl)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print all extracted feature values"
    )
    parser.add_argument(
        "--json-output", "-j", action="store_true",
        help="Output raw JSON result instead of pretty-print"
    )
    args = parser.parse_args()

    result = predict(args.json_file, model_path=Path(args.model), verbose=args.verbose)

    if args.json_output:
        # Strip non-serializable items
        out = {k: v for k, v in result.items() if k != "features" or args.verbose}
        print(json.dumps(out, indent=2))
    else:
        print_report(result, verbose=args.verbose)


if __name__ == "__main__":
    main()
