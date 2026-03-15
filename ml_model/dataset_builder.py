#!/usr/bin/env python3
"""
OSINT-ThreatLink Module 3: Dataset Builder
Builds a labelled training CSV from:
  - Benign (0): existing osint_results_*.json scans in data/
  - Malicious (1): URLhaus public feed + synthetic heuristic samples

Output: data/ml_training_dataset.csv
"""

from __future__ import annotations

import csv
import io
import json
import logging
import math
import random
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

# Add project root to path so we can import sibling modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml_model.feature_extractor import (
    FeatureExtractor,
    HIGH_RISK_KEYWORDS,
    RISKY_TLDS,
    _shannon_entropy,
)
import config

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger("dataset_builder")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MAX_MALICIOUS_FROM_URLHAUS = 2000   # cap so CSV stays manageable
SYNTHETIC_MALICIOUS_COUNT  = 300    # fallback synthetic samples
RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# Benign samples: from real OSINT scans
# ---------------------------------------------------------------------------


def load_benign_samples(data_dir: Path) -> pd.DataFrame:
    """Load all osint_results_*.json in data_dir and extract features (label=0)."""
    rows = []
    json_files = sorted(data_dir.glob("osint_results_*.json"))
    logger.info("[BENIGN] Found %d OSINT result files in %s", len(json_files), data_dir)

    for jf in json_files:
        try:
            with jf.open("r", encoding="utf-8") as f:
                osint_data = json.load(f)
            feats = FeatureExtractor(osint_data).extract()
            feats["label"] = 0
            feats["source"] = "osint_scan"
            feats["domain"] = osint_data.get("target", jf.stem)
            rows.append(feats)
            logger.info("  [OK] %s — %d features", jf.name, len(feats) - 2)
        except Exception as exc:
            logger.warning("  [SKIP] %s: %s", jf.name, exc)

    if not rows:
        logger.warning("[BENIGN] No benign samples loaded — check data/ directory.")
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    logger.info("[BENIGN] Total benign samples: %d", len(df))
    return df


# ---------------------------------------------------------------------------
# Malicious samples: URLhaus feed
# ---------------------------------------------------------------------------

def _derive_features_from_url(url: str) -> Optional[Dict[str, float]]:
    """
    Derive ML features from a raw URL string (no full OSINT scan available).
    Features that require a real scan are imputed with neutral / malicious defaults.
    """
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Extract domain
    m = re.search(r"https?://([^/:?#]+)", url)
    if not m:
        return None
    domain = m.group(1)
    parts = domain.split(".")

    tld = "." + parts[-1] if parts else ""
    first_label = parts[0] if parts else ""

    # ---- features that can be derived from just a URL/domain ----
    feats: Dict[str, float] = {
        # domain group
        "domain_length":            float(len(domain)),
        "domain_label_count":       float(len(parts)),
        "has_ip_in_domain":         float(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain))),
        "has_hyphen":               float("-" in domain),
        "digit_ratio":              sum(c.isdigit() for c in domain) / max(len(domain), 1),
        "tld_is_risky":             float(tld in RISKY_TLDS),
        "domain_entropy":           _shannon_entropy(first_label),
        "domain_risk_keyword_count": float(sum(kw in domain for kw in HIGH_RISK_KEYWORDS)),

        # subdomain group — unknown, set neutral
        "subdomain_count":            0.0,
        "high_risk_subdomain_count":  0.0,
        "high_risk_subdomain_ratio":  0.0,
        "max_subdomain_depth":        0.0,

        # dns group — unknown for malicious, set suspicious defaults
        "a_record_count":    1.0,   # at least one (it resolved)
        "mx_record_count":   0.0,   # malicious sites usually have no MX
        "ns_record_count":   1.0,
        "txt_record_count":  0.0,
        "has_spf":           0.0,
        "has_dmarc":         0.0,
        "has_mx":            0.0,
        "ns_provider_diversity": 1.0,

        # whois — unknown: -1 sentinel
        "domain_age_days":      -1.0,
        "days_to_expiry":       -1.0,
        "registrar_is_known":    0.0,
        "whois_email_count":     0.0,

        # endpoints — unknown, set suspicious
        "endpoint_count":               1.0,
        "pct_200":                      0.5,
        "pct_404":                      0.0,
        "pct_error":                    0.0,
        "avg_content_length":           0.0,
        "has_https":                    float(url.startswith("https")),
        "has_hsts":                     0.0,
        "has_csp":                      0.0,
        "has_xframe_options":           0.0,
        "has_xcontent_type":            0.0,
        "tech_count":                   0.0,

        # email / social — unknown
        "email_count":                  0.0,
        "email_domain_mismatch_count":  0.0,
        "social_profile_count":         0.0,
    }
    return feats


def load_urlhaus_samples(max_samples: int = MAX_MALICIOUS_FROM_URLHAUS) -> pd.DataFrame:
    """Download URLhaus CSV and convert to feature rows (label=1)."""
    logger.info("[URLHAUS] Downloading URLhaus recent feed…")
    try:
        req = urllib.request.Request(
            URLHAUS_CSV_URL,
            headers={"User-Agent": "OSINT-ThreatLink ML Dataset Builder/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        logger.info("[URLHAUS] Download complete (%d bytes)", len(raw))
    except Exception as exc:
        logger.warning("[URLHAUS] Download failed: %s — will use synthetic samples only.", exc)
        return pd.DataFrame()

    # URLhaus CSV has comment lines starting with '#'; skip them
    lines = [line for line in raw.splitlines() if not line.startswith("#") and line.strip()]
    if not lines:
        logger.warning("[URLHAUS] Empty response after stripping comments.")
        return pd.DataFrame()

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows = []
    skipped = 0

    for row in reader:
        url = row.get("url") or row.get("URL") or ""
        if not url:
            skipped += 1
            continue

        feats = _derive_features_from_url(url)
        if feats is None:
            skipped += 1
            continue

        feats["label"]  = 1
        feats["source"] = "urlhaus"
        feats["domain"] = url[:80]
        rows.append(feats)

        if len(rows) >= max_samples:
            break

    logger.info("[URLHAUS] Parsed %d malicious samples (%d skipped)", len(rows), skipped)
    return pd.DataFrame(rows) if rows else pd.DataFrame()


# ---------------------------------------------------------------------------
# Synthetic malicious fallback
# ---------------------------------------------------------------------------

def generate_synthetic_malicious(n: int = SYNTHETIC_MALICIOUS_COUNT) -> pd.DataFrame:
    """
    Generate synthetic malicious-looking feature vectors.
    Used as a fallback if URLhaus is unreachable or as augmentation.
    These are NOT real malicious sites — they are statistically plausible
    feature distributions based on phishing / malware domain research.
    """
    random.seed(RANDOM_SEED)
    rng = random.Random(RANDOM_SEED)

    rows = []
    for i in range(n):
        domain_len = rng.randint(15, 45)
        feats: Dict[str, float] = {
            "domain_length":               float(domain_len),
            "domain_label_count":          float(rng.randint(2, 5)),
            "has_ip_in_domain":            float(rng.random() < 0.25),
            "has_hyphen":                  float(rng.random() < 0.55),
            "digit_ratio":                 rng.uniform(0.05, 0.40),
            "tld_is_risky":                float(rng.random() < 0.65),
            "domain_entropy":              rng.uniform(2.5, 4.5),
            "domain_risk_keyword_count":   float(rng.randint(0, 3)),

            "subdomain_count":             float(rng.randint(0, 3)),
            "high_risk_subdomain_count":   float(rng.randint(0, 2)),
            "high_risk_subdomain_ratio":   rng.uniform(0.0, 0.8),
            "max_subdomain_depth":         float(rng.randint(0, 2)),

            "a_record_count":              float(rng.randint(1, 3)),
            "mx_record_count":             float(rng.randint(0, 1)),
            "ns_record_count":             float(rng.randint(1, 3)),
            "txt_record_count":            float(rng.randint(0, 2)),
            "has_spf":                     float(rng.random() < 0.10),
            "has_dmarc":                   float(rng.random() < 0.05),
            "has_mx":                      float(rng.random() < 0.20),
            "ns_provider_diversity":       float(rng.randint(1, 2)),

            "domain_age_days":             float(rng.randint(-1, 180)),  # very new
            "days_to_expiry":              float(rng.randint(30, 365)),
            "registrar_is_known":          float(rng.random() < 0.15),
            "whois_email_count":           float(rng.randint(0, 1)),

            "endpoint_count":              float(rng.randint(1, 5)),
            "pct_200":                     rng.uniform(0.1, 0.6),
            "pct_404":                     rng.uniform(0.2, 0.7),
            "pct_error":                   rng.uniform(0.0, 0.3),
            "avg_content_length":          float(rng.randint(0, 5000)),
            "has_https":                   float(rng.random() < 0.35),
            "has_hsts":                    float(rng.random() < 0.05),
            "has_csp":                     float(rng.random() < 0.05),
            "has_xframe_options":          float(rng.random() < 0.10),
            "has_xcontent_type":           float(rng.random() < 0.10),
            "tech_count":                  float(rng.randint(0, 2)),

            "email_count":                 float(rng.randint(0, 2)),
            "email_domain_mismatch_count": float(rng.randint(0, 2)),
            "social_profile_count":        float(rng.randint(0, 3)),

            "label":  1,
            "source": "synthetic",
            "domain": f"synthetic_malicious_{i}",
        }
        rows.append(feats)

    logger.info("[SYNTHETIC] Generated %d synthetic malicious samples", n)
    return pd.DataFrame(rows)


def generate_synthetic_benign(n: int = 150) -> pd.DataFrame:
    """
    Generate additional synthetic benign-looking feature vectors to
    balance / augment the small real benign scan set.
    """
    random.seed(RANDOM_SEED + 1)
    rng = random.Random(RANDOM_SEED + 1)

    rows = []
    for i in range(n):
        feats: Dict[str, float] = {
            "domain_length":               float(rng.randint(5, 20)),
            "domain_label_count":          float(rng.randint(2, 3)),
            "has_ip_in_domain":            0.0,
            "has_hyphen":                  float(rng.random() < 0.10),
            "digit_ratio":                 rng.uniform(0.0, 0.05),
            "tld_is_risky":                0.0,
            "domain_entropy":              rng.uniform(1.5, 3.0),
            "domain_risk_keyword_count":   0.0,

            "subdomain_count":             float(rng.randint(5, 100)),
            "high_risk_subdomain_count":   float(rng.randint(0, 3)),
            "high_risk_subdomain_ratio":   rng.uniform(0.0, 0.05),
            "max_subdomain_depth":         float(rng.randint(1, 3)),

            "a_record_count":              float(rng.randint(1, 4)),
            "mx_record_count":             float(rng.randint(2, 8)),
            "ns_record_count":             float(rng.randint(2, 8)),
            "txt_record_count":            float(rng.randint(3, 15)),
            "has_spf":                     1.0,
            "has_dmarc":                   float(rng.random() < 0.70),
            "has_mx":                      1.0,
            "ns_provider_diversity":       float(rng.randint(2, 4)),

            "domain_age_days":             float(rng.randint(365, 10000)),
            "days_to_expiry":              float(rng.randint(90, 3650)),
            "registrar_is_known":          1.0,
            "whois_email_count":           float(rng.randint(1, 4)),

            "endpoint_count":              float(rng.randint(5, 50)),
            "pct_200":                     rng.uniform(0.5, 0.95),
            "pct_404":                     rng.uniform(0.0, 0.20),
            "pct_error":                   rng.uniform(0.0, 0.05),
            "avg_content_length":          float(rng.randint(10000, 500000)),
            "has_https":                   1.0,
            "has_hsts":                    float(rng.random() < 0.85),
            "has_csp":                     float(rng.random() < 0.80),
            "has_xframe_options":          float(rng.random() < 0.90),
            "has_xcontent_type":           float(rng.random() < 0.90),
            "tech_count":                  float(rng.randint(1, 5)),

            "email_count":                 float(rng.randint(0, 5)),
            "email_domain_mismatch_count": float(rng.randint(0, 1)),
            "social_profile_count":        float(rng.randint(2, 20)),

            "label":  0,
            "source": "synthetic_benign",
            "domain": f"synthetic_benign_{i}",
        }
        rows.append(feats)

    logger.info("[SYNTHETIC] Generated %d synthetic benign samples", n)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_dataset(output_path: Optional[Path] = None) -> pd.DataFrame:
    """Assemble the full labelled dataset and save to CSV."""
    output_path = output_path or Path(config.DATA_DIR) / "ml_training_dataset.csv"

    # --- Benign ---
    df_benign_real = load_benign_samples(Path(config.DATA_DIR))
    df_benign_synth = generate_synthetic_benign(n=150)
    df_benign = pd.concat([df_benign_real, df_benign_synth], ignore_index=True)

    # --- Malicious ---
    df_malicious_urlhaus = load_urlhaus_samples()
    if df_malicious_urlhaus.empty:
        logger.info("[BUILDER] URLhaus unavailable — using synthetic malicious only.")
        df_malicious = generate_synthetic_malicious(n=SYNTHETIC_MALICIOUS_COUNT)
    else:
        df_malicious_synth = generate_synthetic_malicious(n=100)  # augment
        df_malicious = pd.concat(
            [df_malicious_urlhaus, df_malicious_synth], ignore_index=True
        )

    # --- Merge ---
    df = pd.concat([df_benign, df_malicious], ignore_index=True)
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    # Ensure all feature columns exist (fill NaN with 0)
    meta_cols = {"label", "source", "domain"}
    feature_cols = [c for c in df.columns if c not in meta_cols]
    df[feature_cols] = df[feature_cols].fillna(0.0)

    # Save
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    logger.info("=" * 60)
    logger.info("[DATASET] Saved %d samples → %s", len(df), output_path)
    logger.info("  Benign   (0): %d", (df["label"] == 0).sum())
    logger.info("  Malicious(1): %d", (df["label"] == 1).sum())
    logger.info("  Features    : %d", len(feature_cols))
    logger.info("=" * 60)
    return df


if __name__ == "__main__":
    build_dataset()
