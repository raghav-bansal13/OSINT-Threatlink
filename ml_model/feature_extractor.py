#!/usr/bin/env python3
"""
OSINT-ThreatLink Module 3: Feature Extractor
Converts a single osint_results_*.json file into a flat numeric feature vector
suitable for XGBoost training / inference.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# TLDs that statistically appear more in malicious / phishing domains
RISKY_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",       # free Freenom TLDs abused heavily
    ".xyz", ".top", ".club", ".online",
    ".site", ".info", ".biz", ".work",
    ".buzz", ".click", ".link", ".live",
    ".loan", ".win", ".bid", ".download",
    ".stream", ".gdn", ".racing", ".date",
}

KNOWN_GOOD_REGISTRARS = {
    "markmonitor", "verisign", "godaddy", "namecheap",
    "network solutions", "register.com", "enom", "cloudflare",
    "amazon registrar", "google domains", "key-systems",
    "fastly", "name.com", "pairnic",
}

HIGH_RISK_KEYWORDS = [
    "vpn", "admin", "root", "backup", "test", "dev", "staging",
    "login", "secure", "portal", "remote", "shell", "phish",
    "update", "verify", "bank", "paypal", "account",
]

RISKY_IP_PATTERN = re.compile(
    r"(^|\.)(\d{1,3}[-._]\d{1,3}[-._]\d{1,3}[-._]\d{1,3})(\.|\.|$)"
)

# ---------------------------------------------------------------------------
# Main Extractor
# ---------------------------------------------------------------------------


class FeatureExtractor:
    """Extract numeric ML features from an OSINT result JSON dict."""

    def __init__(self, osint_data: Dict[str, Any]):
        self.data = osint_data
        self.target: str = osint_data.get("target", "")
        self.features: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self) -> Dict[str, float]:
        """Run all feature groups and return a flat feature dict."""
        self._domain_features()
        self._subdomain_features()
        self._dns_features()
        self._whois_features()
        self._endpoint_features()
        self._email_features()
        self._social_features()
        return self.features

    # ------------------------------------------------------------------
    # Feature groups
    # ------------------------------------------------------------------

    def _domain_features(self) -> None:
        domain = self.target.lower().strip()
        parts = domain.split(".")

        self.features["domain_length"] = float(len(domain))
        self.features["domain_label_count"] = float(len(parts))  # e.g. 3 for sub.example.com
        self.features["has_ip_in_domain"] = float(bool(RISKY_IP_PATTERN.search(domain)))
        self.features["has_hyphen"] = float("-" in domain.replace("-.", "").replace(".-", ""))
        self.features["digit_ratio"] = (
            sum(c.isdigit() for c in domain) / max(len(domain), 1)
        )

        # TLD risk
        tld = "." + parts[-1] if parts else ""
        self.features["tld_is_risky"] = float(tld in RISKY_TLDS)

        # Entropy (high entropy → random-looking domain → risky)
        self.features["domain_entropy"] = _shannon_entropy(parts[0] if parts else "")

        # Risky keywords in the root domain name
        keyword_hits = sum(kw in domain for kw in HIGH_RISK_KEYWORDS)
        self.features["domain_risk_keyword_count"] = float(keyword_hits)

    def _subdomain_features(self) -> None:
        subs: list = self.data.get("subdomains") or []
        self.features["subdomain_count"] = float(len(subs))

        high_risk = 0
        max_depth = 0
        for sub in subs:
            sub_lower = sub.lower()
            hits = sum(kw in sub_lower for kw in HIGH_RISK_KEYWORDS)
            high_risk += min(hits, 1)  # count domains not keyword occurrences

            depth = sub.count(".") - self.target.count(".")
            max_depth = max(max_depth, depth)

        self.features["high_risk_subdomain_count"] = float(high_risk)
        self.features["high_risk_subdomain_ratio"] = (
            high_risk / max(len(subs), 1)
        )
        self.features["max_subdomain_depth"] = float(max_depth)

    def _dns_features(self) -> None:
        dns: dict = self.data.get("dns_records") or {}

        a_records   = dns.get("A")  or []
        mx_records  = dns.get("MX") or []
        ns_records  = dns.get("NS") or []
        txt_records = dns.get("TXT") or []

        self.features["a_record_count"]  = float(len(a_records))
        self.features["mx_record_count"] = float(len(mx_records))
        self.features["ns_record_count"] = float(len(ns_records))
        self.features["txt_record_count"] = float(len(txt_records))

        # SPF / DMARC presence (good indicators of legit domain)
        txt_concat = " ".join(txt_records).lower()
        self.features["has_spf"]   = float("v=spf1" in txt_concat)
        self.features["has_dmarc"] = float("v=dmarc1" in txt_concat)

        # No MX = no legitimate mail setup → slightly suspicious
        self.features["has_mx"] = float(len(mx_records) > 0)

        # Multiple NS in different providers → usually legitimate orgs do this
        self.features["ns_provider_diversity"] = float(
            len({_extract_ns_provider(ns) for ns in ns_records})
        )

    def _whois_features(self) -> None:
        whois: dict = self.data.get("whois_data") or {}

        creation_str    = whois.get("creation_date", "")
        expiration_str  = whois.get("expiration_date", "")
        registrar       = str(whois.get("registrar", "")).lower()
        whois_emails    = whois.get("emails") or []

        now = datetime.now(tz=timezone.utc)

        # Domain age in days
        self.features["domain_age_days"] = _parse_date_delta(creation_str, now, mode="age")

        # Days to expiry — short remaining life is suspicious
        self.features["days_to_expiry"] = _parse_date_delta(expiration_str, now, mode="expiry")

        # Known registrar
        is_known = any(k in registrar for k in KNOWN_GOOD_REGISTRARS)
        self.features["registrar_is_known"] = float(is_known)

        # WHOIS email count (privacy-protected → 0 emails → slightly suspicious)
        self.features["whois_email_count"] = float(len(whois_emails) if isinstance(whois_emails, list) else 0)

    def _endpoint_features(self) -> None:
        endpoints: list = self.data.get("web_endpoints") or []

        if not endpoints:
            self.features.update({
                "endpoint_count": 0.0,
                "pct_200": 0.0,
                "pct_404": 0.0,
                "pct_error": 0.0,
                "avg_content_length": 0.0,
                "has_https": 0.0,
                "has_hsts": 0.0,
                "has_csp": 0.0,
                "has_xframe_options": 0.0,
                "has_xcontent_type": 0.0,
                "tech_count": 0.0,
            })
            return

        count = len(endpoints)
        status_codes  = [ep.get("status_code") or 0 for ep in endpoints]
        content_sizes = [ep.get("content_length") or 0 for ep in endpoints]

        c200  = sum(1 for s in status_codes if s == 200)
        c404  = sum(1 for s in status_codes if s == 404)
        cerr  = sum(1 for s in status_codes if s >= 500)

        self.features["endpoint_count"]      = float(count)
        self.features["pct_200"]             = c200 / count
        self.features["pct_404"]             = c404 / count
        self.features["pct_error"]           = cerr / count
        self.features["avg_content_length"]  = sum(content_sizes) / count

        # Security headers — check across all 200-OK endpoints
        ok_eps = [ep for ep in endpoints if ep.get("status_code") == 200]
        has_https      = any(ep.get("url", "").startswith("https://") for ep in ok_eps)
        has_hsts       = any("strict-transport-security" in _get_headers(ep) for ep in ok_eps)
        has_csp        = any("content-security-policy" in _get_headers(ep) for ep in ok_eps)
        has_xframe     = any("x-frame-options" in _get_headers(ep) for ep in ok_eps)
        has_xct        = any("x-content-type-options" in _get_headers(ep) for ep in ok_eps)

        self.features["has_https"]            = float(has_https)
        self.features["has_hsts"]             = float(has_hsts)
        self.features["has_csp"]              = float(has_csp)
        self.features["has_xframe_options"]   = float(has_xframe)
        self.features["has_xcontent_type"]    = float(has_xct)

        # Technology stack diversity
        all_tech = set()
        for ep in ok_eps:
            all_tech.update(ep.get("technologies") or [])
        self.features["tech_count"] = float(len(all_tech))

    def _email_features(self) -> None:
        emails: list = self.data.get("emails") or []
        self.features["email_count"] = float(len(emails))

        # Check how many email domains don't match the target domain
        mismatch = sum(
            1 for e in emails
            if isinstance(e, str) and "@" in e
            and self.target not in e.split("@")[-1]
        )
        self.features["email_domain_mismatch_count"] = float(mismatch)

    def _social_features(self) -> None:
        profiles: list = self.data.get("social_profiles") or []
        self.features["social_profile_count"] = float(len(profiles))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _extract_ns_provider(ns: str) -> str:
    """Extract the registrar/provider from an NS hostname."""
    ns = ns.lower().rstrip(".")
    parts = ns.split(".")
    # e.g. "ns-421.awsdns-52.com" → "awsdns"
    # heuristic: use second-to-last + last label
    if len(parts) >= 2:
        return parts[-2]
    return ns


def _parse_date_delta(date_val: Any, now: datetime, mode: str = "age") -> float:
    """
    Parse a date string/list into days-since or days-until.
    Returns -1.0 if unparseable (missing WHOIS / privacy protected).
    mode='age'    → days since creation  (negative = future → suspicious)
    mode='expiry' → days until expiry    (negative = already expired)
    """
    if not date_val:
        return -1.0

    # It might be a list (python-whois quirk)
    if isinstance(date_val, list):
        date_val = date_val[0]

    # Already a datetime
    if isinstance(date_val, datetime):
        dt = date_val
    else:
        date_str = str(date_val).strip()
        # Strip timezone offset text like "+00:00"
        date_str = re.sub(r"\+\d{2}:\d{2}$", "", date_str).strip()
        # Try multiple formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
            try:
                dt = datetime.strptime(date_str[:len(fmt) + 2], fmt)
                break
            except ValueError:
                continue
        else:
            return -1.0

    # Make timezone-aware
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    delta = (dt - now).days
    if mode == "age":
        return float(-delta)   # positive = domain is old (good)
    else:  # expiry
        return float(delta)    # positive = expiry is in the future (good)


def _get_headers(endpoint: dict) -> set:
    """Return lowercase set of header names for an endpoint dict."""
    headers = endpoint.get("headers") or {}
    return {k.lower() for k in headers}


# ---------------------------------------------------------------------------
# Convenience loader
# ---------------------------------------------------------------------------

def extract_from_file(json_path: str | Path) -> Dict[str, float]:
    """Load an osint_results JSON file and return feature dict."""
    path = Path(json_path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return FeatureExtractor(data).extract()


def get_feature_names() -> list[str]:
    """Return ordered list of feature names (for consistent DataFrame columns)."""
    # Run a dummy extraction on minimal data to get all column names
    dummy = {"target": "example.com", "subdomains": [], "dns_records": {},
             "whois_data": {}, "web_endpoints": [], "emails": [], "social_profiles": []}
    return sorted(FeatureExtractor(dummy).extract().keys())


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python feature_extractor.py <osint_results.json>")
        sys.exit(1)
    feats = extract_from_file(sys.argv[1])
    print(f"\n{'Feature':<35} Value")
    print("-" * 50)
    for k in sorted(feats):
        print(f"  {k:<33} {feats[k]:.4f}")
    print(f"\nTotal features: {len(feats)}")
