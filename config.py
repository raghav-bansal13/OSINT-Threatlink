"""
OSINT-ThreatLink Module 1: Configuration
Centralized configuration for all OSINT tools and settings
"""

import os
from pathlib import Path

# ============================================
# PROJECT PATHS
# ============================================
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# Create directories if they don't exist
OUTPUT_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ============================================
# TOOL CONFIGURATIONS
# ============================================

# Subfinder settings
SUBFINDER_CONFIG = {
    "binary_path": "subfinder",  # Assumes subfinder is in PATH
    "output_file": OUTPUT_DIR / "subfinder_results.txt",
    "timeout": 300,  # 5 minutes
    "silent": True
}

# Sherlock settings
SHERLOCK_CONFIG = {
    "output_dir": OUTPUT_DIR / "sherlock",
    "timeout": 60,
    "max_usernames": 10  # Limit to avoid long waits
}

# Holehe settings
HOLEHE_CONFIG = {
    "output_file": OUTPUT_DIR / "holehe_results.txt",
    "timeout": 120
}

# httpx settings
HTTPX_CONFIG = {
    "timeout": 10,
    "follow_redirects": True,
    "max_concurrent": 10  # For async requests
}

# WHOIS settings
WHOIS_CONFIG = {
    "timeout": 30
}

# DNS settings
DNS_CONFIG = {
    "timeout": 5,
    "nameservers": ['8.8.8.8', '8.8.4.4']  # Google DNS
}

# ============================================
# COMMON SUBDOMAIN WORDLIST
# ============================================
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'webmail', 'localhost',
    'dev', 'test', 'staging', 'api', 'beta', 'demo',
    'portal', 'vpn', 'blog', 'shop', 'store', 'news',
    'login', 'dashboard', 'app', 'mobile', 'secure',
    'remote', 'support', 'help', 'status', 'monitor'
]

# ============================================
# OUTPUT SETTINGS
# ============================================
ENABLE_LOGGING = True
LOG_FILE = LOGS_DIR / "orchestrator.log"
VERBOSE = True

# ============================================
# RISK SCORING HEURISTICS (For Module 3)
# ============================================
RISK_KEYWORDS = {
    'subdomains': {
        'high': ['vpn', 'admin', 'root', 'backup', 'test', 'dev', 'staging'],
        'medium': ['portal', 'login', 'secure', 'api', 'remote'],
        'low': ['www', 'blog', 'shop', 'news']
    },
    'breach': {
        'found': 20,  # Add 20 points if email found in breach
        'not_found': 0
    }
}

PARALLEL_CONFIG = {
    "max_phase1_workers": 3,  # Subfinder, DNS, WHOIS
    "max_phase3_workers": 4,  # Holehe + Sherlock
    "enable_parallel": True   # Toggle on/off
}