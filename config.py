"""
config.py
Centralized configurations for paths, thresholds, and log tracking modes.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────────────────────────
# LOG INGESTION MODE CONFIGURATION
# ─────────────────────────────────────────────────────────────────
# Set to True to read live traffic from your real XAMPP Apache log.
# Set to False to keep running the mock pipeline using fake_log_generator.py.
USE_LIVE_XAMPP = True 

# Paths
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(BASE_DIR, "storage", "siem.db")

# Default simulated output path
FAKE_LOG_OUTPUT = os.path.join(LOG_DIR, "fake_logs.log")

# Your real local XAMPP server access log location
XAMPP_ACCESS_LOG = r"C:\xampp\apache\logs\access.log"

# Select the target active telemetry channel based on the operational toggle
if USE_LIVE_XAMPP:
    # Point the core pipeline directly to your live production web server log
    ACTIVE_LOG_SOURCE = XAMPP_ACCESS_LOG
else:
    # Use the local project log repository
    ACTIVE_LOG_SOURCE = FAKE_LOG_OUTPUT

# Fake log generator settings
FAKE_LOG_COUNT = 200          # How many logs to generate per run

# Log sources (fallback map for structural reference arrays)
LOG_SOURCES = {
    "windows": os.path.join(LOG_DIR, "windows.log"),
    "linux":   os.path.join(LOG_DIR, "linux.log"),
    "firewall": os.path.join(LOG_DIR, "firewall.log"),
    "webserver": ACTIVE_LOG_SOURCE,  # Dynamically routed depending on live toggle state
}

# Severity levels
SEVERITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}