"""
log_collector.py
Reads log files from disk and yields raw log lines.
Supports: fake logs, real Linux syslog, Windows event exports, firewall logs.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import LOG_SOURCES, FAKE_LOG_OUTPUT

def read_log_file(filepath):
    """Read all lines from a log file. Returns list of raw strings."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return []
    with open(filepath, "r", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]
    print(f"[+] Collected {len(lines)} lines from {filepath}")
    return lines

def collect_all_logs():
    """Collect logs from fake log file (Phase 1). Returns list of raw lines."""
    all_logs = []

    # Phase 1: collect from fake log file
    fake_logs = read_log_file(FAKE_LOG_OUTPUT)
    all_logs.extend(fake_logs)

    return all_logs

def tail_log_file(filepath, interval=2):
    """
    Generator: continuously yields new lines added to a file (like `tail -f`).
    Use this in Phase 4 for the live feed feature.
    """
    if not os.path.exists(filepath):
        print(f"[!] File not found for tailing: {filepath}")
        return
    with open(filepath, "r", errors="ignore") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(interval)

if __name__ == "__main__":
    logs = collect_all_logs()
    print(f"\n[+] Total logs collected: {len(logs)}")
    print("\n── Sample (first 5 lines) ──")
    for line in logs[:5]:
        print(" ", line)