"""
normalizer.py
Takes a parsed log dict and normalizes it into a standard schema.

Standard schema:
{
    timestamp   : str  (YYYY-MM-DD HH:MM:SS)
    source      : str  (windows | linux | firewall | webserver)
    event_type  : str  (FAILED_LOGIN | PORT_SCAN | WEB_ATTACK | ...)
    severity    : str  (LOW | MEDIUM | HIGH | CRITICAL)
    severity_num: int  (1 | 2 | 3 | 4)
    src_ip      : str  (or "unknown")
    dst_ip      : str  (or "unknown")
    user        : str  (or "unknown")
    message     : str  (human-readable summary)
    raw         : str  (original line for reference)
}
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import SEVERITY


def normalize(parsed_dict):
    """
    Normalize a parsed log dict into the standard schema.
    Returns a normalized dict.
    """
    d = parsed_dict

    severity_str = d.get("severity", "LOW").upper()
    severity_num = SEVERITY.get(severity_str, 1)

    # Build human-readable message based on source
    source = d.get("source", "unknown").lower()
    etype  = d.get("type", "UNKNOWN")

    if source == "windows":
        message = _windows_message(d)
    elif source == "linux":
        message = _linux_message(d)
    elif source == "firewall":
        message = _firewall_message(d)
    elif source == "webserver":
        message = _webserver_message(d)
    else:
        message = d.get("msg", "No message")

    normalized = {
        "timestamp"   : d.get("timestamp", "1970-01-01 00:00:00"),
        "source"      : source,
        "event_type"  : etype,
        "severity"    : severity_str,
        "severity_num": severity_num,
        "src_ip"      : d.get("src_ip", "unknown"),
        "dst_ip"      : d.get("dst_ip", "unknown"),
        "user"        : d.get("user", "unknown"),
        "message"     : message,
    }

    return normalized


# ── Per-source message builders ───────────────────────────────────────────────

def _windows_message(d):
    eid   = d.get("event_id", "?")
    etype = d.get("type", "?")
    user  = d.get("user", "unknown")
    ip    = d.get("src_ip", "unknown")
    msg   = d.get("msg", "")
    return f"[EventID {eid}] {etype} — User: {user} from {ip}. {msg}"

def _linux_message(d):
    service = d.get("service", "syslog")
    etype   = d.get("type", "?")
    msg     = d.get("msg", "")
    return f"[{service}] {etype} — {msg}"

def _firewall_message(d):
    action   = d.get("action", "?")
    src_ip   = d.get("src_ip", "?")
    dst_ip   = d.get("dst_ip", "?")
    dst_port = d.get("dst_port", "?")
    proto    = d.get("proto", "?")
    return f"Firewall {action}: {src_ip} → {dst_ip}:{dst_port} ({proto})"

def _webserver_message(d):
    method = d.get("method", "?")
    path   = d.get("path", "?")
    status = d.get("status", "?")
    ip     = d.get("src_ip", "?")
    ua     = d.get("ua", "?")
    return f"{method} {path} [{status}] from {ip} | Agent: {ua}"


def normalize_all(parsed_list):
    """Normalize a list of parsed log dicts."""
    normalized = []
    for item in parsed_list:
        try:
            normalized.append(normalize(item))
        except Exception as e:
            print(f"[!] Normalization error: {e}")
    return normalized


if __name__ == "__main__":
    from collector.log_collector import collect_all_logs
    from parser.log_parser import parse_all

    raw            = collect_all_logs()
    parsed, failed = parse_all(raw)
    normalized     = normalize_all(parsed)

    print(f"\n[+] Normalized: {len(normalized)} logs")
    print("\n── Sample normalized log ──")
    if normalized:
        for k, v in normalized[0].items():
            print(f"   {k:<15}: {v}")