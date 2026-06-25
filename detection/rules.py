"""
rules.py
Detection rules for the SIEM alert engine.
Each rule is a function that takes a list of normalized logs and returns alerts.

Rules implemented:
1. Brute Force Detection     - 5+ failed logins from same IP in 10 mins
2. Account Lockout           - any ACCOUNT_LOCKOUT event
3. Port Scan Detection       - 4+ different ports hit from same IP
4. Web Attack Detection      - any WEB_ATTACK or SUSPICIOUS_REQUEST event
5. Privilege Escalation      - SUDO_CMD or PRIV_LOGON events
6. Critical Event            - any CRITICAL severity log
7. New Service Installed     - SERVICE_INSTALL event on Windows
8. Invalid User Attempts     - 3+ INVALID_USER from same IP
"""

from datetime import datetime, timedelta
from collections import defaultdict


def _parse_ts(ts_str):
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.min


def _make_alert(alert_type, severity, src_ip, description, log_ids):
    sev_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return {
        "timestamp"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type" : alert_type,
        "severity"   : severity,
        "severity_num": sev_map.get(severity, 1),
        "src_ip"     : src_ip,
        "description": description,
        "log_ids"    : ",".join(str(i) for i in log_ids),
    }


# ── Rule 1: Brute Force ───────────────────────────────────────────────────────

def rule_brute_force(logs, threshold=5, window_minutes=10):
    """Detect 5+ failed logins from same IP within 10 minutes."""
    alerts = []
    failed = [l for l in logs if l.get("event_type") == "FAILED_LOGIN"]

    by_ip = defaultdict(list)
    for log in failed:
        by_ip[log["src_ip"]].append(log)

    for ip, ip_logs in by_ip.items():
        if ip == "unknown":
            continue
        ip_logs.sort(key=lambda l: l["timestamp"])
        for i, log in enumerate(ip_logs):
            t_start = _parse_ts(log["timestamp"])
            t_end   = t_start + timedelta(minutes=window_minutes)
            window  = [l for l in ip_logs[i:] if _parse_ts(l["timestamp"]) <= t_end]
            if len(window) >= threshold:
                ids = [l.get("id", 0) for l in window]
                alerts.append(_make_alert(
                    "BRUTE_FORCE", "CRITICAL", ip,
                    f"Brute force detected: {len(window)} failed logins from {ip} within {window_minutes} minutes",
                    ids
                ))
                break  # one alert per IP
    return alerts


# ── Rule 2: Account Lockout ───────────────────────────────────────────────────

def rule_account_lockout(logs):
    """Alert on any account lockout event."""
    alerts = []
    lockouts = [l for l in logs if l.get("event_type") == "ACCOUNT_LOCKOUT"]
    for log in lockouts:
        alerts.append(_make_alert(
            "ACCOUNT_LOCKOUT", "CRITICAL", log.get("src_ip", "unknown"),
            f"Account lockout: user '{log.get('user','unknown')}' locked out. {log.get('message','')}",
            [log.get("id", 0)]
        ))
    return alerts


# ── Rule 3: Port Scan ─────────────────────────────────────────────────────────

def rule_port_scan(logs, port_threshold=4):
    """Detect same IP hitting 4+ different ports (firewall blocks)."""
    alerts = []
    firewall_blocks = [
        l for l in logs
        if l.get("source") == "firewall" and l.get("event_type") == "PORT_SCAN"
    ]

    by_ip = defaultdict(set)
    by_ip_logs = defaultdict(list)
    for log in firewall_blocks:
        ip = log.get("src_ip", "unknown")
        if ip == "unknown":
            continue
        msg = log.get("message", "")
        # extract dst_port from message
        for part in msg.split():
            if ":" in part:
                port = part.split(":")[-1].split(" ")[0].strip("()")
                by_ip[ip].add(port)
        by_ip_logs[ip].append(log)

    for ip, ports in by_ip.items():
        if len(ports) >= port_threshold:
            ids = [l.get("id", 0) for l in by_ip_logs[ip]]
            alerts.append(_make_alert(
                "PORT_SCAN", "HIGH", ip,
                f"Port scan detected from {ip}: hit {len(ports)} ports — {', '.join(list(ports)[:6])}",
                ids
            ))
    return alerts


# ── Rule 4: Web Attack ────────────────────────────────────────────────────────

def rule_web_attack(logs):
    """Alert on WEB_ATTACK or SUSPICIOUS_REQUEST events."""
    alerts = []
    attacks = [
        l for l in logs
        if l.get("event_type") in ("WEB_ATTACK", "SUSPICIOUS_REQUEST")
    ]
    by_ip = defaultdict(list)
    for log in attacks:
        by_ip[log.get("src_ip", "unknown")].append(log)

    for ip, ip_logs in by_ip.items():
        severity = "CRITICAL" if any(l["event_type"] == "WEB_ATTACK" for l in ip_logs) else "HIGH"
        ids = [l.get("id", 0) for l in ip_logs]
        alerts.append(_make_alert(
            "WEB_ATTACK", severity, ip,
            f"Web attack from {ip}: {len(ip_logs)} malicious requests detected (SQL injection / path traversal / scanner)",
            ids
        ))
    return alerts


# ── Rule 5: Privilege Escalation ──────────────────────────────────────────────

def rule_privilege_escalation(logs):
    """Alert on sudo commands and privilege logon events."""
    alerts = []
    priv_events = [
        l for l in logs
        if l.get("event_type") in ("SUDO_CMD", "PRIV_LOGON", "EXPLICIT_CRED")
    ]
    for log in priv_events:
        alerts.append(_make_alert(
            "PRIVILEGE_ESCALATION", "HIGH", log.get("src_ip", "unknown"),
            f"Privilege escalation: {log.get('event_type')} — {log.get('message','')}",
            [log.get("id", 0)]
        ))
    return alerts


# ── Rule 6: Critical Severity Catch-all ───────────────────────────────────────

def rule_critical_events(logs):
    """Alert on any log with CRITICAL severity not already caught."""
    already_caught = {"ACCOUNT_LOCKOUT", "BRUTE_FORCE"}
    alerts = []
    crits = [
        l for l in logs
        if l.get("severity") == "CRITICAL" and l.get("event_type") not in already_caught
    ]
    for log in crits:
        alerts.append(_make_alert(
            "CRITICAL_EVENT", "CRITICAL", log.get("src_ip", "unknown"),
            f"Critical event: {log.get('event_type')} — {log.get('message','')}",
            [log.get("id", 0)]
        ))
    return alerts


# ── Rule 7: New Service Installed ─────────────────────────────────────────────

def rule_new_service(logs):
    """Alert when a new Windows service is installed (common malware persistence)."""
    alerts = []
    services = [l for l in logs if l.get("event_type") == "SERVICE_INSTALL"]
    for log in services:
        alerts.append(_make_alert(
            "NEW_SERVICE_INSTALLED", "HIGH", log.get("src_ip", "unknown"),
            f"New service installed on Windows host: {log.get('message','')}",
            [log.get("id", 0)]
        ))
    return alerts


# ── Rule 8: Invalid User Attempts ────────────────────────────────────────────

def rule_invalid_users(logs, threshold=3):
    """Alert on 3+ invalid user login attempts from same IP."""
    alerts = []
    invalid = [l for l in logs if l.get("event_type") == "INVALID_USER"]
    by_ip = defaultdict(list)
    for log in invalid:
        by_ip[log.get("src_ip", "unknown")].append(log)

    for ip, ip_logs in by_ip.items():
        if ip == "unknown":
            continue
        if len(ip_logs) >= threshold:
            ids = [l.get("id", 0) for l in ip_logs]
            alerts.append(_make_alert(
                "INVALID_USER_ATTEMPTS", "HIGH", ip,
                f"Repeated invalid user attempts from {ip}: {len(ip_logs)} attempts with unknown usernames",
                ids
            ))
    return alerts


# ── All rules registry ────────────────────────────────────────────────────────

ALL_RULES = [
    rule_brute_force,
    rule_account_lockout,
    rule_port_scan,
    rule_web_attack,
    rule_privilege_escalation,
    rule_critical_events,
    rule_new_service,
    rule_invalid_users,
]