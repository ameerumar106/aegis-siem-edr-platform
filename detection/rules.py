"""
rules.py
Real-Time Detection rules for the Aegis SIEM correlation engine.
Each function evaluates a live incoming log against its context history.
"""

from datetime import datetime, timedelta

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
        "status"     : "OPEN"
    }

# ── Real-Time Rule 1: Brute Force ─────────────────────────────────────────────

def evaluate_brute_force(current_log, recent_ip_history, threshold=5, window_minutes=10):
    """Evaluates if the incoming login failure pushes the IP past the threshold limits."""
    if current_log.get("event_type") != "FAILED_LOGIN" or current_log.get("src_ip") == "unknown":
        return None

    # Filter out historical failed logins from the sliding time boundary window
    t_current = _parse_ts(current_log["timestamp"])
    t_boundary = t_current - timedelta(minutes=window_minutes)
    
    window_logs = [
        l for l in recent_ip_history 
        if l.get("event_type") == "FAILED_LOGIN" and _parse_ts(l["timestamp"]) >= t_boundary
    ]
    
    # Include current log in the evaluation array context
    window_logs.append(current_log)

    if len(window_logs) >= threshold:
        ids = [l.get("id", 0) for l in window_logs]
        return _make_alert(
            "BRUTE_FORCE", "CRITICAL", current_log["src_ip"],
            f"Real-time Brute Force: {len(window_logs)} failed logins from {current_log['src_ip']} within {window_minutes} minutes",
            ids
        )
    return None

# ── Real-Time Rule 2: Account Lockout ─────────────────────────────────────────

def evaluate_account_lockout(current_log, recent_ip_history=None):
    """Triggers an alert immediately on any streaming account lockout entry."""
    if current_log.get("event_type") == "ACCOUNT_LOCKOUT":
        return _make_alert(
            "ACCOUNT_LOCKOUT", "CRITICAL", current_log.get("src_ip", "unknown"),
            f"Account Lockout: user '{current_log.get('user','unknown')}' locked out. {current_log.get('message','')}",
            [current_log.get("id", 0)]
        )
    return None

# ── Real-Time Rule 3: Port Scan ───────────────────────────────────────────────

def evaluate_port_scan(current_log, recent_ip_history, port_threshold=4, window_minutes=5):
    """Tracks if an IP address scans multiple discrete destination target ports."""
    # Process if the log is a firewall block or network discovery probe
    if current_log.get("event_type") != "PORT_SCAN" and current_log.get("source") != "firewall":
        return None
        
    if current_log.get("src_ip") == "unknown" or current_log.get("dst_port") is None:
        return None

    t_current = _parse_ts(current_log["timestamp"])
    t_boundary = t_current - timedelta(minutes=window_minutes)

    # Gather historical target destination ports within our timeline window
    unique_ports = {current_log["dst_port"]}
    involved_logs = [current_log]

    for l in recent_ip_history:
        if _parse_ts(l["timestamp"]) >= t_boundary and l.get("dst_port") is not None:
            unique_ports.add(l["dst_port"])
            involved_logs.append(l)

    if len(unique_ports) >= port_threshold:
        ids = [l.get("id", 0) for l in involved_logs]
        return _make_alert(
            "PORT_SCAN", "HIGH", current_log["src_ip"],
            f"Real-time Port Scan: {current_log['src_ip']} probed {len(unique_ports)} distinct ports over {window_minutes}m.",
            ids
        )
    return None

# ── Real-Time Rule 4: Web Attack ──────────────────────────────────────────────

def evaluate_web_attack(current_log, recent_ip_history=None):
    """Fires instantly on explicit SQLi, XSS, Path Traversal payload matches."""
    etype = current_log.get("event_type", "")
    if etype in ("WEB_ATTACK", "SUSPICIOUS_REQUEST") or etype.startswith("WEB_"):
        severity = "CRITICAL" if current_log.get("severity") == "CRITICAL" or "ATTACK" in etype else "HIGH"
        return _make_alert(
            "WEB_ATTACK", severity, current_log.get("src_ip", "unknown"),
            f"Web Attack Vector Isolated: {current_log.get('message','')}",
            [current_log.get("id", 0)]
        )
    return None

# ── Real-Time Rule 5: Privilege Escalation ────────────────────────────────────

def evaluate_privilege_escalation(current_log, recent_ip_history=None):
    if current_log.get("event_type") in ("SUDO_CMD", "PRIV_LOGON", "EXPLICIT_CRED"):
        return _make_alert(
            "PRIVILEGE_ESCALATION", "HIGH", current_log.get("src_ip", "unknown"),
            f"Privilege Escalation Activity: Type {current_log.get('event_type')} — {current_log.get('message','')}",
            [current_log.get("id", 0)]
        )
    return None

# ── Real-Time Rule 6: Critical Catch-All ──────────────────────────────────────

def evaluate_critical_events(current_log, recent_ip_history=None):
    already_caught = {"ACCOUNT_LOCKOUT", "BRUTE_FORCE", "WEB_ATTACK"}
    if current_log.get("severity") == "CRITICAL" and current_log.get("event_type") not in already_caught:
        return _make_alert(
            "CRITICAL_EVENT", "CRITICAL", current_log.get("src_ip", "unknown"),
            f"Uncategorized Critical Baseline Exception: {current_log.get('message','')}",
            [current_log.get("id", 0)]
        )
    return None

# ── Real-Time Rule 7: New Windows Service ─────────────────────────────────────

def evaluate_new_service(current_log, recent_ip_history=None):
    if current_log.get("event_type") == "SERVICE_INSTALL":
        return _make_alert(
            "NEW_SERVICE_INSTALLED", "HIGH", current_log.get("src_ip", "unknown"),
            f"Persistence Vector Spotted: New Windows Service Installation — {current_log.get('message','')}",
            [current_log.get("id", 0)]
        )
    return None

# ── Real-Time Rule 8: Invalid User Attempts ───────────────────────────────────

def evaluate_invalid_users(current_log, recent_ip_history, threshold=3, window_minutes=10):
    if current_log.get("event_type") != "INVALID_USER" or current_log.get("src_ip") == "unknown":
        return None

    t_current = _parse_ts(current_log["timestamp"])
    t_boundary = t_current - timedelta(minutes=window_minutes)

    window_logs = [
        l for l in recent_ip_history 
        if l.get("event_type") == "INVALID_USER" and _parse_ts(l["timestamp"]) >= t_boundary
    ]
    window_logs.append(current_log)

    if len(window_logs) >= threshold:
        ids = [l.get("id", 0) for l in window_logs]
        return _make_alert(
            "INVALID_USER_ATTEMPTS", "HIGH", current_log["src_ip"],
            f"Suspicious Auth Activity: {len(window_logs)} invalid target user login attempts from {current_log['src_ip']}",
            ids
        )
    return None

# ── Real-time Registry Hook ───────────────────────────────────────────────────

REALTIME_RULES = [
    evaluate_brute_force,
    evaluate_account_lockout,
    evaluate_port_scan,
    evaluate_web_attack,
    evaluate_privilege_escalation,
    evaluate_critical_events,
    evaluate_new_service,
    evaluate_invalid_users,
]