"""
fake_log_generator.py
Generates realistic fake security logs simulating:
- Windows Event Logs (failed logins, account lockouts)
- Linux Syslog (SSH attempts, sudo usage)
- Firewall Logs (port scans, blocked IPs)
- Web Server Logs (SQL injection, directory traversal)
"""

import random
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import FAKE_LOG_OUTPUT, FAKE_LOG_COUNT

# ── Fake data pools ──────────────────────────────────────────────────────────

ATTACKER_IPS = [
    "192.168.1.105", "10.0.0.44", "172.16.0.23",
    "45.33.32.156",  "198.51.100.7", "203.0.113.99",
    "185.220.101.45", "91.108.4.10",  "77.88.8.8",
]

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5",     "10.0.0.15",    "10.0.0.25",
]

USERNAMES = ["admin", "root", "administrator", "user1", "guest", "ameer", "test", "oracle"]
SERVICES  = ["sshd", "sudo", "cron", "systemd", "kernel", "auth"]
WEB_PATHS = [
    "/admin", "/login", "/wp-admin", "/.env",
    "/etc/passwd", "/index.php?id=1' OR '1'='1",
    "/../../../etc/shadow", "/shell.php", "/uploads/cmd.php",
    "/api/users", "/dashboard", "/index.html",
]
HTTP_METHODS  = ["GET", "POST", "PUT", "DELETE"]
HTTP_CODES    = [200, 200, 200, 301, 403, 404, 500, 200, 401, 200]
USER_AGENTS   = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "sqlmap/1.7.8",
    "Nikto/2.1.6",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
]
FIREWALL_ACTIONS = ["BLOCK", "ALLOW", "DROP", "REJECT"]
PORTS = [22, 23, 80, 443, 3306, 5432, 8080, 8443, 21, 25, 3389, 445]

# ── Timestamp helper ─────────────────────────────────────────────────────────

def random_timestamp(hours_back=0):
    """Overrides randomized lag delays to supply your exact current clock metrics"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── Individual log generators ────────────────────────────────────────────────

def gen_windows_log():
    event_types = [
        ("4625", "FAILED_LOGIN",   "HIGH",   "An account failed to log on"),
        ("4624", "SUCCESSFUL_LOGIN", "LOW",    "An account was successfully logged on"),
        ("4740", "ACCOUNT_LOCKOUT", "CRITICAL", "A user account was locked out"),
        ("4648", "EXPLICIT_CRED",  "MEDIUM", "Logon attempted using explicit credentials"),
        ("4672", "PRIV_LOGON",     "MEDIUM", "Special privileges assigned to new logon"),
        ("4688", "PROCESS_CREATE", "LOW",    "A new process has been created"),
        ("7045", "SERVICE_INSTALL", "HIGH",   "A new service was installed in the system"),
    ]
    eid, etype, severity, msg = random.choice(event_types)
    ip   = random.choice(ATTACKER_IPS + INTERNAL_IPS)
    user = random.choice(USERNAMES)
    ts   = random_timestamp()
    return (
        f"{ts} | SOURCE=windows | EVENT_ID={eid} | TYPE={etype} | "
        f"SEVERITY={severity} | SRC_IP={ip} | USER={user} | MSG={msg}"
    )

def gen_linux_log():
    event_types = [
        ("SSH_FAILED",    "HIGH",   lambda: f"Failed password for {random.choice(USERNAMES)} from {random.choice(ATTACKER_IPS)} port {random.randint(1024,65535)} ssh2"),
        ("SSH_SUCCESS",   "LOW",    lambda: f"Accepted password for {random.choice(USERNAMES)} from {random.choice(INTERNAL_IPS)} port {random.randint(1024,65535)} ssh2"),
        ("SUDO_CMD",      "MEDIUM", lambda: f"{random.choice(USERNAMES)} : TTY=pts/0 ; PWD=/home/{random.choice(USERNAMES)} ; USER=root ; COMMAND=/bin/bash"),
        ("INVALID_USER",  "HIGH",   lambda: f"Invalid user {random.choice(USERNAMES)} from {random.choice(ATTACKER_IPS)}"),
        ("BRUTE_FORCE",   "CRITICAL", lambda: f"message repeated 10 times: Failed password for {random.choice(USERNAMES)} from {random.choice(ATTACKER_IPS)}"),
        ("CRON_JOB",      "LOW",    lambda: f"(root) CMD (/usr/lib/update-notifier/apt-check)"),
    ]
    etype, severity, msg_fn = random.choice(event_types)
    service = random.choice(SERVICES)
    ts = random_timestamp()
    return (
        f"{ts} | SOURCE=linux | SERVICE={service} | TYPE={etype} | "
        f"SEVERITY={severity} | MSG={msg_fn()}"
    )

def gen_firewall_log():
    action   = random.choice(FIREWALL_ACTIONS)
    src_ip   = random.choice(ATTACKER_IPS + INTERNAL_IPS)
    dst_ip   = random.choice(INTERNAL_IPS)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice(PORTS)
    protocol = random.choice(["TCP", "UDP", "ICMP"])
    severity = "HIGH" if action in ("BLOCK", "DROP", "REJECT") else "LOW"

    # Detect port scan pattern
    etype = "PORT_SCAN" if dst_port in [22, 23, 3389, 445] and action == "BLOCK" else "FIREWALL_EVENT"
    ts = random_timestamp()
    return (
        f"{ts} | SOURCE=firewall | TYPE={etype} | SEVERITY={severity} | "
        f"ACTION={action} | SRC_IP={src_ip} | DST_IP={dst_ip} | "
        f"SRC_PORT={src_port} | DST_PORT={dst_port} | PROTO={protocol}"
    )

def gen_webserver_log():
    ip     = random.choice(ATTACKER_IPS + INTERNAL_IPS)
    method = random.choice(HTTP_METHODS)
    path   = random.choice(WEB_PATHS)
    code   = random.choice(HTTP_CODES)
    ua     = random.choice(USER_AGENTS)
    size   = random.randint(200, 9999)

    # Detect attack patterns
    suspicious_paths  = ["passwd", "shadow", "OR '1'='1", ".php", "../../"]
    suspicious_agents = ["sqlmap", "Nikto", "curl", "python-requests"]
    is_attack_path  = any(s in path for s in suspicious_paths)
    is_attack_agent = any(s in ua   for s in suspicious_agents)

    if is_attack_agent and is_attack_path:
        etype, severity = "WEB_ATTACK", "CRITICAL"
    elif is_attack_agent or is_attack_path:
        etype, severity = "SUSPICIOUS_REQUEST", "HIGH"
    elif code in [401, 403]:
        etype, severity = "ACCESS_DENIED", "MEDIUM"
    else:
        etype, severity = "WEB_ACCESS", "LOW"

    ts = random_timestamp()
    return (
        f"{ts} | SOURCE=webserver | TYPE={etype} | SEVERITY={severity} | "
        f"SRC_IP={ip} | METHOD={method} | PATH={path} | "
        f"STATUS={code} | SIZE={size} | UA={ua}"
    )

# ── Main generator ───────────────────────────────────────────────────────────

def generate_logs(count=FAKE_LOG_COUNT, output_file=FAKE_LOG_OUTPUT):
    generators = [
        gen_windows_log,
        gen_linux_log,
        gen_firewall_log,
        gen_webserver_log,
    ]

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    logs = []

    for _ in range(count):
        fn  = random.choice(generators)
        log = fn()
        logs.append(log)

    # Sort by timestamp so logs are chronological
    logs.sort()

    with open(output_file, "w") as f:
        for log in logs:
            f.write(log + "\n")

    print(f"[+] Generated {count} fake logs → {output_file}")

    # Print summary
    sources = {"windows": 0, "linux": 0, "firewall": 0, "webserver": 0}
    severities = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for log in logs:
        for src in sources:
            if f"SOURCE={src}" in log:
                sources[src] += 1
        for sev in severities:
            if f"SEVERITY={sev}" in log:
                severities[sev] += 1

    print("\n── Source breakdown ──")
    for src, cnt in sources.items():
        print(f"   {src:<12}: {cnt}")
    print("\n── Severity breakdown ──")
    for sev, cnt in severities.items():
        print(f"   {sev:<10}: {cnt}")

    return logs

if __name__ == "__main__":
    generate_logs()