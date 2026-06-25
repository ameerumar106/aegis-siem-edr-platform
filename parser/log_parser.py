"""
log_parser.py
Parses raw log lines into structured Python dicts.
Handles original pipe-separated mock telemetry AND real-world Apache Combined Log Formats (DVWA/phpMyAdmin).
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Regex for real-world Apache Combined Log Format
# Matches: IP - - [Timestamp] "METHOD PATH HTTP" STATUS SIZE "REFERER" "USER-AGENT"
APACHE_LOG_PATTERN = r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}) (\S+)'

def parse_line(raw_line):
    """
    Parse a single raw log line into a dict.
    Returns None if the line is invalid/unparseable.
    """
    if not raw_line or not raw_line.strip():
        return None

    raw_line = raw_line.strip()

    # ─────────────────────────────────────────────────────────────────
    # PATH A: HANDLE REAL-WORLD APACHE LOG LINES (DVWA / phpMyAdmin)
    # ─────────────────────────────────────────────────────────────────
    if not raw_line.startswith("20") and '"' in raw_line:  # Detect Apache pattern
        match = re.match(APACHE_LOG_PATTERN, raw_line)
        if not match:
            return None
        
        fields = match.groups()
        raw_ip = fields[0]
        ip = "127.0.0.1" if raw_ip == "::1" else raw_ip  # Normalize IPv6 loopback
        
        timestamp = fields[1]
        method = fields[2]
        url_path = fields[3] if fields[3] else ""
        status_code = fields[5]
        
        # Extract User-Agent from the end of the line if it exists
        user_agent = ""
        ua_match = re.findall(r'"([^"]*)"', raw_line)
        if len(ua_match) >= 2:
            user_agent = ua_match[-1]

        # Calculate a realistic severity score dynamically based on the attack payload
        severity = "LOW"
        url_lower = url_path.lower()
        
        if "script" in url_lower or "union" in url_lower or "select" in url_lower:
            severity = "CRITICAL"  # XSS or SQLi
        elif "win.ini" in url_lower or "shell.php" in url_lower or "cmd=" in url_lower:
            severity = "HIGH"      # Directory Traversal or Web Shell execution
        elif int(status_code) >= 400:
            severity = "MEDIUM"    # Server errors or auth rejections

        # Map directly to your SIEM database schema fields
        return {
            "timestamp": timestamp,
            "source": "webserver",
            "type": f"WEB_{method}",
            "severity": severity,
            "ip": ip,
            "description": f"{method} {url_path} [{status_code}]",
            "user_agent": user_agent
        }

    # ─────────────────────────────────────────────────────────────────
    # PATH B: ORIGINAL PIPE-SEPARATED TELEMETRY HANDLING
    # ─────────────────────────────────────────────────────────────────
    parts = [p.strip() for p in raw_line.split("|")]
    if len(parts) < 3:
        return None

    fields = {}
    try:
        fields["timestamp"] = parts[0].strip()
    except Exception:
        return None

    for part in parts[1:]:
        if "=" in part:
            key, _, value = part.partition("=")
            fields[key.strip().lower()] = value.strip()

    # Validate your dashboard's required database constraints
    required = ["source", "type", "severity"]
    for req in required:
        if req not in fields:
            return None

    return fields


def parse_all(raw_lines):
    """
    Parse a list of raw log lines.
    Returns (parsed_list, failed_count)
    """
    parsed  = []
    failed  = 0

    for line in raw_lines:
        result = parse_line(line)
        if result:
            parsed.append(result)
        else:
            failed += 1

    return parsed, failed


if __name__ == "__main__":
    from collector.log_collector import collect_all_logs

    raw = collect_all_logs()
    parsed, failed = parse_all(raw)

    print(f"\n[+] Parsed:  {len(parsed)}")
    print(f"[!] Failed:  {failed}")
    print("\n── Sample parsed log ──")
    if parsed:
        for k, v in parsed[0].items():
            print(f"   {k:<15}: {v}")