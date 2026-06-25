"""
alert_engine.py
Runs all detection rules against logs from the database.
Saves generated alerts back to the database.
Prints a detailed report.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from storage.database import get_all_logs, insert_alert, get_all_alerts
from detection.rules  import ALL_RULES


def run_detection(verbose=True):
    """
    Pull all logs from DB, run every rule, save alerts, print report.
    Returns list of generated alert dicts.
    """
    logs = get_all_logs(limit=10000)

    if not logs:
        print("[!] No logs found in database. Run the pipeline first.")
        return []

    if verbose:
        print(f"[+] Running detection on {len(logs)} logs...")
        print(f"[+] Rules loaded: {len(ALL_RULES)}\n")

    all_alerts = []

    for rule_fn in ALL_RULES:
        rule_name = rule_fn.__name__.replace("rule_", "").upper()
        try:
            alerts = rule_fn(logs)
            all_alerts.extend(alerts)
            if verbose:
                status = f"  [{len(alerts):>2} alerts]" if alerts else "  [     clean]"
                print(f"  {rule_name:<30} {status}")
        except Exception as e:
            print(f"  [!] Rule {rule_name} failed: {e}")

    # Save to DB
    saved = 0
    for alert in all_alerts:
        try:
            insert_alert(alert)
            saved += 1
        except Exception as e:
            print(f"[!] Failed to save alert: {e}")

    if verbose:
        _print_report(all_alerts)

    return all_alerts


def _print_report(alerts):
    if not alerts:
        print("\n[+] No alerts generated. System looks clean.")
        return

    print(f"\n{'='*55}")
    print(f"  ALERT REPORT — {len(alerts)} alerts generated")
    print(f"{'='*55}")

    # Group by severity
    by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for a in alerts:
        sev = a.get("severity", "LOW")
        by_sev.setdefault(sev, []).append(a)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_alerts = by_sev.get(sev, [])
        if not sev_alerts:
            continue
        print(f"\n  [{sev}] — {len(sev_alerts)} alert(s)")
        for a in sev_alerts:
            print(f"    ▸ {a['alert_type']:<28} {a['src_ip']}")
            print(f"      {a['description'][:90]}")

    # Top offending IPs
    ip_count = {}
    for a in alerts:
        ip = a.get("src_ip", "unknown")
        ip_count[ip] = ip_count.get(ip, 0) + 1

    print(f"\n  Top offending IPs:")
    for ip, cnt in sorted(ip_count.items(), key=lambda x: -x[1])[:5]:
        print(f"    {ip:<22} → {cnt} alert(s)")

    print(f"{'='*55}")


if __name__ == "__main__":
    run_detection(verbose=True)