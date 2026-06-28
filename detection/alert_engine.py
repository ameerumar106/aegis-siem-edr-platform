"""
alert_engine.py
Real-time Stream Detection Engine for Aegis SIEM.
Evaluates single log streaming elements dynamically and commits triggered alerts.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from storage.database import insert_alert, get_recent_logs_by_ip
from detection.rules import REALTIME_RULES


def process_realtime_log(current_log, verbose=True):
    """
    Evaluates a fresh incoming log entry against all real-time security rules.
    If a threat signature or volumetric threshold matches, it creates and saves an alert.
    """
    if not current_log:
        return []

    src_ip = current_log.get("src_ip", "unknown")
    triggered_alerts = []

    # Optimize lookups: pass recent context for the specific offending IP if known
    recent_context = []
    if src_ip != "unknown":
        try:
            # Query the sliding 10-minute window for this specific target host
            recent_context = get_recent_logs_by_ip(src_ip, minutes_back=10)
        except Exception as e:
            print(f"[-] Context retrieval error for IP {src_ip}: {e}")

    # Process entry across the active streaming rule matrix
    for rule_fn in REALTIME_RULES:
        rule_name = rule_fn.__name__.replace("evaluate_", "").upper()
        try:
            # Evaluate rule using the current log context
            alert = rule_fn(current_log, recent_context)
            
            if alert:
                triggered_alerts.append(alert)
                # Commit immediately to the persistent backend storage
                insert_alert(alert)
                
                if verbose:
                    print(f"\n[🚨 REAL-TIME ALERT RAISED]")
                    print(f"    Type    : {alert['alert_type']}")
                    print(f"    Severity: {alert['severity']} (Level {alert['severity_num']})")
                    print(f"    Actor IP: {alert['src_ip']}")
                    print(f"    Summary : {alert['description']}\n")
                    
        except Exception as e:
            print(f"[-] Real-time evaluation fault on rule {rule_name}: {e}")

    return triggered_alerts


def run_legacy_batch_detection():
    """
    Fallback handle if batch scanning historically parsed logs is manually required.
    """
    from storage.database import get_all_logs
    print("[!] Running legacy batch analysis process drop across last 10,000 items...")
    logs = get_all_logs(limit=10000)
    
    total_alerts = 0
    for log in reversed(logs):  # Process chronologically from past to present
        alerts = process_realtime_log(log, verbose=False)
        total_alerts += len(alerts)
        
    print(f"[+] Legacy batch pass finished. Evaluated {len(logs)} logs -> Generated {total_alerts} alerts.")


if __name__ == "__main__":
    # If run standalone as a utility script, evaluate the historical dataset sequentially
    run_legacy_batch_detection()