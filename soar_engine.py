"""
soar_engine.py
Aegis SOAR Automation Hub - Automated Incident Response Engine.
Monitors the alerts database and auto-deploys local firewall blocks.
"""

import os
import time
import sqlite3
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "storage", "siem.db")

# Keep track of malicious assets we have already blocked during this runtime session
BLOCKED_IPS = set()

def execute_firewall_ban(ip_address):
    """Executes a native Windows Advanced Firewall inbound blocking rule via administrative shell"""
    ip_clean = str(ip_address).strip()
    
    if not ip_clean or ip_clean in BLOCKED_IPS or "127.0.0.1" in ip_clean or "localhost" in ip_clean:
        return False
        
    rule_name = f"AEGIS_SOAR_AUTO_BLOCK_{ip_clean}"
    print(f"\n[💥 SOAR PLAYBOOK TRIGGERED] High severity threat isolated from IP: {ip_clean}")
    print(f"[*] Orchestrating active containment defense. Deploying Windows Firewall rule...")

    cmd = (
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction Inbound -Action Block -RemoteAddress "{ip_clean}" -Protocol Any'
    )
    
    try:
        subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, check=True)
        print(f"[🛡️ SOAR MITIGATION SUCCESS] IP Address {ip_clean} is now completely banned at the kernel firewall level.")
        BLOCKED_IPS.add(ip_clean)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] SOAR Orchestration failed (Ensure terminal is running as Administrator): {e.stderr.strip()}")
        return False

def monitor_alerts_pipeline():
    """Continuously monitors the alerts data engine table for fresh high-risk triggers"""
    print("[+] AEGIS ACTIVE CONTEXT SOAR ENGINE ONLINE: WATCHING FOR CRITICAL THREAT MATRIX ALERTS...")
    
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # CASE-INSENSITIVE CHECK: Lowercase comparison catches 'OPEN', 'Open', and 'open'
            cursor.execute("""
                SELECT id, alert_type, src_ip, description 
                FROM alerts 
                WHERE severity IN ('HIGH', 'CRITICAL') AND LOWER(status) = 'open'
                ORDER BY timestamp DESC LIMIT 10
            """)
            active_threats = cursor.fetchall()
            conn.close()
            
            for threat in active_threats:
                threat_id, alert_type, src_ip, description = threat
                
                if str(alert_type).upper() in ("PORT_SCAN", "TRAFFIC_VOLUMETRIC_SPIKE", "WEB_ATTACK"):
                    if src_ip:
                        ip_clean = str(src_ip).strip()
                        execute_firewall_ban(ip_clean)
                        
                        # Clean description tag to avoid duplicating labels if the loop runs twice
                        clean_desc = description.replace("[SOAR AUTO-BLOCKED] ", "")
                        
                        # Update the status using strict uppercase 'CONTAINED' to match frontend templates
                        conn = sqlite3.connect(DB_PATH)
                        cursor = conn.cursor()
                        cursor.execute("""
                            UPDATE alerts 
                            SET status = 'CONTAINED', description = ? 
                            WHERE id = ?
                        """, (f"[SOAR AUTO-BLOCKED] {clean_desc}", threat_id))
                        conn.commit()
                        conn.close()
                            
        except Exception as e:
            print(f"[-] SOAR Pipeline checking exception: {e}")
            
        time.sleep(2)

if __name__ == "__main__":
    monitor_alerts_pipeline()