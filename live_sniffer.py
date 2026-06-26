"""
live_sniffer.py
Network Telemetry Engine - Deep Packet Inspection (DPI) Sensor.
Extracts network frames dynamically using environment configurations.
"""

import os
import sys
import time
import datetime
import sqlite3
import json
import urllib.request
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import geoip2.database

# ─────────────────────────────────────────────────────────────
# ⚙️ ENVIRONMENT CONTEXT CONFIGURATION PARSER
# ─────────────────────────────────────────────────────────────
def load_env_context():
    """Manual parser to extract configurations from local .env boundaries"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(base_dir, ".env")
    context = {
        "NETWORK_INTERFACE": "Wi-Fi",
        "GEOIP_DB_PATH": "storage/GeoLite2-Country.mmdb",
        "SLACK_WEBHOOK_URL": ""
    }
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                if line.strip() and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    context[key.strip()] = value.strip()
    return context

# Anchor Configuration Assets
ENV = load_env_context()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "storage", "siem.db")
GEOIP_PATH = os.path.join(BASE_DIR, ENV["GEOIP_DB_PATH"])
WEBHOOK_URL = ENV["SLACK_WEBHOOK_URL"]
INTERFACE_NAME = ENV["NETWORK_INTERFACE"]

print("="*80)
print("[+] AEGIS NETWORK INGESTION ENGINE: CORE SENSOR ONLINE")
print(f"[+] Binding Interface Target: {INTERFACE_NAME}")
print(f"[+] GeoIP Mapping Matrix: {GEOIP_PATH}")
print("="*80 + "\n")

# Statistical Baseline Buffers
TRAFFIC_TRACKER = defaultdict(int)
WINDOW_START_TIME = time.time()
ROLLING_WINDOW_SIZE = 10  # 10 second tracking slices
VOLUMETRIC_THRESHOLD = 150  # Hardened baseline alert threshold limit

# Initialize GeoIP Reader Client
try:
    GEOIP_READER = geoip2.database.Reader(GEOIP_PATH)
    print("[+] MaxMind Country Database mapped successfully.")
except Exception as e:
    GEOIP_READER = None
    print(f"[-] GeoIP Initialization bypassed (Missing binary layout file): {e}")

# ─────────────────────────────────────────────────────────────
# 🛡️ TELEMETRY CORRELATION ENGINE
# ─────────────────────────────────────────────────────────────
def get_country_iso(ip_address):
    if not GEOIP_READER or ip_address.startswith(("10.", "192.168.", "127.")):
        return "Internal LAN Node"
    try:
        match = GEOIP_READER.country(ip_address)
        return match.country.name if match.country.name else "Unknown Country Location"
    except Exception:
        return "External Public Node"

def dispatch_slack_notification(event_type, severity, summary):
    if not WEBHOOK_URL or WEBHOOK_URL.startswith("YOUR_"):
        return
    emoji = "🔴" if severity == "CRITICAL" else "🟠"
    payload = {
        "text": f"{emoji} *AEGIS NETWORK MONITOR ALARM* {emoji}\n"
                f"• *Threat Classification:* `{event_type}`\n"
                f"• *Severity Rating:* `{severity}`\n"
                f"• *Context Summary:* _{summary}_\n"
                f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    }
    try:
        req = urllib.request.Request(
            WEBHOOK_URL, 
            data=json.dumps(payload).encode('utf-8'), 
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response: pass
    except Exception:
        pass

def write_security_telemetry(event_type, severity, src_ip, dst_ip, message):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO logs (timestamp, source, event_type, severity, src_ip, dst_ip, message, user, created_at)
            VALUES (?, 'network_dpi', ?, ?, ?, ?, ?, 'system', ?)
        """, (current_time, event_type, severity, src_ip, dst_ip, message, current_time))
        
        cursor.execute("""
            INSERT INTO alerts (timestamp, event_type, severity, src_ip, description, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'OPEN', ?)
        """, (current_time, event_type, severity, src_ip, message, current_time))
        
        conn.commit()
    except Exception as e:
        print(f"[-] Database ingestion fault: {e}")
    finally:
        conn.close()

# ─────────────────────────────────────────────────────────────
# 👁️ PACKET STREAM DECONSTRUCTION WORKER
# ─────────────────────────────────────────────────────────────
def packet_inspection_callback(packet):
    global WINDOW_START_TIME, TRAFFIC_TRACKER
    
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Track volumetric packet metrics
    current_time = time.time()
    TRAFFIC_TRACKER[src_ip] += 1
    
    # Monitor for anomalies across rolling timeframe slices
    if current_time - WINDOW_START_TIME > ROLLING_WINDOW_SIZE:
        for ip, count in list(TRAFFIC_TRACKER.items()):
            if count > VOLUMETRIC_THRESHOLD:
                location = get_country_iso(ip)
                description = f"Traffic spike anomaly detected from host {ip} ({location}). Transmitted {count} frame structures in a {ROLLING_WINDOW_SIZE}s window."
                print(f"[🔥 TRAFFIC SPIKE] {description}")
                write_security_telemetry("TRAFFIC_VOLUMETRIC_SPIKE", "HIGH", ip, dst_ip, description)
                dispatch_slack_notification("TRAFFIC_VOLUMETRIC_SPIKE", "HIGH", description)
        TRAFFIC_TRACKER.clear()
        WINDOW_START_TIME = current_time

    # Specific Signature Detections
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == 0x02:  # Pure SYN Packet structure without ACK validation
            location = get_country_iso(src_ip)
            description = f"TCP SYN packet flagged from {src_ip} ({location}) Target Port: {packet[TCP].dport}. Potential reconnaissance/port scan sweep active."
            print(f"[⚠️ SIGNATURE MATCH] Port probe sequence isolated from {src_ip}")
            write_security_telemetry("PORT_SCAN", "HIGH", src_ip, dst_ip, description)
            dispatch_slack_notification("PORT_SCAN", "HIGH", description)

if __name__ == "__main__":
    try:
        sniff(iface=INTERFACE_NAME, prn=packet_inspection_callback, store=False)
    except KeyboardInterrupt:
        print("\n[-] Core Network Telemetry Sensor gracefully stopped.")
        if GEOIP_READER: GEOIP_READER.close()