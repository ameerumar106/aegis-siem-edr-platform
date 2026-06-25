"""
live_sniffer.py
Production-Tier, High-Performance SOC Live Network Sniffer.
Features: Batch Buffering, Reverse DNS, GeoIP, Anomaly Detection, Slack Escalation, and Log Rotation.
"""

import sys
import os
import datetime
import time
import sqlite3
import json
import urllib.request
import csv
import math
import socket
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Locate the database file path dynamically
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "storage", "siem.db")
ARCHIVE_DIR = os.path.join(BASE_DIR, "storage", "archives")
GEOIP_DB_PATH = os.path.join(BASE_DIR, "storage", "GeoLite2-Country.mmdb")

# ─────────────────────────────────────────────────────────────
# 🛰️ INTEGRATED SIEM ESCALATION CONFIGURATION
# ─────────────────────────────────────────────────────────────
# Your active Slack Webhook channel URL route
WEBHOOK_URL = "https://hooks.slack.com/services/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"

# ─────────────────────────────────────────────────────────────
# 🛠️ DATABASE AUTOMATIC PROVISIONING ENGINE
# ─────────────────────────────────────────────────────────────
def init_siem_db():
    """Guarantees directory structures and schemas exist before dashboard queries run"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source TEXT, event_type TEXT,
        severity TEXT, src_ip TEXT, dst_ip TEXT, message TEXT, user TEXT, created_at TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, event_type TEXT,
        severity TEXT, src_ip TEXT, description TEXT, status TEXT DEFAULT 'OPEN', created_at TEXT
    )
    """)
    conn.commit()
    conn.close()
    print("[+] Database verified: 'logs' and 'alerts' schemas successfully initialized.")

init_siem_db()

# ⚡ PERFORMANCE & ANOMALY TUNING CONFIGURATIONS
BATCH_LIMIT = 50           # Commit traffic logs to disk in chunks of 50
LAST_FLUSH_TIME = time.time()
BUFFER_QUEUE = []          # RAM cache for normal traffic logs

TRAFFIC_HISTORY = [5, 10, 8, 12, 6]  # Seed baseline with normal packet counts per interval
PACKET_COUNT_THIS_INTERVAL = 0

print("="*80)
print("[+] ALL-IN-ONE SOC INTELLIGENT NETWORK SENSOR DEPLOYED SUCCESSFULLY")
print("[+] Listening live on physical network interface... Press CTRL+C to terminate.")
print("="*80 + "\n")

# ─────────────────────────────────────────────────────────────
# 🌐 REVERSE DNS RESOLUTION ENGINE
# ─────────────────────────────────────────────────────────────
def resolve_ip_to_domain(ip_address):
    """Translates a raw numerical IP address into a readable website domain name"""
    if ip_address.startswith(("192.168.", "127.", "10.", "172.16.")) or ip_address == "::1":
        return "Internal LAN Node"
    try:
        # Performs a reverse DNS look up against local DNS cache
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except Exception:
        return "External WAN Host"

# ─────────────────────────────────────────────────────────────
# 🗺️ GEOLOCATION ENRICHMENT LOOKUP
# ─────────────────────────────────────────────────────────────
def get_ip_country(ip_address):
    """Performs an ultra-fast offline binary lookup to find the origin country of an IP"""
    if ip_address.startswith(("127.", "192.168.", "10.", "172.16.")) or ip_address == "::1":
        return "Internal LAN"
        
    if not os.path.exists(GEOIP_DB_PATH):
        return "Unknown Location"
        
    try:
        import geoip2.database
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip_address)
            return response.country.name if response.country.name else "Unknown Country"
    except Exception:
        return "External WAN"

# ─────────────────────────────────────────────────────────────
# 📈 MATHEMATICAL ANOMALY INSPECTION ENGINE
# ─────────────────────────────────────────────────────────────
def inspect_traffic_anomaly(current_count):
    """Calculates rolling standard deviation to isolate statistical traffic spikes"""
    global TRAFFIC_HISTORY
    if len(TRAFFIC_HISTORY) < 3:
        TRAFFIC_HISTORY.append(current_count)
        return False

    mean = sum(TRAFFIC_HISTORY) / len(TRAFFIC_HISTORY)
    variance = sum((x - mean) ** 2 for x in TRAFFIC_HISTORY) / len(TRAFFIC_HISTORY)
    std_dev = math.sqrt(variance)
    
    # Define Anomaly Threshold (Mean + 3 Standard Deviations)
    anomaly_threshold = max(mean + (3 * std_dev), 25)
    
    TRAFFIC_HISTORY.append(current_count)
    if len(TRAFFIC_HISTORY) > 20:
        TRAFFIC_HISTORY.pop(0)
        
    if current_count > anomaly_threshold:
        print(f"[⚠️ ANOMALY DETECTED] Traffic Spike: {current_count} pkts/interval (Threshold: {anomaly_threshold:.2f})")
        return True
    return False

# ─────────────────────────────────────────────────────────────
# 🗄️ AUTOMATIC LOG ROTATION & RETENTION ENGINE
# ─────────────────────────────────────────────────────────────
def rotate_logs(retention_hours=24):
    """Identifies logs older than X hours, archives them to a CSV, and purges the live DB"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cutoff_time = (datetime.datetime.now() - datetime.timedelta(hours=retention_hours)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("SELECT * FROM logs WHERE timestamp < ?", (cutoff_time,))
        old_logs = cursor.fetchall()
        if not old_logs: return
        
        archive_filename = f"log_archive_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        archive_filepath = os.path.join(ARCHIVE_DIR, archive_filename)
        
        cursor.execute("PRAGMA table_info(logs)")
        columns = [col[1] for col in cursor.fetchall()]
        
        with open(archive_filepath, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(columns)
            writer.writerows(old_logs)
            
        cursor.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_time,))
        conn.commit()
        print(f"[🧹 LOG ROTATION] Cleared active rows. Archived {len(old_logs)} records into: {archive_filename}")
    except Exception as e:
        print(f"[-] Log rotation cycle failure: {e}")
    finally:
        conn.close()

# ─────────────────────────────────────────────────────────────
# 🔔 EXTERNAL NOTIFICATION ENGINE (SLACK MARKDOWN BLOCK)
# ─────────────────────────────────────────────────────────────
def send_webhook_alert(event_type, severity, src_ip, description, country="Unknown"):
    """Sends a clean, formatted real-time alert payload directly to your Slack channel"""
    if not WEBHOOK_URL: return
    emoji = "🔴" if severity == "CRITICAL" else "🟠"
    payload = {
        "text": f"{emoji} *SIEM REAL-TIME ALERT RAISED* {emoji}\n"
                f"• *Incident Type:* `{event_type}`\n"
                f"• *Severity:* `{severity}`\n"
                f"• *Target/Source:* `{src_ip}` ({country})\n"
                f"• *Details:* _{description}_\n"
                f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    }
    try:
        req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response: pass
    except Exception: pass

def flush_buffer():
    """Flushes staged logs out of RAM directly into the SQLite logs table"""
    global BUFFER_QUEUE, LAST_FLUSH_TIME, PACKET_COUNT_THIS_INTERVAL
    current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Evaluate aggregate traffic patterns before loop reset
    if inspect_traffic_anomaly(PACKET_COUNT_THIS_INTERVAL):
        msg = f"Volumetric spike detected: handling {PACKET_COUNT_THIS_INTERVAL} packets in a 3-second window."
        route_instant_alert(current_time_str, "TRAFFIC_SPIKE_ANOMALY", "HIGH", "network_interface", msg)
        send_webhook_alert("TRAFFIC_SPIKE_ANOMALY", "HIGH", "LAN_INTERFACE", msg, "Local Node")
        
    PACKET_COUNT_THIS_INTERVAL = 0

    if not BUFFER_QUEUE:
        LAST_FLUSH_TIME = time.time()
        return
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        query = "INSERT INTO logs (timestamp, source, event_type, severity, src_ip, dst_ip, message, user, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        cursor.executemany(query, BUFFER_QUEUE)
        conn.commit()
        print(f"[⚙️ DB FLUSH] Committed {len(BUFFER_QUEUE)} traffic logs to database in a single batch.")
    except Exception as e: 
        print(f"[-] Database batch insert breakdown: {e}")
    finally:
        conn.close()
        BUFFER_QUEUE = [] 
        LAST_FLUSH_TIME = time.time()
        rotate_logs(retention_hours=24) # Housekeeping

def route_instant_alert(timestamp, event_type, severity, src_ip, description):
    """Bypasses memory buffer to write critical alerts to the alerts table instantly"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        query = "INSERT INTO alerts (timestamp, event_type, severity, src_ip, description, status, created_at) VALUES (?, ?, ?, ?, ?, 'OPEN', ?)"
        cursor.execute(query, (timestamp, event_type, severity, src_ip, description, timestamp))
        conn.commit()
    except Exception as e: pass
    finally: conn.close()

def process_packet(packet):
    global BUFFER_QUEUE, LAST_FLUSH_TIME, PACKET_COUNT_THIS_INTERVAL
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "UNKNOWN"
            port_info = ""
            dport = 0
            
            if packet.haslayer(TCP):
                proto = "TCP"
                dport = packet[TCP].dport
                port_info = f" -> Port {dport}"
            elif packet.haslayer(UDP):
                proto = "UDP"
                dport = packet[UDP].dport
                port_info = f" -> Port {dport}"
            elif packet.haslayer(ICMP):
                proto = "ICMP"

            # 🛑 CRITICAL FILTER: Completely block local dashboard loop overhead noise from crashing database
            if proto == "TCP" and (packet[TCP].sport == 5000 or dport == 5000):
                return
            if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
                return

            # Increment interval telemetry tracker counter
            PACKET_COUNT_THIS_INTERVAL += 1

            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            severity = "LOW"
            event_type = f"NET_{proto}_TRAFFIC"
            
            # Enrich packet data string dynamically using DNS and GeoIP functions
            origin_country = get_ip_country(src_ip)
            resolved_host = resolve_ip_to_domain(src_ip)
            message = f"Inbound packet from {src_ip} ({resolved_host}) [{origin_country}]{port_info}"
            
            is_alert = False

            # Incident Detections Rules
            if proto == "ICMP":
                severity = "MEDIUM"
                event_type = "PING_SCAN"
                message = f"ICMP Echo Request from {src_ip} ({resolved_host}) [{origin_country}] (Potential Reconnaissance)"
                is_alert = True
            elif proto == "TCP" and packet[TCP].flags == 0x02:  
                severity = "HIGH"
                event_type = "PORT_SCAN"
                message = f"TCP SYN packet flagged from {src_ip} ({resolved_host}) [{origin_country}] targeting port {dport}"
                is_alert = True
            elif proto == "TCP" and (dport == 80 or dport == 8080):
                payload = str(packet[TCP].payload).lower()
                if any(x in payload for x in ["select", "union", "script", "../", "cmd="]):
                    severity = "CRITICAL"
                    event_type = "WEB_EXPLOIT_ATTACK"
                    message = f"Web payload injection detected from {src_ip} [{origin_country}] targeting application port {dport}"
                    is_alert = True

            log_tuple = (current_time, "network", event_type, severity, src_ip, dst_ip, message, "system", current_time)
            BUFFER_QUEUE.append(log_tuple)

            if is_alert:
                print(f"[🔥 LIVE ALERT SIGNED] [{current_time}] {event_type} from {src_ip} [{origin_country}] [{severity}]")
                route_instant_alert(current_time, event_type, severity, src_ip, message)
                if severity in ["HIGH", "CRITICAL"]:
                    send_webhook_alert(event_type, severity, src_ip, message, origin_country)

            # Trigger check on the time/capacity knobs
            if len(BUFFER_QUEUE) >= BATCH_LIMIT or (time.time() - LAST_FLUSH_TIME) >= 3:
                flush_buffer()

    except Exception as e: pass

# Automatically bind to default physical interface route layer
sniff(prn=process_packet, store=0)