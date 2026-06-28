"""
fim_worker.py
Production-Tier Host Intrusion Detection System (HIDS).
Extracts and shields critical OS configuration lines from local environment context mapping rules.
"""

import os
import time
import datetime
import sqlite3
import hashlib
import json
import urllib.request
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Import our unified real-time pipeline components
from storage.database import insert_log
from detection.alert_engine import process_realtime_log

# ─────────────────────────────────────────────────────────────
# ⚙️ ENVIRONMENT CONTEXT CONFIGURATION PARSER
# ─────────────────────────────────────────────────────────────
def load_env_context():
    """Manual parser to extract configurations from local .env boundaries"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(base_dir, ".env")
    context = {
        "FIM_TARGET_PATHS": r"C:\Windows\System32\drivers\etc",
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
WEBHOOK_URL = ENV["SLACK_WEBHOOK_URL"]

# Dynamically decouple comma-separated paths and expand user/system macro shortcuts
raw_paths = ENV["FIM_TARGET_PATHS"].split(",")
TARGET_PATHS = [os.path.expandvars(p.strip()) for p in raw_paths if p.strip()]

print("="*80)
print("[+] AEGIS SYSTEM DEFENSE ACTIVATED: SECURED ENVIRONMENT HIDS ONLINE")
print("[+] Guarding runtime paths configuration context matrix:")
for path in TARGET_PATHS:
    print(f"  -> {path}")
print("="*80 + "\n")

# ─────────────────────────────────────────────────────────────
# 🛡️ CRYPTOGRAPHIC HASH GENERATOR
# ─────────────────────────────────────────────────────────────
def calculate_sha256(file_path):
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────
# 🛰️ CENTRALIZED SIEM REAL-TIME DISPATCHER
# ─────────────────────────────────────────────────────────────
def dispatch_realtime_fim_event(event_type, severity, description):
    """
    Transforms filesystem events into unified taxonomy data objects,
    commits them to storage, and processes correlation logic instantly.
    """
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Map directly onto our unified database schema blueprint variables
    normalized_log = {
        "timestamp": current_time,
        "source": "host_edr",
        "event_type": event_type,
        "severity": severity,
        "severity_num": {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, 2),
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": None,
        "dst_port": None,
        "protocol": "LOCAL",
        "user": "system",
        "message": description
    }
    
    try:
        # Stream into SQL storage layers
        insert_log(normalized_log)
        
        # Dispatch to correlation rules matrix on the fly
        process_realtime_log(normalized_log)
        
    except Exception as e:
        print(f"[-] HIDS Real-time integration pipe fault: {e}")

    # Out-of-band automated notification alerts processing
    if WEBHOOK_URL and not WEBHOOK_URL.startswith("YOUR_"):
        emoji = "🔴" if severity == "CRITICAL" else "🟠"
        payload = {
            "text": f"{emoji} *CRITICAL HOST INTRUSION DETECTED* {emoji}\n"
                    f"• *Alert Type:* `{event_type}`\n"
                    f"• *Severity:* `{severity}`\n"
                    f"• *Incident Details:* _{description}_\n"
                    f"Timestamp: {current_time}"
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

# ─────────────────────────────────────────────────────────────
# 👁️ SYSTEM RUNTIME WATCHER INTERCEPTOR ROUTINE
# ─────────────────────────────────────────────────────────────
class RealWorldIntegrityHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_hashes = {}
        self.build_initial_baseline()

    def build_initial_baseline(self):
        print("[*] Generating cryptographic footprint snapshot for system paths...")
        count = 0
        for path in TARGET_PATHS:
            if not os.path.exists(path):
                print(f"[!] Path skipped (Target destination not active/found): {path}")
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    file_hash = calculate_sha256(full_path)
                    if file_hash:
                        self.file_hashes[full_path] = file_hash
                        count += 1
        print(f"[+] Security baseline anchored. Shielding {count} critical environment system items.\n")

    def on_created(self, event):
        if event.is_directory: return
        file_path = event.src_path
        
        # Sleep transiently to avoid file lock conflicts during write-burst completions
        time.sleep(0.3)
        new_hash = calculate_sha256(file_path)
        self.file_hashes[file_path] = new_hash
        
        msg = f"Suspicious file creation spotted in protected path: '{file_path}'"
        dispatch_slack_notification = "HIGH"
        dispatch_realtime_fim_event("SYSTEM_FILE_INJECTED", dispatch_slack_notification, msg)

    def on_modified(self, event):
        if event.is_directory: return
        file_path = event.src_path
        
        current_hash = calculate_sha256(file_path)
        previous_hash = self.file_hashes.get(file_path)
        
        if current_hash and previous_hash and current_hash != previous_hash:
            self.file_hashes[file_path] = current_hash
            filename = os.path.basename(file_path)
            
            severity = "CRITICAL" if "hosts" in filename.lower() else "HIGH"
            msg = f"System profile mutation detected: '{file_path}' has broken cryptographic parity baseline!"
            dispatch_realtime_fim_event("SYSTEM_CONFIG_MUTATED", severity, msg)

    def on_deleted(self, event):
        if event.is_directory: return
        file_path = event.src_path
        if file_path in self.file_hashes:
            del self.file_hashes[file_path]
            msg = f"Critical infrastructure asset wiped out of filesystem: '{file_path}'"
            dispatch_realtime_fim_event("SYSTEM_FILE_DELETED", "HIGH", msg)

if __name__ == "__main__":
    observer = Observer()
    handler = RealWorldIntegrityHandler()
    
    watched_directories = 0
    for path in TARGET_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path=path, recursive=True if os.path.isdir(path) else False)
            watched_directories += 1
            
    if watched_directories > 0:
        observer.start()
        print(f"[+] HIDS Listener thread successfully linked onto {watched_directories} path locations.")
        try:
            while True: 
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            print("\n[-] Host Configuration Monitoring Engine offline.")
        observer.join()
    else:
        print("[-] Fatal initialization fault: No execution targets mapped successfully. Check target arrays.")