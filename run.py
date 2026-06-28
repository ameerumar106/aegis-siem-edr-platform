"""
run.py
Main entry point for the Aegis SIEM & EDR Security Platform.
Concurrently orchestrates multi-threaded sensors and the live streaming pipeline.
"""

import sys
import os
import logging
import threading
import time
import queue
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import FAKE_LOG_OUTPUT
from collector.fake_log_generator import generate_logs
from collector.log_collector import tail_log_file
from parser.log_parser import parse_line
from parser.normalizer import normalize
from storage.database import init_db, insert_log
from detection.alert_engine import process_realtime_log
from dashboard.app import create_app
from soar_engine import monitor_alerts_pipeline

# Configure rigorous system logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global thread-safe queue to pipe incoming log entries from collectors to processing workers
LIVE_LOG_QUEUE = queue.Queue()

def log_collector_worker():
    """Background thread worker that tails the simulated security log file in real-time"""
    logger.info("[+] Real-time Log Collector worker activated.")
    
    # Ensure a baseline log file exists to prevent file tail errors
    if not os.path.exists(FAKE_LOG_OUTPUT):
        logger.info("[!] Initial log file baseline missing. Creating seed array...")
        generate_logs(count=50)

    # Continuously capture fresh log entries (Yields lines on write bursts)
    for raw_line in tail_log_file(FAKE_LOG_OUTPUT, interval=1):
        if raw_line:
            LIVE_LOG_QUEUE.put(raw_line)

def siem_pipeline_processor():
    """Core Streaming Processing Loop: Parse -> Normalize -> Store -> Correlate"""
    logger.info("[+] Real-time SIEM Analysis Pipeline running...")
    while True:
        try:
            # Block until an event drops into the memory queue buffer
            raw_line = LIVE_LOG_QUEUE.get(timeout=1)
            
            # 1. Parse raw string strings into structured dictionary attributes
            parsed_data = parse_line(raw_line)
            if not parsed_data:
                LIVE_LOG_QUEUE.task_done()
                continue
                
            # 2. Normalize disparate keys into uniform SIEM taxonomy parameters
            normalized_log = normalize(parsed_data)
            
            # 3. Stream instantly into the persistent SQLite storage layer
            insert_log(normalized_log)
            
            # 4. Push directly into our context sliding-window detection rules
            process_realtime_log(normalized_log, verbose=True)
            
            LIVE_LOG_QUEUE.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"[-] Critical fault inside real-time analysis pipeline: {e}")

def continuous_background_generator():
    """Simulates background system activity by periodically generating fake multi-vector logs"""
    logger.info("[+] Automated security log simulation engine active.")
    while True:
        try:
            time.sleep(random.randint(4, 8))  # Drop batch anomalies randomly every few seconds
            generate_logs(count=random.randint(1, 4))
        except Exception as e:
            logger.error(f"[-] Log simulation worker encountered a fault: {e}")

def start_sniffer_sensor():
    """Spins up the Scapy Deep Packet Inspection worker asynchronously"""
    try:
        from live_sniffer import packet_inspection_callback, INTERFACE_NAME
        from scapy.all import sniff
        logger.info(f"[+] Interface Sniffer worker binding onto endpoint channel: {INTERFACE_NAME}")
        sniff(iface=INTERFACE_NAME, prn=packet_inspection_callback, store=False)
    except Exception as e:
        logger.warning(f"[!] Deep Packet Inspection sensor failed to bind or lacks admin privileges: {e}")

def start_hids_sensor():
    """Spins up the Watchdog Integrity Monitor background kernel listener"""
    try:
        from fim_worker import RealWorldIntegrityHandler, TARGET_PATHS
        from watchdog.observers import Observer
        
        logger.info("[+] Initializing File Integrity Monitoring hooks...")
        observer = Observer()
        handler = RealWorldIntegrityHandler()
        
        watched_count = 0
        for path in TARGET_PATHS:
            if os.path.exists(path):
                observer.schedule(handler, path=path, recursive=True if os.path.isdir(path) else False)
                watched_count += 1
                
        if watched_count > 0:
            observer.start()
            logger.info(f"[+] HIDS Listener safely monitoring {watched_count} file structures.")
            while True:
                time.sleep(1)
        else:
            logger.error("[-] HIDS sensor initialization halted: No valid targets mapped.")
    except Exception as e:
        logger.warning(f"[!] File Integrity Auditing engine exception raised: {e}")

if __name__ == "__main__":
    logger.info("=" * 65)
    logger.info("  AEGIS SIEM & EDR SYSTEM UNIFIED ARCHITECTURE CONTROL LAYER")
    logger.info("=" * 65)

    # Initialize SQL backend infrastructure, schemas, and missing indexes
    logger.info("[+] Verifying atomic database schema layouts...")
    init_db()

    # Register concurrent isolation threads
    workers = [
        threading.Thread(target=log_collector_worker, name="LogTailer", daemon=True),
        threading.Thread(target=siem_pipeline_processor, name="PipelineProcessor", daemon=True),
        threading.Thread(target=continuous_background_generator, name="MockTraffic", daemon=True),
        threading.Thread(target=start_sniffer_sensor, name="NetworkSniffer", daemon=True),
        threading.Thread(target=start_hids_sensor, name="HIDSWorker", daemon=True),
        threading.Thread(target=monitor_alerts_pipeline, name="SOARWorker", daemon=True)
    ]

    # Boot thread grid
    for worker in workers:
        worker.start()
        logger.info(f"[+] Background service worker '{worker.name}' isolated successfully.")

    # Primary Boundary Block: Bind main execution onto our responsive Flask server UI
    logger.info("\n" + "=" * 65)
    logger.info(" [+] LOCKING INTERACTIVE SOC DASHBOARD VIEW PORTAL ENGINE ONLINE")
    logger.info(" [+] Web Administration Interface: http://127.0.0.1:5000")
    logger.info("=" * 65 + "\n")
    
    app = create_app()
    # Debug=False and use_reloader=False are mandatory to prevent sub-process thread duplication crashing Scapy
    app.run(debug=False, host="127.0.0.1", port=5000, use_reloader=False)