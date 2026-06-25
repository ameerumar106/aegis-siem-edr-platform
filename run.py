"""
run.py
Main entry point — runs the full SIEM pipeline:
Generate → Collect → Parse → Normalize → Store → Detect → Alert
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collector.fake_log_generator import generate_logs
from collector.log_collector      import collect_all_logs
from parser.log_parser            import parse_all
from parser.normalizer            import normalize_all
from storage.database             import init_db, insert_logs_bulk, get_stats, clear_db
from detection.alert_engine       import run_detection


def run_pipeline(regenerate=True):
    print("=" * 55)
    print("   SIEM DASHBOARD — Full Pipeline")
    print("=" * 55)

    print("\n[1/6] Initializing database...")
    init_db()
    clear_db()

    if regenerate:
        print("\n[2/6] Generating fake logs...")
        generate_logs()

    print("\n[3/6] Collecting logs...")
    raw_logs = collect_all_logs()

    print("\n[4/6] Parsing and normalizing...")
    parsed, failed = parse_all(raw_logs)
    print(f"   Parsed: {len(parsed)} | Failed: {failed}")
    normalized = normalize_all(parsed)

    print("\n[5/6] Storing to database...")
    insert_logs_bulk(normalized)

    print("\n[6/6] Running detection engine...")
    alerts = run_detection(verbose=True)

    stats = get_stats()
    print(f"\n{'='*55}")
    print(f"   Pipeline Complete")
    print(f"{'='*55}")
    print(f"   Logs in DB    : {stats['total_logs']}")
    print(f"   Alerts raised : {stats['total_alerts']}")
    print(f"   By severity   : {stats['by_severity']}")
    print(f"   By source     : {stats['by_source']}")
    print(f"{'='*55}")


if __name__ == "__main__":
    run_pipeline()