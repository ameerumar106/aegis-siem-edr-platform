"""
database.py
SQLite database handler.
Handles: init, insert logs, insert alerts, all query functions.
"""

import sqlite3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import DB_PATH
from storage.models import CREATE_LOGS_TABLE, CREATE_ALERTS_TABLE, CREATE_INDEXES


def get_connection():
    """Return a SQLite connection with row_factory for dict-like access."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and indexes if they don't exist."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute(CREATE_LOGS_TABLE)
    cur.execute(CREATE_ALERTS_TABLE)
    for idx in CREATE_INDEXES:
        cur.execute(idx)
    conn.commit()
    conn.close()
    print(f"[+] Database initialized → {DB_PATH}")


# ── Insert functions ──────────────────────────────────────────────────────────

def insert_log(normalized_dict):
    """Insert a single normalized log into the logs table."""
    d = normalized_dict
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO logs
            (timestamp, source, event_type, severity, severity_num,
             src_ip, dst_ip, user, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        d["timestamp"], d["source"],    d["event_type"],
        d["severity"],  d["severity_num"],
        d["src_ip"],    d["dst_ip"],    d["user"], d["message"]
    ))
    log_id = cur.lastrowid
    conn.commit()
    conn.close()
    return log_id


def insert_logs_bulk(normalized_list):
    """Insert many normalized logs at once (faster than one-by-one)."""
    conn = get_connection()
    cur  = conn.cursor()
    rows = [(
        d["timestamp"], d["source"],    d["event_type"],
        d["severity"],  d["severity_num"],
        d["src_ip"],    d["dst_ip"],    d["user"], d["message"]
    ) for d in normalized_list]

    cur.executemany("""
        INSERT INTO logs
            (timestamp, source, event_type, severity, severity_num,
             src_ip, dst_ip, user, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()
    conn.close()
    print(f"[+] Inserted {len(rows)} logs into database")


def insert_alert(alert_dict):
    """Insert a single alert into the alerts table."""
    d = alert_dict
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO alerts
            (timestamp, alert_type, severity, severity_num,
             src_ip, description, log_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        d["timestamp"],    d["alert_type"],
        d["severity"],     d["severity_num"],
        d.get("src_ip",  "unknown"),
        d.get("description", ""),
        d.get("log_ids", "")
    ))
    alert_id = cur.lastrowid
    conn.commit()
    conn.close()
    return alert_id


# ── Query functions ───────────────────────────────────────────────────────────

def get_all_logs(limit=500, offset=0):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT * FROM logs
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_logs_by_severity(severity):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM logs WHERE severity=? ORDER BY timestamp DESC", (severity,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_logs_by_source(source):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM logs WHERE source=? ORDER BY timestamp DESC", (source,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_logs_by_ip(ip):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM logs WHERE src_ip=? ORDER BY timestamp DESC", (ip,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_all_alerts(limit=200):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_stats():
    """Return summary statistics for the dashboard."""
    conn = get_connection()
    cur  = conn.cursor()

    stats = {}

    # Total logs
    cur.execute("SELECT COUNT(*) FROM logs")
    stats["total_logs"] = cur.fetchone()[0]

    # Logs by severity
    cur.execute("SELECT severity, COUNT(*) as cnt FROM logs GROUP BY severity")
    stats["by_severity"] = {row["severity"]: row["cnt"] for row in cur.fetchall()}

    # Logs by source
    cur.execute("SELECT source, COUNT(*) as cnt FROM logs GROUP BY source")
    stats["by_source"] = {row["source"]: row["cnt"] for row in cur.fetchall()}

    # Total alerts
    cur.execute("SELECT COUNT(*) FROM alerts")
    stats["total_alerts"] = cur.fetchone()[0]

    # Top attacker IPs
    cur.execute("""
        SELECT src_ip, COUNT(*) as cnt FROM logs
        WHERE src_ip != 'unknown'
        GROUP BY src_ip ORDER BY cnt DESC LIMIT 5
    """)
    stats["top_ips"] = [{"ip": row["src_ip"], "count": row["cnt"]} for row in cur.fetchall()]

    # Events over last 24h (by hour)
    cur.execute("""
        SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt
        FROM logs GROUP BY hour ORDER BY hour
    """)
    stats["by_hour"] = [{"hour": row["hour"], "count": row["cnt"]} for row in cur.fetchall()]

    conn.close()
    return stats


def clear_db():
    """Wipe all data (for testing/reset)."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("DELETE FROM logs")
    cur.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    print("[!] Database cleared")


if __name__ == "__main__":
    init_db()
    stats = get_stats()
    print(f"\n── Database Stats ──")
    print(f"   Total logs  : {stats['total_logs']}")
    print(f"   Total alerts: {stats['total_alerts']}")
    print(f"   By severity : {stats['by_severity']}")
    print(f"   By source   : {stats['by_source']}")