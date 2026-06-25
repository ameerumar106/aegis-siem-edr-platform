"""
models.py
SQL schema definitions for the SIEM database.
Two tables: logs, alerts
"""

CREATE_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    source       TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    severity_num INTEGER NOT NULL DEFAULT 1,
    src_ip       TEXT    DEFAULT 'unknown',
    dst_ip       TEXT    DEFAULT 'unknown',
    user         TEXT    DEFAULT 'unknown',
    message      TEXT,
    created_at   TEXT    DEFAULT (datetime('now'))
);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    alert_type   TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    severity_num INTEGER NOT NULL DEFAULT 1,
    src_ip       TEXT    DEFAULT 'unknown',
    description  TEXT,
    log_ids      TEXT,
    resolved     INTEGER DEFAULT 0,
    created_at   TEXT    DEFAULT (datetime('now'))
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp   ON logs(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_logs_source      ON logs(source);",
    "CREATE INDEX IF NOT EXISTS idx_logs_severity    ON logs(severity_num);",
    "CREATE INDEX IF NOT EXISTS idx_logs_src_ip      ON logs(src_ip);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity_num);",
]