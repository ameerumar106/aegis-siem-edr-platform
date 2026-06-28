"""
models.py
SQL schema definitions for the Aegis SIEM database.
Defines structural tables, native constraints, and optimization indexes.
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
    src_port     INTEGER DEFAULT NULL,
    dst_port     INTEGER DEFAULT NULL,
    protocol     TEXT    DEFAULT NULL,
    user         TEXT    DEFAULT 'unknown',
    message      TEXT,
    created_at   TEXT    DEFAULT (datetime('now', 'localtime'))
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
    status       TEXT    DEFAULT 'OPEN',
    resolved     INTEGER DEFAULT 0,
    created_at   TEXT    DEFAULT (datetime('now', 'localtime'))
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp   ON logs(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_logs_source      ON logs(source);",
    "CREATE INDEX IF NOT EXISTS idx_logs_event_type  ON logs(event_type);",
    "CREATE INDEX IF NOT EXISTS idx_logs_severity    ON logs(severity_num);",
    "CREATE INDEX IF NOT EXISTS idx_logs_src_ip      ON logs(src_ip);",
    "CREATE INDEX IF NOT EXISTS idx_logs_network_flow ON logs(src_ip, dst_port);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity_num);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);"
]