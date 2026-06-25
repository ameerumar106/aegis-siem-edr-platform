import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Blueprint, render_template, jsonify, request
from storage.database import (
    get_all_logs, get_all_alerts, get_stats,
    get_logs_by_severity, get_logs_by_source, get_logs_by_ip
)

main = Blueprint("main", __name__)

@main.route("/")
def index():
    stats = get_stats()
    stats['recent_alerts'] = get_all_alerts(limit=10)
    return render_template("index.html", stats=stats)

@main.route("/alerts")
def alerts_page():
    alerts = get_all_alerts(limit=300)
    return render_template("alerts.html", alerts=alerts)

@main.route("/logs")
def logs_page():
    severity = request.args.get("severity", "")
    source   = request.args.get("source", "")
    ip       = request.args.get("ip", "")
    if severity:
        logs = get_logs_by_severity(severity)
    elif source:
        logs = get_logs_by_source(source)
    elif ip:
        logs = get_logs_by_ip(ip)
    else:
        logs = get_all_logs(limit=500)
    return render_template("logs.html", logs=logs, severity=severity, source=source, ip=ip)

@main.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

@main.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 100))
    return jsonify(get_all_logs(limit=limit))

@main.route("/api/alerts")
def api_alerts():
    return jsonify(get_all_alerts(limit=200))

@main.route("/api/logs/severity/<severity>")
def api_logs_severity(severity):
    return jsonify(get_logs_by_severity(severity.upper()))

@main.route("/api/logs/source/<source>")
def api_logs_source(source):
    return jsonify(get_logs_by_source(source.lower()))