from flask import Flask, jsonify, render_template
import sqlite3
import os
from datetime import datetime, timezone

# ==========================================
# VSEC SECURITY OPERATIONS
# FLASK DASHBOARD BACKEND
# ==========================================

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "vsec.db")

# Current monitoring session starts when Flask starts.
SESSION_START = datetime.now(timezone.utc).isoformat()


# ==========================================
# DATABASE CONNECTION
# ==========================================

def connect_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def initialize_database():

    with connect_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                attack TEXT,
                severity INTEGER,
                signature_id INTEGER,
                category TEXT,
                event_id TEXT UNIQUE
            )
        """)

        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(alerts)")
        }

        # Track when each alert was inserted into SQLite.
        if "inserted_at" not in columns:
            conn.execute("""
                ALTER TABLE alerts
                ADD COLUMN inserted_at TEXT
            """)

        # Existing records remain historical.
        conn.commit()


# ==========================================
# READ ALERTS
# ==========================================

def get_alerts(live_only=False):

    query = """
        SELECT
            id,
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack,
            severity,
            signature_id,
            category,
            inserted_at
        FROM alerts
    """

    parameters = ()

    if live_only:
        query += """
            WHERE inserted_at IS NOT NULL
              AND inserted_at >= ?
        """
        parameters = (SESSION_START,)

    query += " ORDER BY id ASC"

    with connect_db() as conn:
        rows = conn.execute(query, parameters).fetchall()

    return [dict(row) for row in rows]


# ==========================================
# LIVE DASHBOARD PAGE
# ==========================================

@app.route("/")
def home():
    return render_template("dashboard.html")


# ==========================================
# ATTACK HISTORY PAGE
# ==========================================

@app.route("/history")
def history():
    return render_template("history.html")


# ==========================================
# LIVE ALERTS API
# ==========================================

@app.route("/api/alerts")
def api_alerts():

    try:
        alerts = get_alerts(live_only=True)

        return jsonify({
            "status": "success",
            "total_alerts": len(alerts),
            "alerts": alerts
        })

    except sqlite3.Error as error:
        app.logger.error("Database error: %s", error)

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve live alerts"
        }), 500


# ==========================================
# ATTACK HISTORY API
# ==========================================

@app.route("/api/history")
def api_history():

    try:
        alerts = get_alerts(live_only=False)

        return jsonify({
            "status": "success",
            "total_alerts": len(alerts),
            "alerts": alerts
        })

    except sqlite3.Error as error:
        app.logger.error("Database error: %s", error)

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve attack history"
        }), 500


# ==========================================
# LIVE DASHBOARD STATISTICS API
# ==========================================

@app.route("/api/stats")
def api_stats():

    try:
        alerts = get_alerts(live_only=True)

        high = sum(
            1 for alert in alerts
            if alert["severity"] == 1
        )

        medium = sum(
            1 for alert in alerts
            if alert["severity"] == 2
        )

        low = sum(
            1 for alert in alerts
            if alert["severity"] is not None
            and alert["severity"] >= 3
        )

        unique_sources = len({
            alert["source_ip"]
            for alert in alerts
            if alert["source_ip"]
        })

        attack_types = len({
            alert["attack"]
            for alert in alerts
            if alert["attack"]
        })

        return jsonify({
            "total_alerts": len(alerts),
            "high_alerts": high,
            "medium_alerts": medium,
            "low_alerts": low,
            "unique_source_ips": unique_sources,
            "attack_categories": attack_types
        })

    except sqlite3.Error as error:
        app.logger.error("Database error: %s", error)

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve statistics"
        }), 500


# ==========================================
# START VSEC SECURITY OPERATIONS
# ==========================================

if __name__ == "__main__":

    initialize_database()

    print("=" * 55)
    print("VSEC SECURITY OPERATIONS")
    print("=" * 55)

    print("Database:", DB_FILE)
    print("Session started:", SESSION_START)

    print("Live Dashboard: http://127.0.0.1:5000")
    print("Attack History: http://127.0.0.1:5000/history")

    print("Live API: http://127.0.0.1:5000/api/alerts")
    print("History API: http://127.0.0.1:5000/api/history")
    print("Statistics API: http://127.0.0.1:5000/api/stats")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
