import json
import os
import sqlite3
import time
import hashlib
from datetime import datetime, timezone

# ==========================================
# VSEC SECURITY OPERATIONS
# AUTOMATIC SURICATA ALERT COLLECTOR
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = "/var/log/suricata/eve.json"
DB_FILE = os.path.join(BASE_DIR, "vsec.db")


# ==========================================
# DATABASE CONNECTION
# ==========================================

def connect_db():
    return sqlite3.connect(DB_FILE, timeout=10)


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
                event_id TEXT UNIQUE,
                inserted_at TEXT
            )
        """)

        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(alerts)")
        }

        if "inserted_at" not in columns:
            conn.execute("""
                ALTER TABLE alerts
                ADD COLUMN inserted_at TEXT
            """)

        conn.commit()


# ==========================================
# GENERATE UNIQUE EVENT ID
# ==========================================

def generate_event_id(event):

    event_string = json.dumps(
        event,
        sort_keys=True
    )

    return hashlib.sha256(
        event_string.encode("utf-8")
    ).hexdigest()


# ==========================================
# SAVE ALERT TO SQLITE
# ==========================================

def save_alert(event):

    alert = event.get("alert", {})

    event_id = generate_event_id(event)

    inserted_at = datetime.now(
        timezone.utc
    ).isoformat()

    with connect_db() as conn:

        cursor = conn.execute("""
            INSERT OR IGNORE INTO alerts (
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
                event_id,
                inserted_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("src_ip"),
            event.get("dest_ip"),
            event.get("src_port"),
            event.get("dest_port"),
            event.get("proto"),
            alert.get("signature"),
            alert.get("severity"),
            alert.get("signature_id"),
            alert.get("category"),
            event_id,
            inserted_at
        ))

        conn.commit()

        return cursor.rowcount == 1


# ==========================================
# READ SURICATA ALERT LOG
# ==========================================

def collect_alerts():

    if not os.path.isfile(LOG_FILE):
        print("Suricata log file not found.")
        return 0

    inserted = 0

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                try:
                    event = json.loads(line)

                    if event.get("event_type") != "alert":
                        continue

                    if save_alert(event):
                        inserted += 1

                except json.JSONDecodeError:
                    continue

    except PermissionError:
        print("Permission denied reading Suricata logs.")

    return inserted


# ==========================================
# MAIN COLLECTOR LOOP
# ==========================================

if __name__ == "__main__":

    initialize_database()

    print("=" * 55)
    print("VSEC SECURITY OPERATIONS - ALERT COLLECTOR")
    print("=" * 55)

    print("Monitoring:", LOG_FILE)
    print("Database:", DB_FILE)

    try:

        while True:

            new_alerts = collect_alerts()

            if new_alerts > 0:
                print(
                    f"[VSEC] Stored {new_alerts} new alerts"
                )

            time.sleep(3)

    except KeyboardInterrupt:
        print("\nVSEC Collector stopped.")
