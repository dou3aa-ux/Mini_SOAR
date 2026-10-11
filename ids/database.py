import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from config import DB_PATH


DEFAULT_DB_PATH = DB_PATH


def init_db(db_path=DEFAULT_DB_PATH):
    db_path = DB_PATH if db_path is None else db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(db_path)) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )
            """)


def save_alerts(alerts, db_path=DEFAULT_DB_PATH):
    init_db(db_path)
    saved_ids = []

    with closing(sqlite3.connect(db_path)) as connection:
        with connection:
            for alert in alerts:
                cursor = connection.execute(
                    """
                    INSERT INTO alerts (
                        alert_type,
                        severity,
                        source_ip,
                        destination_ip,
                        description,
                        created_at,
                        details_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert["type"],
                        alert["severity"],
                        alert.get("source_ip"),
                        alert.get("destination_ip"),
                        alert["description"],
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        json.dumps(alert),
                    ),
                )
                saved_ids.append(cursor.lastrowid)

    return saved_ids


def get_recent_alerts(limit=100, db_path=DEFAULT_DB_PATH):
    init_db(db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                id,
                alert_type,
                severity,
                source_ip,
                destination_ip,
                description,
                created_at,
                details_json
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    alerts = []
    for row in rows:
        alert = dict(row)
        alert["details"] = json.loads(alert.pop("details_json"))
        alerts.append(alert)

    return alerts


def get_alert_by_id(alert_id, db_path=DEFAULT_DB_PATH):
    init_db(db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT
                id,
                alert_type,
                severity,
                source_ip,
                destination_ip,
                description,
                created_at,
                details_json
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()

    if row is None:
        return None

    alert = dict(row)
    alert["details"] = json.loads(alert.pop("details_json"))
    return alert