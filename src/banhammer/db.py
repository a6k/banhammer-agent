import json
import sqlite3
import threading
import time
from pathlib import Path


class EventDB:
    """SQLite permanent storage for ban/unban events and status snapshots."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS ban_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type TEXT NOT NULL,
                        jail TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        UNIQUE(type, jail, ip, timestamp)
                    )"""
                )
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS status_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        data TEXT NOT NULL,
                        created_at REAL NOT NULL
                    )"""
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_created_at ON ban_events(created_at)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_type ON ban_events(type)"
                )

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Low-level execute for tests and internal use."""
        with self._lock:
            with self._connect() as conn:
                return conn.execute(sql, params)

    def insert_event(self, event_type: str, jail: str, ip: str, timestamp: str):
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO ban_events (type, jail, ip, timestamp, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (event_type, jail, ip, timestamp, time.time()),
                    )
                except sqlite3.IntegrityError:
                    pass  # Duplicate event, skip

    def get_events(self, limit: int = 50, offset: int = 0) -> list[dict]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, type, jail, ip, timestamp FROM ban_events "
                    "ORDER BY id DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [
            {"id": r[0], "type": r[1], "jail": r[2], "ip": r[3], "timestamp": r[4]}
            for r in rows
        ]

    def count_events(self) -> int:
        with self._lock:
            with self._connect() as conn:
                return conn.execute("SELECT COUNT(*) FROM ban_events").fetchone()[0]

    def top_attackers(self, limit: int = 10) -> list[dict]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT ip, COUNT(*) as ban_count FROM ban_events "
                    "WHERE type = 'ban' GROUP BY ip ORDER BY ban_count DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [{"ip": r[0], "ban_count": r[1]} for r in rows]

    def bans_by_jail(self) -> dict[str, int]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT jail, COUNT(*) FROM ban_events "
                    "WHERE type = 'ban' GROUP BY jail"
                ).fetchall()
        return {r[0]: r[1] for r in rows}

    def bans_since(self, since_timestamp: float) -> int:
        with self._lock:
            with self._connect() as conn:
                return conn.execute(
                    "SELECT COUNT(*) FROM ban_events WHERE type = 'ban' AND created_at >= ?",
                    (since_timestamp,),
                ).fetchone()[0]

    def prune(self, retention_days: int):
        cutoff = time.time() - (retention_days * 86400)
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM ban_events WHERE created_at < ?", (cutoff,))

    def save_status(self, jails_data: dict):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO status_snapshots (data, created_at) VALUES (?, ?)",
                    (json.dumps(jails_data), time.time()),
                )
                # Keep only the latest snapshot
                conn.execute(
                    "DELETE FROM status_snapshots WHERE id NOT IN "
                    "(SELECT id FROM status_snapshots ORDER BY id DESC LIMIT 1)"
                )

    def get_latest_status(self) -> dict | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT data FROM status_snapshots ORDER BY id DESC LIMIT 1"
                ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def size_bytes(self) -> int:
        return Path(self.db_path).stat().st_size
