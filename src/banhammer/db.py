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
                        lat REAL,
                        lon REAL,
                        country_code TEXT,
                        country_name TEXT,
                        city TEXT,
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
                # Migration: add geo columns to existing DBs
                existing_cols = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info(ban_events)").fetchall()
                }
                for col, col_type in [
                    ("lat", "REAL"),
                    ("lon", "REAL"),
                    ("country_code", "TEXT"),
                    ("country_name", "TEXT"),
                    ("city", "TEXT"),
                ]:
                    if col not in existing_cols:
                        conn.execute(f"ALTER TABLE ban_events ADD COLUMN {col} {col_type}")

    def _insert_with_timestamp(
        self,
        event_type: str,
        jail: str,
        ip: str,
        timestamp: str,
        created_at: float,
        *,
        lat=None,
        lon=None,
        country_code=None,
        country_name=None,
        city=None,
    ):
        """Insert a ban event with an explicit created_at — for testing only."""
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO ban_events "
                        "(type, jail, ip, timestamp, created_at, lat, lon, country_code, country_name, city) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (event_type, jail, ip, timestamp, created_at, lat, lon, country_code, country_name, city),
                    )
                except sqlite3.IntegrityError:
                    pass  # Duplicate event, skip

    def insert_event(
        self,
        event_type: str,
        jail: str,
        ip: str,
        timestamp: str,
        *,
        lat=None,
        lon=None,
        country_code=None,
        country_name=None,
        city=None,
    ):
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO ban_events "
                        "(type, jail, ip, timestamp, created_at, lat, lon, country_code, country_name, city) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (event_type, jail, ip, timestamp, time.time(), lat, lon, country_code, country_name, city),
                    )
                except sqlite3.IntegrityError:
                    pass  # Duplicate event, skip

    def get_events(self, limit: int = 50, offset: int = 0) -> list[dict]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, type, jail, ip, timestamp, lat, lon, country_code, country_name, city "
                    "FROM ban_events "
                    "ORDER BY id DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [
            {
                "id": r[0],
                "type": r[1],
                "jail": r[2],
                "ip": r[3],
                "timestamp": r[4],
                "lat": r[5],
                "lon": r[6],
                "country_code": r[7],
                "country_name": r[8],
                "city": r[9],
            }
            for r in rows
        ]

    def get_events_missing_geo(self) -> list[tuple[int, str]]:
        """Return (id, ip) for events where country_code IS NULL."""
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, ip FROM ban_events WHERE country_code IS NULL"
                ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def update_event_geo(
        self,
        event_id: int,
        *,
        lat,
        lon,
        country_code,
        country_name,
        city,
    ):
        """Update geo fields for one event."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE ban_events SET lat=?, lon=?, country_code=?, country_name=?, city=? "
                    "WHERE id=?",
                    (lat, lon, country_code, country_name, city, event_id),
                )

    def count_events(self) -> int:
        with self._lock:
            with self._connect() as conn:
                return conn.execute("SELECT COUNT(*) FROM ban_events").fetchone()[0]

    def top_attackers(self, limit: int = 10) -> list[dict]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT ip, COUNT(*) as ban_count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen "
                    "FROM ban_events "
                    "WHERE type = 'ban' GROUP BY ip ORDER BY ban_count DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [
            {"ip": r[0], "ban_count": r[1], "first_seen": r[2], "last_seen": r[3]}
            for r in rows
        ]

    def timeline_buckets(self, period: str = "24h") -> list[dict]:
        """Return ban counts grouped by hour and jail for the given period."""
        hours_map = {"24h": 24, "7d": 168, "30d": 720}
        hours = hours_map.get(period, 24)
        cutoff = time.time() - hours * 3600
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour, jail, COUNT(*) as cnt "
                    "FROM ban_events "
                    "WHERE created_at >= ? "
                    "GROUP BY hour, jail "
                    "ORDER BY hour ASC",
                    (cutoff,),
                ).fetchall()
        # Aggregate into buckets keyed by hour
        buckets: dict[str, dict] = {}
        for hour, jail, cnt in rows:
            if hour not in buckets:
                buckets[hour] = {"timestamp": hour, "total": 0, "by_jail": {}}
            buckets[hour]["total"] += cnt
            buckets[hour]["by_jail"][jail] = cnt
        return list(buckets.values())

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
        p = Path(self.db_path)
        return p.stat().st_size if p.exists() else 0
