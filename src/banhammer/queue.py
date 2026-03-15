import hashlib
import json
import sqlite3
import threading
import time


class EventQueue:
    def __init__(self, db_path: str, max_events: int = 10000):
        self.db_path = db_path
        self.max_events = max_events
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_hash TEXT UNIQUE,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _hash_event(self, event: dict) -> str:
        if event.get("type") in ("ban", "unban"):
            key = json.dumps(
                {
                    "type": event.get("type"),
                    "jail": event.get("jail"),
                    "ip": event.get("ip"),
                    "timestamp": event.get("timestamp"),
                },
                sort_keys=True,
            )
        else:
            key = json.dumps(event, sort_keys=True)
        return hashlib.sha256(key.encode()).hexdigest()

    def enqueue(self, event: dict):
        event_hash = self._hash_event(event)
        payload = json.dumps(event)
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO events (event_hash, payload, created_at) VALUES (?, ?, ?)",
                        (event_hash, payload, time.time()),
                    )
                except sqlite3.IntegrityError:
                    return
                self._evict(conn)

    def _evict(self, conn: sqlite3.Connection):
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count > self.max_events:
            excess = count - self.max_events
            conn.execute(
                "DELETE FROM events WHERE id IN "
                "(SELECT id FROM events ORDER BY id ASC LIMIT ?)",
                (excess,),
            )

    def dequeue(self, batch_size: int) -> list[tuple[int, dict]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, payload FROM events ORDER BY id ASC LIMIT ?",
                    (batch_size,),
                ).fetchall()
        return [(row[0], json.loads(row[1])) for row in rows]

    def remove(self, event_ids: list[int]):
        with self._lock:
            with self._connect() as conn:
                placeholders = ",".join("?" for _ in event_ids)
                conn.execute(
                    f"DELETE FROM events WHERE id IN ({placeholders})",
                    event_ids,
                )

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
