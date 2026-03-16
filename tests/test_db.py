import time
from datetime import datetime, timezone

import pytest

from banhammer.db import EventDB


@pytest.fixture
def db(tmp_path):
    return EventDB(str(tmp_path / "banhammer.db"))


def test_insert_and_get_events(db):
    db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
    events = db.get_events(limit=50, offset=0)
    assert len(events) == 1
    assert events[0]["type"] == "ban"
    assert events[0]["jail"] == "sshd"
    assert events[0]["ip"] == "1.2.3.4"
    assert events[0]["timestamp"] == "2026-03-15T12:00:00Z"
    assert "id" in events[0]


def test_get_events_pagination(db):
    for i in range(10):
        db.insert_event("ban", "sshd", f"1.2.3.{i}", f"2026-03-15T12:0{i}:00Z")
    page1 = db.get_events(limit=3, offset=0)
    page2 = db.get_events(limit=3, offset=3)
    assert len(page1) == 3
    assert len(page2) == 3
    assert page1[0]["id"] != page2[0]["id"]


def test_get_events_returns_newest_first(db):
    db.insert_event("ban", "sshd", "1.1.1.1", "2026-03-15T10:00:00Z")
    db.insert_event("ban", "sshd", "2.2.2.2", "2026-03-15T12:00:00Z")
    events = db.get_events(limit=50, offset=0)
    assert events[0]["timestamp"] == "2026-03-15T12:00:00Z"
    assert events[1]["timestamp"] == "2026-03-15T10:00:00Z"


def test_get_events_total_count(db):
    for i in range(5):
        db.insert_event("ban", "sshd", f"1.2.3.{i}", f"2026-03-15T12:0{i}:00Z")
    total = db.count_events()
    assert total == 5


def test_dedup_identical_events(db):
    db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
    db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
    assert db.count_events() == 1


def test_different_types_not_deduped(db):
    db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
    db.insert_event("unban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
    assert db.count_events() == 2


def test_top_attackers(db):
    for _ in range(5):
        db.insert_event("ban", "sshd", "1.2.3.4", f"2026-03-15T12:00:0{_}Z")
    for _ in range(3):
        db.insert_event("ban", "sshd", "5.6.7.8", f"2026-03-15T12:01:0{_}Z")
    attackers = db.top_attackers(limit=10)
    assert attackers[0]["ip"] == "1.2.3.4"
    assert attackers[0]["ban_count"] == 5
    assert attackers[1]["ip"] == "5.6.7.8"
    assert attackers[1]["ban_count"] == 3


def test_bans_by_jail(db):
    db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
    db.insert_event("ban", "sshd", "1.2.3.5", "2026-03-15T12:00:01Z")
    db.insert_event("ban", "postfix", "5.6.7.8", "2026-03-15T12:00:02Z")
    result = db.bans_by_jail()
    assert result["sshd"] == 2
    assert result["postfix"] == 1


def test_bans_since(db):
    now = time.time()
    # Insert event with created_at in the past (2 days ago)
    db._EventDB__execute(
        "INSERT INTO ban_events (type, jail, ip, timestamp, created_at) VALUES (?, ?, ?, ?, ?)",
        ("ban", "sshd", "1.1.1.1", "2026-03-13T12:00:00Z", now - 2 * 86400),
    )
    # Insert event with created_at now
    db.insert_event("ban", "sshd", "2.2.2.2", "2026-03-15T12:00:00Z")
    count_24h = db.bans_since(now - 86400)
    count_7d = db.bans_since(now - 7 * 86400)
    assert count_24h == 1
    assert count_7d == 2


def test_prune_old_events(db):
    now = time.time()
    # Insert old event (100 days ago)
    db._EventDB__execute(
        "INSERT INTO ban_events (type, jail, ip, timestamp, created_at) VALUES (?, ?, ?, ?, ?)",
        ("ban", "sshd", "1.1.1.1", "2025-12-01T12:00:00Z", now - 100 * 86400),
    )
    # Insert recent event
    db.insert_event("ban", "sshd", "2.2.2.2", "2026-03-15T12:00:00Z")
    db.prune(retention_days=90)
    assert db.count_events() == 1
    events = db.get_events(limit=50, offset=0)
    assert events[0]["ip"] == "2.2.2.2"


def test_save_and_get_latest_status(db):
    jails_data = {
        "sshd": {
            "active_bans": 2,
            "total_bans": 48,
            "banned_ips": ["1.2.3.4", "5.6.7.8"],
            "ip_details": {"1.2.3.4": ["log line 1"]},
        }
    }
    db.save_status(jails_data)
    status = db.get_latest_status()
    assert status is not None
    assert status["sshd"]["active_bans"] == 2
    assert status["sshd"]["banned_ips"] == ["1.2.3.4", "5.6.7.8"]


def test_get_latest_status_returns_none_when_empty(db):
    assert db.get_latest_status() is None


def test_db_size_bytes(db):
    db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
    size = db.size_bytes()
    assert size > 0
