from banhammer.queue import EventQueue


def test_enqueue_and_dequeue(tmp_path):
    db_path = str(tmp_path / "queue.db")
    q = EventQueue(db_path, max_events=100)
    event = {"type": "ban", "server_id": "test", "jail": "sshd", "ip": "1.2.3.4"}
    q.enqueue(event)
    events = q.dequeue(10)
    assert len(events) == 1
    assert events[0][1]["type"] == "ban"


def test_dequeue_returns_empty_when_no_events(tmp_path):
    db_path = str(tmp_path / "queue.db")
    q = EventQueue(db_path, max_events=100)
    events = q.dequeue(10)
    assert events == []


def test_remove_after_successful_send(tmp_path):
    db_path = str(tmp_path / "queue.db")
    q = EventQueue(db_path, max_events=100)
    q.enqueue({"type": "ban", "ip": "1.2.3.4"})
    events = q.dequeue(10)
    event_id = events[0][0]
    q.remove([event_id])
    assert q.count() == 0


def test_count(tmp_path):
    db_path = str(tmp_path / "queue.db")
    q = EventQueue(db_path, max_events=100)
    assert q.count() == 0
    q.enqueue({"type": "ban", "ip": "1.1.1.1"})
    q.enqueue({"type": "ban", "ip": "2.2.2.2"})
    assert q.count() == 2


def test_eviction_when_max_exceeded(tmp_path):
    db_path = str(tmp_path / "queue.db")
    q = EventQueue(db_path, max_events=3)
    for i in range(5):
        q.enqueue({"type": "ban", "ip": f"1.1.1.{i}"})
    assert q.count() == 3
    events = q.dequeue(10)
    ips = [e[1]["ip"] for e in events]
    assert "1.1.1.2" in ips
    assert "1.1.1.3" in ips
    assert "1.1.1.4" in ips
    assert "1.1.1.0" not in ips


def test_dedup_identical_events(tmp_path):
    db_path = str(tmp_path / "queue.db")
    q = EventQueue(db_path, max_events=100)
    event = {
        "type": "ban",
        "jail": "sshd",
        "ip": "1.2.3.4",
        "timestamp": "2026-03-15T06:09:12+00:00",
    }
    q.enqueue(event)
    q.enqueue(event)
    assert q.count() == 1
