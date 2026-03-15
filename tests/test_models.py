import json
from datetime import datetime, timezone

from banhammer.models import BanEvent, UnbanEvent, StatusEvent, HeartbeatEvent


def test_ban_event_to_dict():
    event = BanEvent(
        server_id="mail.voodoo.re",
        jail="sshd",
        ip="203.0.113.42",
        timestamp=datetime(2026, 3, 15, 6, 9, 12, tzinfo=timezone.utc),
    )
    d = event.to_dict()
    assert d["type"] == "ban"
    assert d["server_id"] == "mail.voodoo.re"
    assert d["jail"] == "sshd"
    assert d["ip"] == "203.0.113.42"
    assert d["timestamp"] == "2026-03-15T06:09:12+00:00"


def test_unban_event_to_dict():
    event = UnbanEvent(
        server_id="mail.voodoo.re",
        jail="sshd",
        ip="203.0.113.42",
        timestamp=datetime(2026, 3, 15, 6, 19, 12, tzinfo=timezone.utc),
    )
    d = event.to_dict()
    assert d["type"] == "unban"
    assert d["ip"] == "203.0.113.42"


def test_status_event_to_dict():
    event = StatusEvent(
        server_id="mail.voodoo.re",
        timestamp=datetime(2026, 3, 15, 6, 10, 0, tzinfo=timezone.utc),
        jails={
            "sshd": {"active_bans": 3, "total_bans": 127},
            "postfix": {"active_bans": 1, "total_bans": 45},
        },
    )
    d = event.to_dict()
    assert d["type"] == "status"
    assert d["jails"]["sshd"]["active_bans"] == 3


def test_heartbeat_event_to_dict():
    event = HeartbeatEvent(
        server_id="mail.voodoo.re",
        timestamp=datetime(2026, 3, 15, 6, 15, 0, tzinfo=timezone.utc),
    )
    d = event.to_dict()
    assert d["type"] == "heartbeat"
    assert d["server_id"] == "mail.voodoo.re"


def test_event_to_json_serializable():
    event = BanEvent(
        server_id="test",
        jail="sshd",
        ip="1.2.3.4",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    result = json.dumps(event.to_dict())
    assert '"type": "ban"' in result
