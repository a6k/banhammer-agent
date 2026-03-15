from datetime import datetime, timezone

from banhammer.models import BanEvent, UnbanEvent


def test_ban_event_to_dict():
    ts = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
    event = BanEvent(server_id="test", jail="sshd", ip="1.2.3.4", timestamp=ts)
    d = event.to_dict()
    assert d["type"] == "ban"
    assert d["jail"] == "sshd"
    assert d["ip"] == "1.2.3.4"


def test_unban_event_to_dict():
    ts = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
    event = UnbanEvent(server_id="test", jail="sshd", ip="1.2.3.4", timestamp=ts)
    d = event.to_dict()
    assert d["type"] == "unban"
