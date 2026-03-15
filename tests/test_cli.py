import asyncio
import secrets
import textwrap
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from banhammer.cli import Agent, cmd_init


def _make_config(tmp_path):
    return {
        "api": {
            "bind": "127.0.0.1",
            "port": 18443,  # Use high port for tests
            "api_key": "bh_testapikey1234567890abcdef12",
        },
        "agent": {
            "server_id": "test-server",
            "poll_interval": 60,
            "heartbeat_interval": 300,
        },
        "fail2ban": {
            "log_path": str(tmp_path / "fail2ban.log"),
            "client_path": "/usr/bin/fail2ban-client",
        },
        "storage": {
            "db_path": str(tmp_path / "banhammer.db"),
            "retention_days": 90,
        },
    }


def test_agent_init_creates_db(tmp_path):
    (tmp_path / "fail2ban.log").write_text("")
    config = _make_config(tmp_path)
    agent = Agent(config)
    assert agent.db is not None


@patch("banhammer.cli.Poller")
def test_agent_enqueues_log_events_to_db(mock_poller_cls, tmp_path):
    log_file = tmp_path / "fail2ban.log"
    log_file.write_text("")  # Start with empty log
    config = _make_config(tmp_path)
    mock_poller_cls.return_value.poll.return_value = {}

    agent = Agent(config)

    # Append a log line AFTER tailer init (tailer seeks to EOF on init)
    with open(log_file, "a") as f:
        f.write("2026-03-15 06:09:12,345 fail2ban.actions        [1]: NOTICE  [sshd] Ban 1.2.3.4\n")

    # Run one monitoring cycle manually
    agent._monitor_once()

    assert agent.db.count_events() >= 1
    events = agent.db.get_events(limit=10, offset=0)
    ban_events = [e for e in events if e["type"] == "ban"]
    assert len(ban_events) >= 1
    assert ban_events[0]["ip"] == "1.2.3.4"


def test_cmd_init_generates_api_key(tmp_path, monkeypatch):
    config_dir = tmp_path / "etc"
    data_dir = tmp_path / "data"
    monkeypatch.setattr("banhammer.cli.CONFIG_DIR", config_dir)
    monkeypatch.setattr("banhammer.cli.DATA_DIR", data_dir)

    args = MagicMock()
    cmd_init(args)

    config_file = config_dir / "config.toml"
    assert config_file.exists()
    content = config_file.read_text()
    assert "[api]" in content
    assert "api_key" in content
    assert "bh_" in content
    # Should NOT have [backend]
    assert "[backend]" not in content
