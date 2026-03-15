import threading
import time
from unittest.mock import patch

from banhammer.cli import Agent


def _make_config(tmp_path):
    return {
        "backend": {"url": "https://example.com/events", "api_key": "bh_test"},
        "agent": {
            "server_id": "test-server",
            "poll_interval": 60,
            "heartbeat_interval": 300,
            "batch_size": 50,
            "retry_max": 3,
            "retry_backoff": 2,
        },
        "fail2ban": {
            "log_path": str(tmp_path / "fail2ban.log"),
            "client_path": "/usr/bin/fail2ban-client",
        },
        "storage": {
            "queue_db": str(tmp_path / "queue.db"),
            "queue_max_events": 1000,
        },
    }


def test_agent_stops_on_signal(tmp_path):
    (tmp_path / "fail2ban.log").write_text("")
    config = _make_config(tmp_path)
    agent = Agent(config)

    def stop_agent():
        time.sleep(0.5)
        agent.running = False

    t = threading.Thread(target=stop_agent)
    t.start()
    agent.run()
    t.join()
    assert not agent.running


@patch("banhammer.cli.Poller")
def test_agent_enqueues_log_events(mock_poller_cls, tmp_path):
    log_file = tmp_path / "fail2ban.log"
    log_file.write_text(
        "2026-03-15 06:09:12,345 fail2ban.actions        [1]: NOTICE  [sshd] Ban 1.2.3.4\n"
    )
    config = _make_config(tmp_path)
    mock_poller_cls.return_value.poll.return_value = {}

    agent = Agent(config)

    def stop_agent():
        time.sleep(0.5)
        agent.running = False

    t = threading.Thread(target=stop_agent)
    t.start()
    agent.run()
    t.join()
    assert agent.queue.count() >= 1
