import argparse
import logging
import os
import signal
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

from banhammer.config import load_config
from banhammer.log_tailer import LogTailer
from banhammer.models import HeartbeatEvent, StatusEvent
from banhammer.poller import Poller
from banhammer.queue import EventQueue
from banhammer.sender import Sender

logger = logging.getLogger("banhammer")

DEFAULT_CONFIG_PATH = "/etc/banhammer/config.toml"


class Agent:
    def __init__(self, config: dict):
        self.config = config
        self.running = False
        self.queue = EventQueue(
            config["storage"]["queue_db"],
            max_events=config["storage"]["queue_max_events"],
        )
        self.tailer = LogTailer(config["fail2ban"]["log_path"])
        self.poller = Poller(config["fail2ban"]["client_path"])
        self.sender = Sender(
            url=config["backend"]["url"],
            api_key=config["backend"]["api_key"],
            batch_size=config["agent"]["batch_size"],
            retry_max=config["agent"]["retry_max"],
            retry_backoff=config["agent"]["retry_backoff"],
            ca_bundle=config["backend"].get("ca_bundle"),
        )
        self.server_id = config["agent"]["server_id"]

    def run(self):
        self.running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        logger.info("BanHammer agent started (server_id=%s)", self.server_id)

        last_poll = 0.0
        last_heartbeat = 0.0
        poll_interval = self.config["agent"]["poll_interval"]
        heartbeat_interval = self.config["agent"]["heartbeat_interval"]

        while self.running:
            now = time.time()

            # Tail log for new events
            for event in self.tailer.poll():
                event_dict = {
                    "server_id": self.server_id,
                    "type": event["type"],
                    "jail": event["jail"],
                    "ip": event["ip"],
                    "timestamp": event["timestamp"].isoformat(),
                }
                self.queue.enqueue(event_dict)

            # Poll fail2ban-client
            if now - last_poll >= poll_interval:
                try:
                    jails = self.poller.poll()
                    status = StatusEvent(
                        server_id=self.server_id,
                        timestamp=datetime.now(timezone.utc),
                        jails=jails,
                    )
                    self.queue.enqueue(status.to_dict())
                    last_poll = now
                except Exception:
                    logger.warning("Polling fail2ban-client failed", exc_info=True)

            # Heartbeat
            if now - last_heartbeat >= heartbeat_interval:
                heartbeat = HeartbeatEvent(
                    server_id=self.server_id,
                    timestamp=datetime.now(timezone.utc),
                )
                self.queue.enqueue(heartbeat.to_dict())
                last_heartbeat = now

            # Send queued events
            events = self.queue.dequeue(self.config["agent"]["batch_size"])
            if events:
                sent_ids = self.sender.send_batch(events)
                if sent_ids:
                    self.queue.remove(sent_ids)

            time.sleep(1)

        logger.info("BanHammer agent stopped")

    def _handle_signal(self, signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        self.running = False


def cmd_run(args):
    config = load_config(args.config)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    agent = Agent(config)
    agent.run()


def cmd_init(args):
    config_dir = Path("/etc/banhammer")
    config_file = config_dir / "config.toml"
    data_dir = Path("/var/lib/banhammer")

    if config_file.exists():
        print(f"Config already exists: {config_file}")
        return

    config_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    url = input("Backend URL: ").strip()
    api_key = input("API Key: ").strip()

    import socket

    config_content = textwrap.dedent(f"""\
        [backend]
        url = "{url}"
        api_key = "{api_key}"

        [agent]
        server_id = "{socket.gethostname()}"
        poll_interval = 60
        heartbeat_interval = 300
        batch_size = 50
        retry_max = 5
        retry_backoff = 2

        [fail2ban]
        log_path = "/var/log/fail2ban.log"
        client_path = "/usr/bin/fail2ban-client"

        [storage]
        queue_db = "/var/lib/banhammer/queue.db"
        queue_max_events = 10000
    """)

    config_file.write_text(config_content)
    os.chmod(config_file, 0o600)
    print(f"Config written to {config_file}")
    print(f"Data directory: {data_dir}")
    print("Start the agent with: banhammer-agent run")


def cmd_status(args):
    config = load_config(args.config)
    queue = EventQueue(
        config["storage"]["queue_db"],
        max_events=config["storage"]["queue_max_events"],
    )
    count = queue.count()
    print(f"Queue: {count} pending events")
    print(f"Backend: {config['backend']['url']}")
    print(f"Server ID: {config['agent']['server_id']}")


def cmd_test(args):
    config = load_config(args.config)
    sender = Sender(
        url=config["backend"]["url"],
        api_key=config["backend"]["api_key"],
        batch_size=1,
        retry_max=1,
        retry_backoff=1,
        ca_bundle=config["backend"].get("ca_bundle"),
    )
    test_event = {
        "server_id": config["agent"]["server_id"],
        "type": "heartbeat",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    sent = sender.send_batch([(0, test_event)])
    if sent:
        print("Test event sent successfully!")
    else:
        print("Failed to send test event. Check your config and backend.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="banhammer-agent",
        description="BanHammer Agent — Fail2Ban monitor",
    )
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Config file path (default: {DEFAULT_CONFIG_PATH})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Start the agent")
    subparsers.add_parser("init", help="Initialize configuration")
    subparsers.add_parser("status", help="Show agent status")
    subparsers.add_parser("test", help="Send a test event")

    args = parser.parse_args()

    commands = {
        "run": cmd_run,
        "init": cmd_init,
        "status": cmd_status,
        "test": cmd_test,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
