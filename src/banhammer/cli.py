import argparse
import asyncio
import logging
import os
import secrets
import signal
import socket
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

import uvicorn

from banhammer.api import create_app
from banhammer.config import load_config
from banhammer.db import EventDB
from banhammer.log_tailer import LogTailer
from banhammer.models import BanEvent
from banhammer.poller import Poller

logger = logging.getLogger("banhammer")

DEFAULT_CONFIG_PATH = "/etc/banhammer/config.toml"
CONFIG_DIR = Path("/etc/banhammer")
DATA_DIR = Path("/var/lib/banhammer")


class Agent:
    def __init__(self, config: dict):
        self.config = config
        self.running = False
        self.db = EventDB(config["storage"]["db_path"])
        self.tailer = LogTailer(config["fail2ban"]["log_path"])
        self.poller = Poller(config["fail2ban"]["client_path"])
        self.server_id = config["agent"]["server_id"]
        self._last_poll = 0.0
        self._last_heartbeat = 0.0

    def _monitor_once(self):
        """Run one monitoring cycle: tail log + poll fail2ban."""
        now = time.time()
        poll_interval = self.config["agent"]["poll_interval"]

        # Tail log for new ban/unban events
        for event in self.tailer.poll():
            self.db.insert_event(
                event_type=event["type"],
                jail=event["jail"],
                ip=event["ip"],
                timestamp=event["timestamp"].isoformat(),
            )

        # Poll fail2ban-client periodically
        if now - self._last_poll >= poll_interval:
            try:
                jails = self.poller.poll()
                self.db.save_status(jails)
                self._last_poll = now
            except Exception:
                logger.warning("Polling fail2ban-client failed", exc_info=True)

            # Prune old events
            retention_days = self.config["storage"]["retention_days"]
            self.db.prune(retention_days)

    async def _monitoring_loop(self):
        """Async monitoring loop that runs blocking calls in a thread."""
        logger.info("Monitoring loop started (server_id=%s)", self.server_id)
        while self.running:
            try:
                await asyncio.to_thread(self._monitor_once)
            except Exception:
                logger.warning("Monitoring cycle failed", exc_info=True)
            await asyncio.sleep(1)
        logger.info("Monitoring loop stopped")

    async def run_async(self):
        """Start monitoring loop + FastAPI server concurrently."""
        self.running = True

        # Create FastAPI app
        app = create_app(
            db=self.db,
            server_id=self.server_id,
            api_key=self.config["api"]["api_key"],
            poller=self.poller,
        )

        # Configure uvicorn
        uvicorn_config = uvicorn.Config(
            app=app,
            host=self.config["api"]["bind"],
            port=self.config["api"]["port"],
            log_level="info",
        )

        # Add TLS if configured
        tls_cert = self.config["api"].get("tls_cert")
        tls_key = self.config["api"].get("tls_key")
        if tls_cert and tls_key:
            uvicorn_config.ssl_certfile = tls_cert
            uvicorn_config.ssl_keyfile = tls_key

        server = uvicorn.Server(uvicorn_config)

        # Handle shutdown signals
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: self._shutdown(server))

        logger.info(
            "API server starting on %s:%d",
            self.config["api"]["bind"],
            self.config["api"]["port"],
        )

        # Run both concurrently
        await asyncio.gather(
            self._monitoring_loop(),
            server.serve(),
        )

    def _shutdown(self, server):
        logger.info("Shutdown signal received")
        self.running = False
        server.should_exit = True

    def run(self):
        """Synchronous entry point."""
        asyncio.run(self.run_async())


def cmd_run(args):
    config = load_config(args.config)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    agent = Agent(config)
    agent.run()


def cmd_init(args):
    config_dir = CONFIG_DIR
    config_file = config_dir / "config.toml"
    data_dir = DATA_DIR

    if config_file.exists():
        print(f"Config already exists: {config_file}")
        return

    config_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    api_key = "bh_" + secrets.token_hex(16)

    config_content = textwrap.dedent(f"""\
        [api]
        bind = "127.0.0.1"
        port = 8443
        api_key = "{api_key}"
        # tls_cert = "/etc/banhammer/cert.pem"
        # tls_key = "/etc/banhammer/key.pem"

        [agent]
        server_id = "{socket.gethostname()}"
        poll_interval = 60
        heartbeat_interval = 300

        [fail2ban]
        log_path = "/var/log/fail2ban.log"
        client_path = "/usr/bin/fail2ban-client"

        [storage]
        db_path = "/var/lib/banhammer/banhammer.db"
        retention_days = 90
    """)

    config_file.write_text(config_content)
    os.chmod(config_file, 0o600)
    print(f"Config written to {config_file}")
    print(f"Data directory: {data_dir}")
    print(f"API Key: {api_key}")
    print(f"Agent API will be available at https://your-server:8443/")
    print("Start the agent with: banhammer-agent run")


def cmd_status(args):
    config = load_config(args.config)
    db = EventDB(config["storage"]["db_path"])

    event_count = db.count_events()
    db_size = db.size_bytes()
    server_id = config["agent"]["server_id"]
    bind = config["api"]["bind"]
    port = config["api"]["port"]

    print(f"Server ID: {server_id}")
    print(f"Events in DB: {event_count}")
    print(f"DB size: {db_size / 1024:.1f} KB")
    print(f"API: {bind}:{port}")


def main():
    parser = argparse.ArgumentParser(
        prog="banhammer-agent",
        description="BanHammer Agent — Fail2Ban monitor + API",
    )
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Config file path (default: {DEFAULT_CONFIG_PATH})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Start monitoring + API server")
    subparsers.add_parser("init", help="Initialize configuration")
    subparsers.add_parser("status", help="Show agent status")

    args = parser.parse_args()

    commands = {
        "run": cmd_run,
        "init": cmd_init,
        "status": cmd_status,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
