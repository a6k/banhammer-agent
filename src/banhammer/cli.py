import argparse
import asyncio
import logging
import os
import secrets
import signal
import socket
import sys
import tempfile
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

import uvicorn

from banhammer.api import create_app, resolve_server_location
from banhammer.config import load_config
from banhammer.db import EventDB
from banhammer.geo import GeoIPService
from banhammer.log_tailer import LogTailer
from banhammer.poller import Poller
from banhammer.geodb_updater import check_and_update, download_geodb
from banhammer.websocket import WebSocketManager

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
        self.poller = Poller(
            config["fail2ban"]["client_path"],
            use_sudo=config["fail2ban"].get("use_sudo", False),
        )
        geo_config = config.get("geo", {})
        self.geo = GeoIPService(
            db_path=geo_config.get("geoip_db_path"),
            allow_http_fallback=geo_config.get("allow_http_fallback", False),
        )
        self.server_id = config["agent"]["server_id"]
        self._last_poll = 0.0
        self._last_heartbeat = 0.0
        self.ws_manager = WebSocketManager()
        self._loop = None

    def _monitor_once(self):
        """Run one monitoring cycle: tail log + poll fail2ban."""
        now = time.time()
        poll_interval = self.config["agent"]["poll_interval"]

        # Tail log for new ban/unban events
        for event in self.tailer.poll():
            # Skip events for whitelisted IPs
            if self.db.whitelist_contains(event["ip"]):
                continue
            geo = self.geo.lookup(event["ip"])
            geo_kwargs = {}
            if geo:
                geo_kwargs = {
                    "lat": geo["lat"], "lon": geo["lon"],
                    "country_code": geo["country_code"],
                    "country_name": geo["country_name"],
                    "city": geo["city"],
                }
            self.db.insert_event(
                event_type=event["type"],
                jail=event["jail"],
                ip=event["ip"],
                timestamp=event["timestamp"].isoformat(),
                **geo_kwargs,
            )
            # Broadcast new event via WebSocket
            if self._loop:
                event_data = {
                    "type": event["type"],
                    "jail": event["jail"],
                    "ip": event["ip"],
                    "timestamp": event["timestamp"].isoformat(),
                }
                if geo:
                    event_data.update(geo)
                asyncio.run_coroutine_threadsafe(
                    self.ws_manager.broadcast("ban_event", event_data), self._loop
                )

        # Poll fail2ban-client periodically
        if now - self._last_poll >= poll_interval:
            try:
                jails = self.poller.poll()
                self.db.save_status(jails)
                self._last_poll = now
                # Broadcast status update via WebSocket
                if self._loop:
                    asyncio.run_coroutine_threadsafe(
                        self.ws_manager.broadcast("status_update", jails), self._loop
                    )
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
        self._loop = asyncio.get_event_loop()

        # Auto-update GeoLite2 DB if needed
        geo_config = self.config.get("geo", {})
        db_path = geo_config.get("geoip_db_path")
        license_key = geo_config.get("maxmind_license_key")
        if db_path:
            await asyncio.to_thread(check_and_update, db_path, license_key)

        # Resolve server location in a thread to avoid blocking the event loop
        server_location = None
        if self.geo:
            server_location = await asyncio.to_thread(resolve_server_location, self.geo)

        # Create FastAPI app
        app = create_app(
            db=self.db,
            server_id=self.server_id,
            api_key=self.config["api"]["api_key"],
            poller=self.poller,
            path_prefix=self.config["api"].get("path_prefix", ""),
            geo_service=self.geo,
            ws_manager=self.ws_manager,
            server_location=server_location,
        )

        # Configure uvicorn
        uvicorn_config = uvicorn.Config(
            app=app,
            host=self.config["api"]["bind"],
            port=self.config["api"]["port"],
            log_level="info",
            access_log=False,
            server_header=False,
            date_header=False,
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
            loop.add_signal_handler(sig, lambda s=server: self._shutdown(s))

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
        if not self.running:
            return  # Already shutting down — prevent double geo.close() on double signal
        logger.info("Shutdown signal received")
        self.running = False
        self.geo.close()
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
    path_prefix = "/" + secrets.token_hex(6)

    config_content = textwrap.dedent(f"""\
        [api]
        bind = "127.0.0.1"
        port = 8443
        api_key = "{api_key}"
        path_prefix = "{path_prefix}"
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

    # Write atomically: set permissions before content to avoid a window
    # where the file is world-readable (write_text uses umask-derived perms).
    fd, tmp_path = tempfile.mkstemp(dir=config_dir)
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(config_content)
        os.replace(tmp_path, config_file)
    except Exception:
        os.unlink(tmp_path)
        raise
    print(f"Config written to {config_file}")
    print(f"Data directory: {data_dir}")
    print(f"API key and path prefix written to {config_file} (readable only by root).")
    print(f"Agent API will be available at https://your-server{path_prefix}/api/v1/health")
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


def cmd_backfill(args):
    """Backfill geo data for existing events missing geo info."""
    config = load_config(args.config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    db_inst = EventDB(config["storage"]["db_path"])
    geo_config = config.get("geo", {})
    geo = GeoIPService(
        db_path=geo_config.get("geoip_db_path"),
        allow_http_fallback=geo_config.get("allow_http_fallback", False),
    )

    # Process in batches with cursor-based pagination to avoid OOM and skipping
    BATCH = 500
    total = 0
    updated = 0
    cursor = 0
    while True:
        rows = db_inst.get_events_missing_geo(limit=BATCH, min_id=cursor)
        if not rows:
            break
        total += len(rows)
        logger.info("Processing batch of %d events (%d total so far)", len(rows), total)
        for event_id, ip in rows:
            result = geo.lookup(ip)
            if result:
                db_inst.update_event_geo(
                    event_id, lat=result["lat"], lon=result["lon"],
                    country_code=result["country_code"],
                    country_name=result["country_name"], city=result["city"],
                )
                updated += 1
            cursor = max(cursor, event_id)

    logger.info("Backfill complete: %d/%d events enriched", updated, total)
    print(f"Backfill complete: {updated}/{total} events enriched with geo data")


def cmd_update_geodb(args):
    config = load_config(args.config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    geo_config = config.get("geo", {})
    db_path = geo_config.get("geoip_db_path")
    license_key = geo_config.get("maxmind_license_key")
    if not db_path:
        print("Error: geo.geoip_db_path not configured")
        return
    if not license_key:
        print("Error: geo.maxmind_license_key not configured")
        return
    if download_geodb(license_key, db_path):
        print(f"GeoLite2 database updated: {db_path}")
    else:
        print("Failed to update GeoLite2 database")


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
    subparsers.add_parser("backfill-geo", help="Backfill geo data for existing events")
    subparsers.add_parser("update-geodb", help="Download/update GeoLite2 database")

    args = parser.parse_args()

    commands = {
        "run": cmd_run,
        "init": cmd_init,
        "status": cmd_status,
        "backfill-geo": cmd_backfill,
        "update-geodb": cmd_update_geodb,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
