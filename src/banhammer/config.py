import logging
import os
import socket
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

logger = logging.getLogger("banhammer")

DEFAULTS = {
    "api": {
        "bind": "127.0.0.1",
        "port": 8443,
    },
    "agent": {
        "poll_interval": 60,
        "heartbeat_interval": 300,
    },
    "fail2ban": {
        "log_path": "/var/log/fail2ban.log",
        "client_path": "/usr/bin/fail2ban-client",
    },
    "storage": {
        "db_path": "/var/lib/banhammer/banhammer.db",
        "retention_days": 90,
    },
}


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        config = tomllib.load(f)

    # Warn about old [backend] section
    if "backend" in config:
        logger.warning(
            "[backend] section found in config — ignored. "
            "The agent no longer uses an external backend. "
            "Please remove the [backend] section from your config."
        )

    # Apply defaults
    for section, defaults in DEFAULTS.items():
        if section not in config:
            config[section] = {}
        for key, value in defaults.items():
            config[section].setdefault(key, value)

    # Ensure [api] section exists
    if "api" not in config:
        config["api"] = {}

    # API key from env overrides config
    env_key = os.environ.get("BANHAMMER_API_KEY")
    if env_key:
        config["api"]["api_key"] = env_key

    # Validate required: api.api_key
    if not config["api"].get("api_key"):
        raise ValueError(
            "Missing required config: api.api_key "
            "(set in config file or BANHAMMER_API_KEY env var)"
        )

    # TLS enforcement when binding to all interfaces
    bind = config["api"].get("bind", "127.0.0.1")
    if bind == "0.0.0.0":
        tls_cert = config["api"].get("tls_cert")
        tls_key = config["api"].get("tls_key")
        if not tls_cert or not tls_key:
            raise ValueError(
                "TLS is required when bind = '0.0.0.0'. "
                "Set api.tls_cert and api.tls_key, or use bind = '127.0.0.1' behind a reverse proxy."
            )

    # Server ID defaults to hostname
    config["agent"].setdefault("server_id", socket.gethostname())

    return config
