import os
import socket
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

DEFAULTS = {
    "agent": {
        "poll_interval": 60,
        "heartbeat_interval": 300,
        "batch_size": 50,
        "retry_max": 5,
        "retry_backoff": 2,
    },
    "fail2ban": {
        "log_path": "/var/log/fail2ban.log",
        "client_path": "/usr/bin/fail2ban-client",
    },
    "storage": {
        "queue_db": "/var/lib/banhammer/queue.db",
        "queue_max_events": 10000,
    },
}


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        config = tomllib.load(f)

    for section, defaults in DEFAULTS.items():
        if section not in config:
            config[section] = {}
        for key, value in defaults.items():
            config[section].setdefault(key, value)

    if "backend" not in config:
        config["backend"] = {}

    if not config["backend"].get("url"):
        raise ValueError("Missing required config: backend.url")

    env_key = os.environ.get("BANHAMMER_API_KEY")
    if env_key:
        config["backend"]["api_key"] = env_key

    if not config["backend"].get("api_key"):
        raise ValueError(
            "Missing required config: backend.api_key "
            "(set in config file or BANHAMMER_API_KEY env var)"
        )

    if "agent" not in config:
        config["agent"] = {}
    config["agent"].setdefault("server_id", socket.gethostname())

    return config
