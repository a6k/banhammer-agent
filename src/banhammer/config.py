import ipaddress
import logging
import os
import re
import socket
import stat
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


def _is_loopback(bind: str) -> bool:
    """Check whether *bind* is a loopback address."""
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        try:
            resolved = socket.getaddrinfo(bind, None, type=socket.SOCK_STREAM)
            return all(ipaddress.ip_address(r[4][0]).is_loopback for r in resolved)
        except Exception:
            return False


def load_config(path: str) -> dict:
    path = os.path.realpath(path)
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

    # HIGH-3: Minimum API key length
    key = config["api"].get("api_key", "")
    if len(key) < 32:
        raise ValueError("api.api_key is too short (minimum 32 characters)")

    # LOW-3: Reject placeholder API keys
    if re.match(r"^bh_x+$", key):
        raise ValueError("api.api_key is a placeholder — run 'banhammer-agent init' to generate a real key")

    # HIGH-4: TLS enforcement for any non-loopback bind address
    bind = config["api"].get("bind", "127.0.0.1")
    tls_cert = config["api"].get("tls_cert")
    tls_key = config["api"].get("tls_key")
    if not _is_loopback(bind):
        if not tls_cert or not tls_key:
            raise ValueError(
                "TLS is required when binding to a non-loopback address. "
                "Set api.tls_cert and api.tls_key, or use a loopback bind address behind a reverse proxy."
            )

    if tls_cert and tls_key:
        if not os.path.isfile(tls_cert):
            raise ValueError(f"api.tls_cert file not found: {tls_cert}")
        if not os.path.isfile(tls_key):
            raise ValueError(f"api.tls_key file not found: {tls_key}")
        key_stat = os.stat(tls_key)
        if key_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH):
            logger.warning("TLS key file %s is readable by group/others — consider chmod 600", tls_key)

    # CRIT-1: Validate client_path is absolute and exists
    client_path = config["fail2ban"]["client_path"]
    if not os.path.isabs(client_path):
        raise ValueError(f"fail2ban.client_path must be absolute: {client_path}")
    if not os.path.isfile(client_path):
        logger.warning("fail2ban.client_path does not exist: %s", client_path)

    # MEDIUM-4: Validate log_path is absolute and under /var/log/
    log_path = config["fail2ban"]["log_path"]
    if not os.path.isabs(log_path):
        raise ValueError(f"fail2ban.log_path must be absolute: {log_path}")
    real_log_path = os.path.realpath(log_path) if os.path.exists(log_path) else log_path
    if not real_log_path.startswith("/var/log/"):
        logger.warning("fail2ban.log_path is outside /var/log/: %s", log_path)

    # CRIT-1: Verify config file permissions (warn if too open)
    try:
        file_stat = os.stat(path)
        if file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH):
            logger.warning("Config file %s is readable by group/others — consider chmod 600", path)
    except OSError:
        pass

    # MED-3: Validate db_path is absolute
    db_path = config["storage"]["db_path"]
    if not os.path.isabs(db_path):
        raise ValueError(f"storage.db_path must be absolute: {db_path}")
    allowed_db_dirs = ("/var/lib/banhammer/", "/tmp/")  # /tmp/ for tests
    real_parent = os.path.realpath(os.path.dirname(db_path))
    if not any(real_parent.startswith(d.rstrip("/")) for d in allowed_db_dirs):
        logger.warning("storage.db_path is outside expected directory: %s", db_path)

    # MED-2: Validate path_prefix format
    path_prefix = config.get("api", {}).get("path_prefix", "")
    if path_prefix and not re.match(r"^(/[a-zA-Z0-9_-]+)+$", path_prefix):
        raise ValueError(
            f"Invalid path_prefix: {path_prefix!r} — "
            "must match /segment format (e.g. /abc123)"
        )

    # Validate numeric ranges
    poll_interval = config["agent"]["poll_interval"]
    if not isinstance(poll_interval, int) or poll_interval < 5:
        raise ValueError("agent.poll_interval must be an integer >= 5")

    retention_days = config["storage"]["retention_days"]
    if not isinstance(retention_days, int) or retention_days < 1:
        raise ValueError("storage.retention_days must be an integer >= 1")

    port = config["api"]["port"]
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("api.port must be an integer between 1 and 65535")

    # Server ID defaults to hostname
    config["agent"].setdefault("server_id", socket.gethostname())

    return config
