import ipaddress
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone

ALLOWED_LOG_DIRS = ("/var/log/",)

MAX_LINE_LEN = 512

JAIL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

JOURNAL_MATCH_RE = re.compile(r"^_[A-Z_]+=[A-Za-z0-9@._-]+$")


def parse_status_output(output: str) -> list[str]:
    for line in output.splitlines():
        if "Jail list:" in line:
            jail_str = line.split("Jail list:")[1].strip()
            if not jail_str:
                return []
            return [j.strip() for j in jail_str.split(",") if JAIL_RE.match(j.strip())]
    return []


def parse_jail_status_output(output: str) -> dict:
    active_bans = 0
    total_bans = 0
    banned_ips = []

    for line in output.splitlines():
        if "Currently banned:" in line:
            match = re.search(r"(\d+)", line.split("Currently banned:")[1])
            if match:
                active_bans = int(match.group(1))
        elif "Total banned:" in line:
            match = re.search(r"(\d+)", line.split("Total banned:")[1])
            if match:
                total_bans = int(match.group(1))
        elif "Banned IP list:" in line:
            ip_str = line.split("Banned IP list:")[1].strip()
            if ip_str:
                banned_ips = ip_str.split()

    # CRIT-3: Validate IPs parsed from fail2ban-client output
    validated_ips = []
    for ip_str in banned_ips:
        try:
            ipaddress.ip_address(ip_str)
            validated_ips.append(ip_str)
        except ValueError:
            pass

    return {
        "active_bans": active_bans,
        "total_bans": total_bans,
        "banned_ips": validated_ips,
    }


class Poller:
    def __init__(self, client_path: str, timeout: int = 10, use_sudo: bool = False):
        self.client_path = client_path
        self.timeout = timeout
        self.use_sudo = use_sudo

    def build_cmd(self, *args: str) -> list[str]:
        """Build command list for fail2ban-client, with optional sudo prefix."""
        cmd = [self.client_path, *args]
        if self.use_sudo:
            cmd = ["sudo"] + cmd
        return cmd

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            self.build_cmd(*args),
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        result.check_returncode()
        return result.stdout

    def get_jail_list(self) -> list[str]:
        output = self._run("status")
        return parse_status_output(output)

    def get_jail_status(self, jail: str) -> dict:
        output = self._run("status", jail)
        return parse_jail_status_output(output)

    def poll(self) -> dict:
        jails = self.get_jail_list()
        MAX_JAILS = 50
        if len(jails) > MAX_JAILS:
            jails = jails[:MAX_JAILS]
        jail_data = {}
        MAX_LOOKUP_IPS = 20
        MAX_DETAIL_LINES_TOTAL = 100  # hard cap: total log lines across all IPs per jail
        for jail in jails:
            status = self.get_jail_status(jail)
            # Look up log context for each banned IP
            ip_details = {}
            total_lines = 0
            for ip in status["banned_ips"][:MAX_LOOKUP_IPS]:
                if total_lines >= MAX_DETAIL_LINES_TOTAL:
                    break
                try:
                    log_lines = self.lookup_ip(jail, ip, max_lines=5)
                    ip_details[ip] = log_lines
                    total_lines += len(log_lines)
                except Exception:
                    ip_details[ip] = []

            jail_data[jail] = {
                "active_bans": status["active_bans"],
                "total_bans": status["total_bans"],
                "banned_ips": status["banned_ips"],
                "ip_details": ip_details,
            }
        return jail_data

    def _validate_log_path(self, path: str) -> bool:
        """CRIT-2: Ensure log path is absolute, under allowed dirs, and a regular file."""
        real = os.path.realpath(path)
        if not any(real.startswith(d) for d in ALLOWED_LOG_DIRS):
            return False
        if not os.path.isfile(real):
            return False
        return True

    def lookup_ip(self, jail: str, ip: str, max_lines: int = 10) -> list[str]:
        """Look up recent log entries for an IP in a jail's log source."""
        # CRIT-3: Validate IP before using it in commands
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return []

        lines = []

        # Try logpath first (file-based logging)
        try:
            output = self._run("get", jail, "logpath")
            for line in output.splitlines():
                if line.startswith("`-"):
                    log_path = line.split("`-")[1].strip()
                    if log_path:
                        # CRIT-2: Validate log path before reading
                        if not self._validate_log_path(log_path):
                            continue
                        lines = self._grep_file(log_path, ip, max_lines)
                        if lines:
                            return lines
        except Exception:
            pass

        # Try journalmatch (systemd journal)
        try:
            output = self._run("get", jail, "journalmatch")
            # Extract all match filter parts (e.g. _SYSTEMD_UNIT=postfix.service)
            match_parts = []
            for line in output.splitlines():
                for token in line.strip().split():
                    if "=" in token and not token.startswith("Current"):
                        match_parts.append(token)

            # CRIT-3: Validate journal match parts
            validated_parts = [p for p in match_parts if JOURNAL_MATCH_RE.match(p)]

            if validated_parts:
                lines = self._grep_journal(validated_parts, ip, max_lines)
        except Exception:
            pass

        return lines

    def _grep_file(self, path: str, ip: str, max_lines: int) -> list[str]:
        try:
            # CRIT-3: Use -F for fixed-string matching instead of -i
            result = subprocess.run(
                ["grep", "-F", "--max-count=100", ip, path],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout:
                lines = [l[:MAX_LINE_LEN] for l in result.stdout.strip().splitlines()][-max_lines:]
                return lines
        except Exception:
            pass
        return []

    def _grep_journal(self, match_parts: list[str], ip: str, max_lines: int) -> list[str]:
        try:
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            cmd = ["journalctl", "--no-pager", "-n", "500", "--output", "short-iso",
                   "--since", since, "--"]
            for part in match_parts:
                cmd.append(part)
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.stdout:
                ip_pattern = re.compile(r'(?<![0-9a-fA-F:.])' + re.escape(ip) + r'(?![0-9a-fA-F:.])')
                matching = [l[:MAX_LINE_LEN] for l in result.stdout.splitlines() if ip_pattern.search(l)]
                return matching[-max_lines:]
        except Exception:
            pass
        return []
