import re
import subprocess


def parse_status_output(output: str) -> list[str]:
    for line in output.splitlines():
        if "Jail list:" in line:
            jail_str = line.split("Jail list:")[1].strip()
            if not jail_str:
                return []
            return [j.strip() for j in jail_str.split(",")]
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

    return {
        "active_bans": active_bans,
        "total_bans": total_bans,
        "banned_ips": banned_ips,
    }


class Poller:
    def __init__(self, client_path: str, timeout: int = 10):
        self.client_path = client_path
        self.timeout = timeout

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            [self.client_path, *args],
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
        jail_data = {}
        for jail in jails:
            status = self.get_jail_status(jail)
            # Look up log context for each banned IP
            ip_details = {}
            for ip in status["banned_ips"]:
                try:
                    log_lines = self.lookup_ip(jail, ip, max_lines=5)
                    ip_details[ip] = log_lines
                except Exception:
                    ip_details[ip] = []

            jail_data[jail] = {
                "active_bans": status["active_bans"],
                "total_bans": status["total_bans"],
                "banned_ips": status["banned_ips"],
                "ip_details": ip_details,
            }
        return jail_data

    def lookup_ip(self, jail: str, ip: str, max_lines: int = 10) -> list[str]:
        """Look up recent log entries for an IP in a jail's log source."""
        lines = []

        # Try logpath first (file-based logging)
        try:
            output = self._run("get", jail, "logpath")
            for line in output.splitlines():
                if line.startswith("`-"):
                    log_path = line.split("`-")[1].strip()
                    if log_path:
                        lines = self._grep_file(log_path, ip, max_lines)
                        if lines:
                            return lines
        except Exception:
            pass

        # Try journalmatch (systemd journal)
        try:
            output = self._run("get", jail, "journalmatch")
            # Extract the match filter
            match_parts = []
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("_SYSTEMD_UNIT=") or line.startswith("_COMM="):
                    match_parts.extend(line.split())

            if match_parts:
                lines = self._grep_journal(match_parts, ip, max_lines)
        except Exception:
            pass

        return lines

    def _grep_file(self, path: str, ip: str, max_lines: int) -> list[str]:
        try:
            result = subprocess.run(
                ["grep", "-i", ip, path],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout:
                return result.stdout.strip().splitlines()[-max_lines:]
        except Exception:
            pass
        return []

    def _grep_journal(self, match_parts: list[str], ip: str, max_lines: int) -> list[str]:
        try:
            cmd = ["journalctl", "--no-pager", "-n", "200", "--output", "short-iso"]
            for part in match_parts:
                if part == "+":
                    continue
                cmd.append(part)
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.stdout:
                matching = [l for l in result.stdout.splitlines() if ip in l]
                return matching[-max_lines:]
        except Exception:
            pass
        return []
