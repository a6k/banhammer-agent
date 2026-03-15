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
            jail_data[jail] = {
                "active_bans": status["active_bans"],
                "total_bans": status["total_bans"],
                "banned_ips": status["banned_ips"],
            }
        return jail_data
