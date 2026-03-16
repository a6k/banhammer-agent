import hashlib
import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Iterator

BAN_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+"
    r"\[(\w[\w-]*)\]\s+(Ban|Unban)\s+(\S+)"
)

# Number of bytes to use for content fingerprinting
_FINGERPRINT_BYTES = 64


def parse_fail2ban_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    match = BAN_PATTERN.match(line)
    if not match:
        return None
    timestamp_str, jail, action, ip = match.groups()

    # MED-4: Validate IP before returning event
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=timezone.utc)
    return {
        "type": action.lower(),
        "jail": jail,
        "ip": ip,
        "timestamp": timestamp,
    }


def _read_fingerprint(path: str, position: int) -> bytes | None:
    """Read a fingerprint of the file content ending at *position*.

    Returns up to _FINGERPRINT_BYTES bytes ending at *position*, or None if
    the file cannot be read or *position* is 0.
    """
    if position == 0:
        return None
    try:
        start = max(0, position - _FINGERPRINT_BYTES)
        with open(path, "rb") as f:
            f.seek(start)
            return f.read(position - start)
    except OSError:
        return None


class LogTailer:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._inode: int | None = None
        self._position: int = 0
        self._fingerprint: bytes | None = None
        self._init_position()

    def _init_position(self):
        try:
            stat = os.stat(self.log_path)
            self._inode = stat.st_ino
            self._position = stat.st_size
            self._fingerprint = _read_fingerprint(self.log_path, self._position)
        except FileNotFoundError:
            self._inode = None
            self._position = 0
            self._fingerprint = None

    def _detect_rotation(self) -> bool:
        try:
            stat = os.stat(self.log_path)
        except FileNotFoundError:
            return False

        # Different inode: classic log rotation (rename + new file)
        if self._inode is not None and stat.st_ino != self._inode:
            return True

        # File is smaller than our stored read position: truncation
        if stat.st_size < self._position:
            return True

        # Same inode, same or larger size: verify content continuity.
        # If the file was truncated to 0 then rewritten (e.g. via write_text),
        # the fingerprint of the bytes we last read will no longer match the
        # content at the same offset.
        if self._position > 0 and self._fingerprint is not None:
            current_fp = _read_fingerprint(self.log_path, self._position)
            if current_fp is not None and current_fp != self._fingerprint:
                return True

        return False

    def poll(self) -> Iterator[dict]:
        if self._detect_rotation():
            self._position = 0
            self._fingerprint = None
            try:
                self._inode = os.stat(self.log_path).st_ino
            except FileNotFoundError:
                return

        try:
            with open(self.log_path, "r") as f:
                f.seek(self._position)
                for line in f:
                    event = parse_fail2ban_line(line)
                    if event is not None:
                        yield event
                self._position = f.tell()
            # Update fingerprint so the next poll can detect future rotations
            self._fingerprint = _read_fingerprint(self.log_path, self._position)
        except FileNotFoundError:
            return
