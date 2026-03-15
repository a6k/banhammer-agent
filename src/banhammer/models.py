from dataclasses import dataclass
from datetime import datetime


@dataclass
class BanEvent:
    server_id: str
    jail: str
    ip: str
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "type": "ban",
            "server_id": self.server_id,
            "jail": self.jail,
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class UnbanEvent:
    server_id: str
    jail: str
    ip: str
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "type": "unban",
            "server_id": self.server_id,
            "jail": self.jail,
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class StatusEvent:
    server_id: str
    timestamp: datetime
    jails: dict

    def to_dict(self) -> dict:
        return {
            "type": "status",
            "server_id": self.server_id,
            "timestamp": self.timestamp.isoformat(),
            "jails": self.jails,
        }


@dataclass
class HeartbeatEvent:
    server_id: str
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "type": "heartbeat",
            "server_id": self.server_id,
            "timestamp": self.timestamp.isoformat(),
        }
