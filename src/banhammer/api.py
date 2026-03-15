import ipaddress
import re
import socket
import subprocess
import time
from importlib.metadata import version as pkg_version
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

from banhammer.db import EventDB

JAIL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

security = HTTPBearer()


def _get_version() -> str:
    try:
        return pkg_version("banhammer-agent")
    except Exception:
        return "0.2.0"


class UnbanRequest(BaseModel):
    ip: str
    jail: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @field_validator("jail")
    @classmethod
    def validate_jail(cls, v: str) -> str:
        if not v or not JAIL_RE.match(v):
            raise ValueError(f"Invalid jail name: {v!r} — must match ^[a-zA-Z0-9_-]+$")
        return v


class RateLimiter:
    """Simple per-IP rate limiter using a sliding window."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 1.0):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = {}

    def check(self, client_ip: str) -> bool:
        now = time.time()
        if client_ip not in self._requests:
            self._requests[client_ip] = []
        # Prune old entries
        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if now - t < self.window
        ]
        if len(self._requests[client_ip]) >= self.max_requests:
            return False
        self._requests[client_ip].append(now)
        return True


def create_app(
    db: EventDB,
    server_id: str,
    api_key: str,
    poller=None,
) -> FastAPI:
    app = FastAPI(title="BanHammer Agent", docs_url=None, redoc_url=None)
    rate_limiter = RateLimiter(max_requests=10, window_seconds=1.0)

    def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
        if credentials.credentials != api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return credentials

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.check(client_ip):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
            )
        return await call_next(request)

    @app.get("/api/v1/health")
    async def health():
        return {
            "status": "ok",
            "version": _get_version(),
            "hostname": socket.gethostname(),
        }

    @app.get("/api/v1/status")
    async def status(_=Depends(verify_api_key)):
        latest = db.get_latest_status()
        return {
            "server_id": server_id,
            "hostname": socket.gethostname(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "jails": latest or {},
        }

    @app.get("/api/v1/events")
    async def events(
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
        _=Depends(verify_api_key),
    ):
        total = db.count_events()
        event_list = db.get_events(limit=limit, offset=offset)
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": event_list,
        }

    @app.get("/api/v1/stats")
    async def stats(_=Depends(verify_api_key)):
        now = time.time()
        return {
            "top_attackers": db.top_attackers(limit=10),
            "bans_by_jail": db.bans_by_jail(),
            "total_bans_24h": db.bans_since(now - 86400),
            "total_bans_7d": db.bans_since(now - 7 * 86400),
        }

    @app.post("/api/v1/unban")
    async def unban(req: UnbanRequest, _=Depends(verify_api_key)):
        if poller is None:
            raise HTTPException(status_code=503, detail="Poller not available")
        try:
            result = subprocess.run(
                [poller.client_path, "set", req.jail, "unbanip", req.ip],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to unban: {result.stderr.strip() or result.stdout.strip()}",
                )
            return {"status": "ok", "message": f"{req.ip} unbanned from {req.jail}"}
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="fail2ban-client timed out")
        except FileNotFoundError:
            raise HTTPException(status_code=503, detail="fail2ban-client not found")

    return app
