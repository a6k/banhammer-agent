import hmac
import ipaddress
import logging
import re
import socket
import subprocess
import threading
import time
from importlib.metadata import version as pkg_version
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

from banhammer.db import EventDB

logger = logging.getLogger("banhammer")

JAIL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

security = HTTPBearer()


def _get_version() -> str:
    try:
        return pkg_version("banhammer-agent")
    except Exception:
        return "unknown"


def _get_client_ip(request: Request) -> str:
    """Use X-Real-IP when behind a reverse proxy on loopback, validated."""
    peer = request.client.host if request.client else "unknown"
    if peer in ("127.0.0.1", "::1"):
        raw = request.headers.get("X-Real-IP", "")
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            return peer
    return peer


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
        self._lock = threading.Lock()
        self._check_count = 0

    def check(self, client_ip: str) -> bool:
        with self._lock:
            now = time.time()
            self._check_count += 1

            # Periodic cleanup every 100 checks
            if self._check_count % 100 == 0:
                stale = [k for k, v in self._requests.items()
                         if not v or (now - v[-1]) >= self.window]
                for k in stale:
                    del self._requests[k]

                # Hard cap to prevent unbounded growth
                if len(self._requests) > 10000:
                    # Emergency prune: remove oldest half
                    sorted_ips = sorted(self._requests.keys(),
                                        key=lambda k: self._requests[k][-1] if self._requests[k] else 0)
                    for k in sorted_ips[:5000]:
                        del self._requests[k]

            window = self._requests.get(client_ip, [])
            window = [t for t in window if now - t < self.window]
            if len(window) >= self.max_requests:
                self._requests[client_ip] = window
                return False
            window.append(now)
            self._requests[client_ip] = window
            return True


def create_app(
    db: EventDB,
    server_id: str,
    api_key: str,
    poller=None,
    path_prefix: str = "",
) -> FastAPI:
    app = FastAPI(title="BanHammer Agent", docs_url=None, redoc_url=None)
    prefix = path_prefix.rstrip("/") if path_prefix else ""
    rate_limiter = RateLimiter(max_requests=10, window_seconds=1.0)

    def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
        # HIGH-3: Use constant-time comparison for API key
        if not hmac.compare_digest(credentials.credentials, api_key):
            raise HTTPException(status_code=401, detail="Invalid API key")
        return credentials

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        # HIGH-1: Use X-Real-IP behind reverse proxy
        client_ip = _get_client_ip(request)
        if not rate_limiter.check(client_ip):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
            )
        return await call_next(request)

    @app.get(f"{prefix}/api/v1/health")
    async def health():
        # HIGH-2: Only return status, no hostname/version
        return {"status": "ok"}

    @app.get(f"{prefix}/api/v1/status")
    async def status(_=Depends(verify_api_key)):
        latest = db.get_latest_status()
        return {
            "server_id": server_id,
            "hostname": socket.gethostname(),
            "version": _get_version(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "jails": latest or {},
            "capabilities": ["geo", "timeline", "countries", "whitelist", "bulk_unban"],
        }

    @app.get(f"{prefix}/api/v1/events")
    async def events(
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
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

    @app.get(f"{prefix}/api/v1/stats")
    async def stats(_=Depends(verify_api_key)):
        now = time.time()
        return {
            "top_attackers": db.top_attackers(limit=10),
            "bans_by_jail": db.bans_by_jail(),
            "total_bans_24h": db.bans_since(now - 86400),
            "total_bans_7d": db.bans_since(now - 7 * 86400),
        }

    @app.get(f"{prefix}/api/v1/stats/timeline")
    async def timeline(
        period: Annotated[str, Query(pattern="^(24h|7d|30d)$")] = "24h",
        _=Depends(verify_api_key),
    ):
        buckets = db.timeline_buckets(period=period)
        return {"period": period, "buckets": buckets}

    @app.post(f"{prefix}/api/v1/unban")
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
                # HIGH-5: Don't reflect fail2ban-client stderr to caller
                logger.warning("Unban failed: %s", result.stderr.strip() or result.stdout.strip())
                raise HTTPException(
                    status_code=400,
                    detail="Unban command failed. Check server logs.",
                )
            return {"status": "ok", "message": f"{req.ip} unbanned from {req.jail}"}
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="fail2ban-client timed out")
        except FileNotFoundError:
            raise HTTPException(status_code=503, detail="fail2ban-client not found")

    return app
