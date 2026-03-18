import asyncio
import hmac
import ipaddress
import logging
import re
import subprocess
import threading
import time
from importlib.metadata import version as pkg_version
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

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


class BulkUnbanEntry(BaseModel):
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
            raise ValueError(f"Invalid jail name: {v!r}")
        return v


class BulkUnbanRequest(BaseModel):
    entries: list[BulkUnbanEntry] = Field(..., max_length=25)


class WhitelistRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


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


def _do_bulk_unban(entries, poller_ref):
    results = []
    for entry in entries:
        if poller_ref is None:
            results.append({"ip": entry.ip, "jail": entry.jail,
                            "success": False, "error": "poller not available"})
            continue
        try:
            result = subprocess.run(
                poller_ref.build_cmd("set", entry.jail, "unbanip", entry.ip),
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                results.append({"ip": entry.ip, "jail": entry.jail,
                                "success": False, "error": "unban failed"})
            else:
                results.append({"ip": entry.ip, "jail": entry.jail, "success": True})
        except Exception:
            results.append({"ip": entry.ip, "jail": entry.jail,
                            "success": False, "error": "command error"})
    return results


def resolve_server_location(geo_service) -> "dict | None":
    """Resolve the server's own public IP and look up its geo location.
    Runs synchronously — call via asyncio.to_thread() to avoid blocking
    the event loop."""
    try:
        import httpx as _httpx
        resp = _httpx.get("https://api.ipify.org", timeout=5.0)
        public_ip = resp.text.strip()
        ipaddress.ip_address(public_ip)  # validate before use
        location = geo_service.lookup(public_ip)
        if location:
            logger.info("Server location resolved (%s)", location.get("city"))
        return location
    except Exception:
        logger.debug("Could not resolve server location")
        return None


def create_app(
    db: EventDB,
    server_id: str,
    api_key: str,
    poller=None,
    path_prefix: str = "",
    geo_service=None,
    ws_manager=None,
    server_location: "dict | None" = None,
) -> FastAPI:
    app = FastAPI(title="BanHammer Agent", docs_url=None, redoc_url=None)
    prefix = path_prefix.rstrip("/") if path_prefix else ""

    _server_location = server_location
    rate_limiter = RateLimiter(max_requests=10, window_seconds=1.0)

    caps = ["geo", "timeline", "countries", "whitelist", "bulk_unban"]
    if ws_manager is not None:
        caps.append("websocket")

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
        result = {
            "server_id": server_id,
            "hostname": server_id,
            "version": _get_version(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "jails": latest or {},
            "capabilities": caps,
        }
        if _server_location:
            result["server_lat"] = _server_location["lat"]
            result["server_lon"] = _server_location["lon"]
        return result

    @app.get(f"{prefix}/api/v1/events")
    async def events(
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
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

    @app.get(f"{prefix}/api/v1/whitelist")
    async def whitelist_list_endpoint(_=Depends(verify_api_key)):
        return {"ips": db.whitelist_list()}

    @app.post(f"{prefix}/api/v1/whitelist")
    async def whitelist_add_endpoint(req: WhitelistRequest, _=Depends(verify_api_key)):
        db.whitelist_add(req.ip)
        if poller:
            def _apply_whitelist_add(ip, poller_ref):
                try:
                    latest = db.get_latest_status()
                    jails = poller_ref.get_jail_list()
                    for jail in jails:
                        # Only unban if IP is actually banned in this jail
                        jail_status = (latest or {}).get(jail, {})
                        banned_ips = jail_status.get("banned_ips", [])
                        if ip in banned_ips:
                            subprocess.run(
                                poller_ref.build_cmd("set", jail, "unbanip", ip),
                                capture_output=True, text=True, timeout=10,
                            )
                        # Always add to ignore list for all jails
                        subprocess.run(
                            poller_ref.build_cmd("set", jail, "addignoreip", ip),
                            capture_output=True, text=True, timeout=10,
                        )
                except Exception:
                    logger.warning("Failed to apply whitelist to fail2ban for %s", ip)
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(_apply_whitelist_add, req.ip, poller),
                    timeout=60.0,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Whitelist apply to fail2ban timed out for %s — "
                    "IP is saved in DB whitelist but may not be fully applied to all jails",
                    req.ip,
                )
        return {"status": "ok"}

    @app.delete(f"{prefix}/api/v1/whitelist/{{ip}}")
    async def whitelist_delete_endpoint(ip: str, _=Depends(verify_api_key)):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid IP address: {ip}")
        removed = db.whitelist_remove(ip)
        if not removed:
            raise HTTPException(status_code=404, detail=f"{ip} not in whitelist")
        if poller:
            def _apply_whitelist_delete(ip_addr, poller_ref):
                try:
                    jails = poller_ref.get_jail_list()
                    for jail in jails:
                        subprocess.run(
                            poller_ref.build_cmd("set", jail, "delignoreip", ip_addr),
                            capture_output=True, text=True, timeout=10,
                        )
                except Exception:
                    logger.warning("Failed to remove whitelist from fail2ban for %s", ip_addr)
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(_apply_whitelist_delete, ip, poller),
                    timeout=60.0,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Whitelist delete from fail2ban timed out for %s — "
                    "IP is removed from DB whitelist but may still be in some jail ignore lists",
                    ip,
                )
        return {"status": "ok"}

    @app.get(f"{prefix}/api/v1/stats/countries")
    async def countries(_=Depends(verify_api_key)):
        return db.countries_stats()

    @app.get(f"{prefix}/api/v1/stats/timeline")
    async def timeline(
        period: Annotated[str, Query(pattern="^(24h|7d|30d)$")] = "24h",
        _=Depends(verify_api_key),
    ):
        buckets = db.timeline_buckets(period=period)
        return {"period": period, "buckets": buckets}

    @app.post(f"{prefix}/api/v1/unban/bulk")
    async def unban_bulk(req: BulkUnbanRequest, _=Depends(verify_api_key)):
        try:
            results = await asyncio.wait_for(
                asyncio.to_thread(_do_bulk_unban, req.entries, poller),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Bulk unban timed out")
        return {"results": results}

    @app.post(f"{prefix}/api/v1/unban")
    async def unban(req: UnbanRequest, _=Depends(verify_api_key)):
        if poller is None:
            raise HTTPException(status_code=503, detail="Poller not available")
        def _do():
            return subprocess.run(
                poller.build_cmd("set", req.jail, "unbanip", req.ip),
                capture_output=True, text=True, timeout=10,
            )
        try:
            result = await asyncio.to_thread(_do)
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

    @app.websocket(f"{prefix}/api/v1/ws")
    async def websocket_endpoint(websocket: WebSocket, token: str = ""):
        await websocket.accept()
        if not token or not hmac.compare_digest(token, api_key):
            await websocket.close(code=4001, reason="Invalid token")
            return
        if ws_manager is None:
            await websocket.close(code=4002, reason="WebSocket not available")
            return
        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive()
                if data.get("type") == "websocket.disconnect":
                    break
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.warning("WebSocket receive error: %s", e)
        finally:
            await ws_manager.disconnect(websocket)

    return app
