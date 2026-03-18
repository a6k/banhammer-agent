import asyncio
import json
import logging

from fastapi import WebSocket

logger = logging.getLogger("banhammer")

MAX_WS_CLIENTS = 10
_SEND_TIMEOUT = 5.0


class WebSocketManager:
    def __init__(self):
        self._clients: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        async with self._lock:
            if len(self._clients) >= MAX_WS_CLIENTS:
                await ws.close(code=4008, reason="Too many connections")
                return
            self._clients.append(ws)
        logger.info("WebSocket client connected (%d total)", len(self._clients))

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._clients:
                self._clients.remove(ws)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._clients))

    async def broadcast(self, message_type: str, data: dict):
        payload = json.dumps({"type": message_type, "data": data})

        # Snapshot client list outside the lock so slow sends don't block
        # connect/disconnect from acquiring it.
        async with self._lock:
            clients = list(self._clients)

        dead = []
        for client in clients:
            try:
                await asyncio.wait_for(client.send_text(payload), timeout=_SEND_TIMEOUT)
            except Exception:
                dead.append(client)

        if dead:
            async with self._lock:
                for client in dead:
                    if client in self._clients:
                        self._clients.remove(client)

    @property
    def client_count(self) -> int:
        return len(self._clients)
