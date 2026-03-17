import asyncio
import json
import logging

from fastapi import WebSocket

logger = logging.getLogger("banhammer")

MAX_WS_CLIENTS = 10


class WebSocketManager:
    def __init__(self):
        self._clients: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        async with self._lock:
            if len(self._clients) >= MAX_WS_CLIENTS:
                await ws.close(code=4008, reason="Too many connections")
                return
            await ws.accept()
            self._clients.append(ws)
        logger.info("WebSocket client connected (%d total)", len(self._clients))

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._clients:
                self._clients.remove(ws)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._clients))

    async def broadcast(self, message_type: str, data: dict):
        payload = json.dumps({"type": message_type, "data": data})
        async with self._lock:
            dead = []
            for client in self._clients:
                try:
                    await client.send_text(payload)
                except Exception:
                    dead.append(client)
            for client in dead:
                self._clients.remove(client)

    @property
    def client_count(self) -> int:
        return len(self._clients)
