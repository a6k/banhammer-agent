import pytest
from fastapi.testclient import TestClient
from banhammer.api import create_app
from banhammer.db import EventDB
from banhammer.websocket import WebSocketManager

API_KEY = "bh_testapikey1234567890abcdef1234"

@pytest.fixture
def db(tmp_path):
    return EventDB(str(tmp_path / "banhammer.db"))

@pytest.fixture
def ws_manager():
    return WebSocketManager()

@pytest.fixture
def app(db, ws_manager):
    return create_app(db=db, server_id="test", api_key=API_KEY, ws_manager=ws_manager)

@pytest.fixture
def client(app):
    return TestClient(app)

def test_websocket_rejects_invalid_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws?token=wrong"):
            pass

def test_websocket_rejects_empty_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws"):
            pass

def test_websocket_connects_with_valid_token(client, ws_manager):
    with client.websocket_connect(f"/api/v1/ws?token={API_KEY}") as ws:
        assert ws_manager.client_count == 1

def test_capabilities_include_websocket(client):
    resp = client.get("/api/v1/status", headers={"Authorization": f"Bearer {API_KEY}"})
    assert "websocket" in resp.json()["capabilities"]

def test_capabilities_without_ws_manager(db):
    app = create_app(db=db, server_id="test", api_key=API_KEY, ws_manager=None)
    client = TestClient(app)
    resp = client.get("/api/v1/status", headers={"Authorization": f"Bearer {API_KEY}"})
    assert "websocket" not in resp.json()["capabilities"]
