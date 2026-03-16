import re
import time

import pytest
from fastapi.testclient import TestClient

from banhammer.api import create_app
from banhammer.db import EventDB

API_KEY = "bh_testapikey1234567890abcdef1234"


@pytest.fixture
def db(tmp_path):
    return EventDB(str(tmp_path / "banhammer.db"))


@pytest.fixture
def app(db):
    return create_app(
        db=db,
        server_id="test-server",
        api_key=API_KEY,
        poller=None,  # No real poller in tests
    )


@pytest.fixture
def client(app):
    return TestClient(app)


def auth_headers():
    return {"Authorization": f"Bearer {API_KEY}"}


# --- /api/v1/health ---

class TestHealth:
    def test_health_no_auth_required(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        # HIGH-2: health endpoint no longer exposes version or hostname
        assert "version" not in data
        assert "hostname" not in data

    def test_health_returns_only_status(self, client):
        resp = client.get("/api/v1/health")
        assert resp.json() == {"status": "ok"}


# --- /api/v1/status ---

class TestStatus:
    def test_status_requires_auth(self, client):
        resp = client.get("/api/v1/status")
        assert resp.status_code == 401

    def test_status_wrong_key(self, client):
        resp = client.get("/api/v1/status", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401

    def test_status_returns_data(self, client, db):
        jails = {"sshd": {"active_bans": 1, "total_bans": 10, "banned_ips": ["1.2.3.4"], "ip_details": {}}}
        db.save_status(jails)
        resp = client.get("/api/v1/status", headers=auth_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["server_id"] == "test-server"
        assert "sshd" in data["jails"]
        assert data["jails"]["sshd"]["active_bans"] == 1

    def test_status_empty_when_no_data(self, client):
        resp = client.get("/api/v1/status", headers=auth_headers())
        assert resp.status_code == 200
        assert resp.json()["jails"] == {}


# --- /api/v1/events ---

class TestEvents:
    def test_events_requires_auth(self, client):
        resp = client.get("/api/v1/events")
        assert resp.status_code == 401

    def test_events_returns_paginated(self, client, db):
        for i in range(10):
            db.insert_event("ban", "sshd", f"1.2.3.{i}", f"2026-03-15T12:0{i}:00Z")
        resp = client.get("/api/v1/events?limit=3&offset=0", headers=auth_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 10
        assert data["limit"] == 3
        assert data["offset"] == 0
        assert len(data["events"]) == 3

    def test_events_offset(self, client, db):
        for i in range(5):
            db.insert_event("ban", "sshd", f"1.2.3.{i}", f"2026-03-15T12:0{i}:00Z")
        resp = client.get("/api/v1/events?limit=50&offset=3", headers=auth_headers())
        data = resp.json()
        assert len(data["events"]) == 2

    def test_events_default_pagination(self, client, db):
        db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
        resp = client.get("/api/v1/events", headers=auth_headers())
        data = resp.json()
        assert data["limit"] == 50
        assert data["offset"] == 0


# --- /api/v1/stats ---

class TestStats:
    def test_stats_requires_auth(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 401

    def test_stats_returns_data(self, client, db):
        db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
        db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:01Z")
        db.insert_event("ban", "postfix", "5.6.7.8", "2026-03-15T12:00:02Z")
        resp = client.get("/api/v1/stats", headers=auth_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert "top_attackers" in data
        assert "bans_by_jail" in data
        assert "total_bans_24h" in data
        assert "total_bans_7d" in data
        assert data["bans_by_jail"]["sshd"] == 2


# --- /api/v1/unban ---

class TestUnban:
    def test_unban_requires_auth(self, client):
        resp = client.post("/api/v1/unban", json={"ip": "1.2.3.4", "jail": "sshd"})
        assert resp.status_code == 401

    def test_unban_validates_ip(self, client):
        resp = client.post(
            "/api/v1/unban",
            json={"ip": "not-an-ip", "jail": "sshd"},
            headers=auth_headers(),
        )
        assert resp.status_code == 422

    def test_unban_validates_jail_name(self, client):
        resp = client.post(
            "/api/v1/unban",
            json={"ip": "1.2.3.4", "jail": "ssh; rm -rf /"},
            headers=auth_headers(),
        )
        assert resp.status_code == 422

    def test_unban_valid_ipv4(self, client):
        # Will fail because no real poller, but should not be 422
        resp = client.post(
            "/api/v1/unban",
            json={"ip": "1.2.3.4", "jail": "sshd"},
            headers=auth_headers(),
        )
        # 500 or 503 because no poller configured — not 422
        assert resp.status_code != 422

    def test_unban_valid_ipv6(self, client):
        resp = client.post(
            "/api/v1/unban",
            json={"ip": "2001:db8::1", "jail": "sshd"},
            headers=auth_headers(),
        )
        assert resp.status_code != 422

    def test_unban_valid_jail_names(self, client):
        for jail in ["sshd", "postfix-sasl", "nginx_bad_request", "my-jail-2"]:
            resp = client.post(
                "/api/v1/unban",
                json={"ip": "1.2.3.4", "jail": jail},
                headers=auth_headers(),
            )
            assert resp.status_code != 422, f"jail={jail} should be valid"

    def test_unban_invalid_jail_names(self, client):
        for jail in ["ssh; ls", "jail name", "jail/path", ""]:
            resp = client.post(
                "/api/v1/unban",
                json={"ip": "1.2.3.4", "jail": jail},
                headers=auth_headers(),
            )
            assert resp.status_code == 422, f"jail={jail!r} should be invalid"


class TestPathPrefix:
    def test_prefix_routes(self, db):
        app = create_app(
            db=db,
            server_id="test",
            api_key=API_KEY,
            path_prefix="/x7k9m2",
        )
        client = TestClient(app)
        # Prefixed route works
        resp = client.get("/x7k9m2/api/v1/health")
        assert resp.status_code == 200
        # Unprefixed route returns 404
        resp = client.get("/api/v1/health")
        assert resp.status_code == 404

    def test_empty_prefix_still_works(self, db):
        app = create_app(db=db, server_id="test", api_key=API_KEY, path_prefix="")
        client = TestClient(app)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
