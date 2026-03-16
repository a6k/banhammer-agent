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

    def test_status_includes_capabilities(self, client):
        resp = client.get("/api/v1/status", headers=auth_headers())
        data = resp.json()
        assert "capabilities" in data
        caps = data["capabilities"]
        assert "geo" in caps
        assert "timeline" in caps
        assert "countries" in caps
        assert "whitelist" in caps
        assert "bulk_unban" in caps


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


# --- /api/v1/whitelist ---

class TestWhitelist:
    def test_whitelist_requires_auth(self, client):
        assert client.get("/api/v1/whitelist").status_code == 401
        assert client.post("/api/v1/whitelist", json={"ip": "1.2.3.4"}).status_code == 401

    def test_whitelist_add_and_list(self, client, db):
        resp = client.post("/api/v1/whitelist", json={"ip": "1.2.3.4"},
                           headers=auth_headers())
        assert resp.status_code == 200
        resp = client.get("/api/v1/whitelist", headers=auth_headers())
        assert "1.2.3.4" in resp.json()["ips"]

    def test_whitelist_add_idempotent(self, client):
        client.post("/api/v1/whitelist", json={"ip": "1.2.3.4"}, headers=auth_headers())
        resp = client.post("/api/v1/whitelist", json={"ip": "1.2.3.4"},
                           headers=auth_headers())
        assert resp.status_code == 200

    def test_whitelist_add_validates_ip(self, client):
        resp = client.post("/api/v1/whitelist", json={"ip": "not-an-ip"},
                           headers=auth_headers())
        assert resp.status_code == 422

    def test_whitelist_delete(self, client, db):
        client.post("/api/v1/whitelist", json={"ip": "1.2.3.4"}, headers=auth_headers())
        resp = client.delete("/api/v1/whitelist/1.2.3.4", headers=auth_headers())
        assert resp.status_code == 200
        resp = client.get("/api/v1/whitelist", headers=auth_headers())
        assert "1.2.3.4" not in resp.json()["ips"]

    def test_whitelist_delete_nonexistent(self, client):
        resp = client.delete("/api/v1/whitelist/9.9.9.9", headers=auth_headers())
        assert resp.status_code == 404


# --- /api/v1/stats/countries ---

class TestCountries:
    def test_countries_requires_auth(self, client):
        resp = client.get("/api/v1/stats/countries")
        assert resp.status_code == 401

    def test_countries_returns_data(self, client, db):
        db.insert_event("ban", "sshd", "1.1.1.1", "2026-03-15T10:00:00Z",
                         country_code="CN", country_name="China")
        db.insert_event("ban", "sshd", "2.2.2.2", "2026-03-15T10:01:00Z",
                         country_code="RU", country_name="Russia")
        resp = client.get("/api/v1/stats/countries", headers=auth_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_bans"] == 2
        assert data["countries"][0]["country_code"] == "CN"

    def test_countries_empty(self, client):
        resp = client.get("/api/v1/stats/countries", headers=auth_headers())
        assert resp.status_code == 200
        assert resp.json()["total_bans"] == 0
        assert resp.json()["countries"] == []


# --- /api/v1/stats/timeline ---

class TestTimeline:
    def test_timeline_requires_auth(self, client):
        resp = client.get("/api/v1/stats/timeline")
        assert resp.status_code == 401

    def test_timeline_default_period(self, client, db):
        db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
        resp = client.get("/api/v1/stats/timeline", headers=auth_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["period"] == "24h"
        assert "buckets" in data

    def test_timeline_7d_period(self, client, db):
        db.insert_event("ban", "sshd", "1.2.3.4", "2026-03-15T12:00:00Z")
        resp = client.get("/api/v1/stats/timeline?period=7d", headers=auth_headers())
        assert resp.status_code == 200
        assert resp.json()["period"] == "7d"

    def test_timeline_invalid_period(self, client):
        resp = client.get("/api/v1/stats/timeline?period=1y", headers=auth_headers())
        assert resp.status_code == 422


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


# --- /api/v1/unban/bulk ---

class TestBulkUnban:
    def test_bulk_unban_requires_auth(self, client):
        resp = client.post("/api/v1/unban/bulk", json={"entries": []})
        assert resp.status_code == 401

    def test_bulk_unban_validates_entries(self, client):
        resp = client.post("/api/v1/unban/bulk",
                           json={"entries": [{"ip": "not-an-ip", "jail": "sshd"}]},
                           headers=auth_headers())
        assert resp.status_code == 422

    def test_bulk_unban_empty_entries(self, client):
        resp = client.post("/api/v1/unban/bulk",
                           json={"entries": []},
                           headers=auth_headers())
        assert resp.status_code == 200
        assert resp.json()["results"] == []

    def test_bulk_unban_returns_per_ip_results(self, client):
        resp = client.post("/api/v1/unban/bulk",
                           json={"entries": [
                               {"ip": "1.2.3.4", "jail": "sshd"},
                               {"ip": "5.6.7.8", "jail": "postfix"},
                           ]},
                           headers=auth_headers())
        assert resp.status_code == 200
        results = resp.json()["results"]
        assert len(results) == 2
        assert results[0]["ip"] == "1.2.3.4"
        assert "success" in results[0]


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
