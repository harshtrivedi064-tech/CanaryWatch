import os
from concurrent.futures import ThreadPoolExecutor
os.environ["DATABASE_URL"] = "sqlite:///./test_canarywatch.db"
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, engine

client = TestClient(app, client=("127.0.0.1", 50000))

def setup_function():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def test_health():
    assert client.get("/api/v1/health").status_code == 200

def test_create_trigger_and_rotate():
    created = client.post("/api/v1/honeytokens", json={
        "name": "Test canary", "kind": "API credential", "environment": "test", "severity": "high"
    })
    assert created.status_code == 200
    token = created.json()
    assert token["status"] == "active"
    triggered = client.post(f"/api/v1/demo/trigger/{token['id']}")
    assert triggered.status_code == 200
    assert triggered.json()["incident"]["severity"] == "high"
    assert client.post(f"/api/v1/demo/trigger/{token['id']}").status_code == 409
    rotated = client.post(f"/api/v1/honeytokens/{token['id']}/rotate")
    assert rotated.status_code == 200
    assert rotated.json()["rotation_of"] == token["id"]

def test_unknown_token():
    assert client.post("/api/v1/demo/trigger/not-real").status_code == 404

def test_demo_start_is_idempotent():
    first = client.post("/api/v1/demo/start")
    second = client.post("/api/v1/demo/start")

    assert first.json() == {"status": "initialized", "created": 4}
    assert second.json() == {"status": "already_initialized", "created": 0}
    assert len(client.get("/api/v1/honeytokens").json()) == 4

def test_concurrent_demo_start_does_not_duplicate_seeds():
    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(
            lambda _: client.post("/api/v1/demo/start"),
            range(4),
        ))

    assert sum(response.json()["created"] for response in responses) == 4
    assert len(client.get("/api/v1/honeytokens").json()) == 4

def test_reset_restores_baseline_and_clears_incidents():
    client.post("/api/v1/demo/start")
    token = client.get("/api/v1/honeytokens").json()[0]
    client.post(f"/api/v1/demo/trigger/{token['id']}")

    reset = client.post("/api/v1/demo/reset")
    summary = client.get("/api/v1/dashboard/summary").json()

    assert reset.json()["created"] == 4
    assert summary["active_honeytokens"] == 4
    assert summary["triggered_decoys"] == 0
    assert summary["open_incidents"] == 0
    assert client.get("/api/v1/incidents").json() == []

def test_trigger_broadcasts_websocket_alert():
    client.post("/api/v1/demo/start")
    token = client.get("/api/v1/honeytokens").json()[0]

    with client.websocket_connect("/api/v1/ws/alerts") as websocket:
        response = client.post(f"/api/v1/demo/trigger/{token['id']}")
        alert = websocket.receive_json()

    assert response.status_code == 200
    assert alert["type"] == "incident.created"
    assert alert["token_id"] == token["id"]

def test_frontend_origins_are_allowed():
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        response = client.options(
            "/api/v1/honeytokens",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin

def test_ip_is_blocked_after_four_failed_triggers_and_can_be_unblocked():
    for _ in range(3):
        assert client.post("/api/v1/demo/trigger/not-real").status_code == 404

    blocked = client.post("/api/v1/demo/trigger/not-real")
    assert blocked.status_code == 403
    assert client.post("/api/v1/demo/trigger/not-real").status_code == 403

    entry = next(item for item in client.get("/api/v1/ip-blocks").json() if item["ip_address"] == "127.0.0.1")
    assert entry["failed_attempts"] == 4
    assert entry["blocked"] is True

    assert client.post("/api/v1/ip-blocks/not-an-ip/unblock").status_code == 422
    unblocked = client.post("/api/v1/ip-blocks/127.0.0.1/unblock")
    assert unblocked.status_code == 200
    assert unblocked.json()["blocked"] is False
    assert unblocked.json()["failed_attempts"] == 0
    assert client.post("/api/v1/demo/trigger/not-real").status_code == 404

def test_successful_trigger_does_not_count_as_failed_ip_attempt():
    token = client.post("/api/v1/honeytokens", json={
        "name": "Valid trigger", "kind": "API credential", "environment": "test", "severity": "low"
    }).json()

    assert client.post(f"/api/v1/demo/trigger/{token['id']}").status_code == 200
    assert client.get("/api/v1/ip-blocks").json() == []

def test_latency_analytics_reports_measured_trigger_samples():
    empty = client.get("/api/v1/analytics/latency").json()
    assert empty["sample_count"] == 0
    assert empty["min_ms"] is None
    assert empty["median_ms"] is None
    assert empty["p95_ms"] is None
    assert empty["max_ms"] is None

    token = client.post("/api/v1/honeytokens", json={
        "name": "Latency canary", "kind": "API credential", "environment": "test", "severity": "medium"
    }).json()
    client.post(f"/api/v1/demo/trigger/{token['id']}")

    measured = client.get("/api/v1/analytics/latency").json()
    assert measured["sample_count"] == 1
    assert measured["min_ms"] == measured["median_ms"] == measured["p95_ms"] == measured["max_ms"]
    assert measured["min_ms"] >= 0
    assert "not network-wide detection latency" in measured["note"]

def test_guided_demo_scenario_creates_four_synthetic_incidents():
    response = client.post("/api/v1/demo/scenario")
    result = response.json()

    assert response.status_code == 200
    assert result["triggered_count"] == 4
    assert len(result["incidents"]) == 4
    assert len(client.get("/api/v1/incidents").json()) == 4
    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["triggered_decoys"] == 4
    assert summary["open_incidents"] == 4
    assert client.get("/api/v1/analytics/latency").json()["sample_count"] == 4

def test_demo_ip_protection_simulator_and_reset():
    simulated = client.post("/api/v1/demo/ip-protection/simulate")
    assert simulated.status_code == 200
    assert simulated.json()["failed_attempts"] == 4
    assert simulated.json()["blocked"] is True
    client.post("/api/v1/demo/ip-protection/simulate")
    assert len([item for item in client.get("/api/v1/audit").json() if item["action"] == "IP_BLOCKED"]) == 1

    assert client.post("/api/v1/demo/reset").status_code == 200
    assert client.get("/api/v1/ip-blocks").json() == []
