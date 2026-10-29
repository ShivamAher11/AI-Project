from fastapi.testclient import TestClient

from app.main import app


def test_health_returns_200_and_request_id():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-request-id"]


def test_cors_preflight_matches_spec_allowlist():
    response = TestClient(app).options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type,accept,last-event-id",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert {method.strip() for method in response.headers["access-control-allow-methods"].split(",")} == {"GET", "POST", "DELETE", "OPTIONS"}
    assert {header.strip().lower() for header in response.headers["access-control-allow-headers"].split(",")} == {"content-type", "accept", "last-event-id"}
    assert "access-control-allow-credentials" not in response.headers


def test_http_errors_use_the_request_id_envelope():
    response = TestClient(app).get("/not-a-route")
    assert response.status_code == 404
    assert set(response.json()) == {"error"}
    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]
