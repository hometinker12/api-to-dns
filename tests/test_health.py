"""Tests for health and readiness endpoints."""

from fastapi.testclient import TestClient


def test_health_returns_ok_without_db(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_returns_ready_when_db_available(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_ready_returns_not_ready_when_db_unavailable(client: TestClient, monkeypatch) -> None:
    class BrokenSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def exec(self, *_args, **_kwargs):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr("src.routes.health.SessionLocal", lambda: BrokenSession())
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
