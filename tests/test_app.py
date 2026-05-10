from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from src.app import app
from src.db import SessionLocal, init_db
from src.models import ApiKey


@pytest.fixture
def api_key_value() -> str:
    return "test-api-key-for-dns-endpoint"


@pytest.fixture
def client(api_key_value: str) -> TestClient:
    init_db()
    with SessionLocal() as db:
        if not db.exec(select(ApiKey).where(ApiKey.key == api_key_value)).first():
            db.add(ApiKey(label="pytest", key=api_key_value, active=True))
            db.commit()
    return TestClient(app)


def test_dns_record_requires_api_key(client: TestClient) -> None:
    response = client.post(
        "/dns-record",
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 401


def test_dns_record_with_mock_client(client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = MagicMock()
    fake.create_or_update_record.return_value = False
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.post(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "subscription_id": "00000000-0000-0000-0000-000000000001",
            "resource_group": "rg-test",
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["action"] == "created"
    fake.create_or_update_record.assert_called_once()
