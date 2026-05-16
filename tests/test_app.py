from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from src.app import app, encode_zone_config_dict, normalize_zone_name
from src.auth import create_session_cookie
from src.db import SessionLocal, init_db
from src.models import ApiKey, ApiKeyAllowedZone, DnsZoneConfig


@pytest.fixture
def api_key_value() -> str:
    return "test-api-key-for-dns-endpoint"


def _seed_example_zone_and_permission(db, api_key_value: str) -> None:
    if not db.exec(select(ApiKey).where(ApiKey.key == api_key_value)).first():
        db.add(ApiKey(label="pytest", key=api_key_value, active=True))
        db.commit()
    key = db.exec(select(ApiKey).where(ApiKey.key == api_key_value)).first()
    zname = normalize_zone_name("example.com")
    zone = db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == zname)).first()
    if not zone:
        cfg = {
            "dns_provider_type": "azure",
            "dns_server": "",
            "dns_username": "",
            "dns_password": "",
            "dns_tsig_algorithm": "",
            "dns_winrm_ssl": "",
            "azure_tenant_id": "",
            "azure_client_id": "",
            "azure_client_secret": "",
            "azure_subscription_id": "00000000-0000-0000-0000-000000000001",
            "azure_resource_group": "rg-test",
        }
        zone = DnsZoneConfig(zone_name=zname, encrypted_config=encode_zone_config_dict(cfg))
        db.add(zone)
        db.commit()
        db.refresh(zone)
    if not db.exec(
        select(ApiKeyAllowedZone).where(
            ApiKeyAllowedZone.api_key_id == key.id,
            ApiKeyAllowedZone.dns_zone_config_id == zone.id,
        )
    ).first():
        db.add(ApiKeyAllowedZone(api_key_id=key.id, dns_zone_config_id=zone.id))
        db.commit()


@pytest.fixture
def client(api_key_value: str) -> TestClient:
    init_db()
    with SessionLocal() as db:
        _seed_example_zone_and_permission(db, api_key_value)
    return TestClient(app)


def test_root_redirects_to_login_without_session(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_admin_redirects_to_login_without_session(client: TestClient) -> None:
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_api_auth_failure_still_returns_json(client: TestClient) -> None:
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
    assert response.json()["detail"] == "API key is required"


def test_authenticated_web_pages_render(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        zone = db.exec(select(DnsZoneConfig)).first()
        api_key = db.exec(select(ApiKey)).first()
        assert zone is not None
        assert api_key is not None
    for path in (
        "/admin",
        "/settings",
        "/api-keys",
        "/zones/new",
        f"/zones/{zone.id}/edit",
        f"/api-keys/{api_key.id}/edit",
    ):
        response = client.get(path)
        assert response.status_code == 200


def test_settings_page_displays_zone_provider_metadata(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings")
    assert response.status_code == 200
    assert "Type" in response.text
    assert "Target DNS Server" in response.text
    assert "Azure" in response.text
    assert "&mdash;" in response.text


def test_create_api_key_without_zone_keeps_error_in_popup(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post("/api-keys", data={"label": "missing-zone"})
    assert response.status_code == 200
    assert '<dialog id="create-key-dialog"' in response.text
    assert 'data-auto-open="true"' in response.text
    assert '<div class="alert error">Select at least one DNS zone for this API key.</div>' in response.text
    assert 'value="missing-zone"' in response.text
    assert "createDialog?.showModal();" in response.text


def test_edit_api_key_posts_to_api_keys_page(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        api_key = db.exec(select(ApiKey)).first()
        zone = db.exec(select(DnsZoneConfig)).first()
        assert api_key is not None
        assert zone is not None

    response = client.post(
        "/api-keys",
        data={"key_id": str(api_key.id), "label": "renamed-key", "zone_ids": str(zone.id)},
    )

    assert response.status_code == 200
    assert str(response.url).endswith("/api-keys")
    assert "API key updated." in response.text
    assert "renamed-key" in response.text


def test_edit_api_key_without_zone_keeps_error_in_popup(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        api_key = db.exec(select(ApiKey)).first()
        assert api_key is not None

    response = client.post("/api-keys", data={"key_id": str(api_key.id), "label": "bad-edit"})

    assert response.status_code == 200
    assert str(response.url).endswith("/api-keys")
    assert 'data-auto-open="true"' in response.text
    assert '<div class="alert error">Select at least one DNS zone.</div>' in response.text
    assert 'value="bad-edit"' in response.text


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


def test_dns_record_delete_with_mock_client(client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = MagicMock()
    fake.create_or_update_record.return_value = True
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.post(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "subscription_id": "00000000-0000-0000-0000-000000000001",
            "resource_group": "rg-test",
            "zone_name": "example.com",
            "record_type": "DELETE",
            "record_name": "www",
            "values": ["A"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["action"] == "deleted"
    fake.create_or_update_record.assert_called_once()


def test_dns_record_delete_not_found_returns_404(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
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
            "record_type": "DELETE",
            "record_name": "missing",
            "values": ["A"],
        },
    )
    assert response.status_code == 404
    body = response.json()
    assert body["status"] == "error"
    assert body["action"] == "not_found"


def test_dns_record_provider_runtime_error_returns_502(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = MagicMock()
    fake.create_or_update_record.side_effect = RuntimeError("WinRM/PowerShell failed (1): example")
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
    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "dns_provider_failed"
    assert "WinRM" in detail["message"]


def test_dns_record_access_denied_unknown_zone(client: TestClient, api_key_value: str) -> None:
    response = client.post(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "not-configured.example",
            "record_type": "A",
            "record_name": "www",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "access_denied"


def test_dns_record_access_denied_zone_not_allowed(client: TestClient, api_key_value: str) -> None:
    with SessionLocal() as db:
        other = normalize_zone_name("other.example")
        if not db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == other)).first():
            cfg = {
                "dns_provider_type": "azure",
                "dns_server": "",
                "dns_username": "",
                "dns_password": "",
                "dns_tsig_algorithm": "",
                "dns_winrm_ssl": "",
                "azure_tenant_id": "",
                "azure_client_id": "",
                "azure_client_secret": "",
                "azure_subscription_id": "00000000-0000-0000-0000-000000000001",
                "azure_resource_group": "rg-test",
            }
            db.add(DnsZoneConfig(zone_name=other, encrypted_config=encode_zone_config_dict(cfg)))
            db.commit()

    response = client.post(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "other.example",
            "record_type": "A",
            "record_name": "www",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "access_denied"


def test_dns_record_requires_zone_name(client: TestClient, api_key_value: str) -> None:
    response = client.post(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "record_type": "A",
            "record_name": "www",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 400
