from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from src.app import (
    ALL_ROLES,
    ROLE_ACCOUNT_RESET_PASSWORD,
    ROLE_ACCOUNT_UPDATE,
    ROLE_API_KEYS_READ,
    ROLE_API_KEYS_UPDATE,
    ROLE_DNS_ZONES_READ,
    ROLE_DNS_ZONES_UPDATE,
    ROLE_GLOBAL_READ,
    ROLE_PLUGIN_UPDATE,
    ROLE_SYSTEM_UPDATE,
    _serialize_roles,
    app,
    encode_zone_config_dict,
    normalize_zone_name,
    set_disabled_dns_plugins,
)
from src.auth import create_session_cookie
from src.db import SessionLocal, init_db
from src.dns_client import create_dns_client, discover_plugins, dns_provider_display_name
from src.models import ApiKey, ApiKeyAllowedZone, DnsZoneConfig, User
from src.plugins.bind import BindTsigDnsClient
from src.security import hash_password


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
        set_disabled_dns_plugins(db, set())
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
        "/zones",
        "/api-keys",
        "/zones/new",
        f"/zones/{zone.id}/edit",
        f"/api-keys/{api_key.id}/edit",
    ):
        response = client.get(path)
        assert response.status_code == 200


def test_zones_page_displays_zone_provider_metadata(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/zones")
    assert response.status_code == 200
    assert "Type" in response.text
    assert "Target DNS Server" in response.text
    assert "Azure DNS (REST API)" in response.text
    assert "&mdash;" in response.text


def test_builtin_dns_plugins_are_discovered() -> None:
    plugins = discover_plugins()
    assert set(plugins) >= {"azure", "bind", "microsoft"}
    assert plugins["azure"].label == "Azure DNS (REST API)"
    assert dns_provider_display_name("microsoft") == "Microsoft DNS (WinRM)"


def test_dns_client_factory_uses_plugin_registry() -> None:
    client = create_dns_client(
        {
            "dns_provider_type": "bind",
            "dns_username": "api-to-dns.",
            "dns_password": "c2VjcmV0",
            "dns_tsig_algorithm": "hmac-sha256",
        }
    )
    assert isinstance(client, BindTsigDnsClient)


def test_zone_form_renders_plugins_from_metadata(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/zones/new")
    assert response.status_code == 200
    assert '<option value="azure" selected>Azure DNS (REST API)</option>' in response.text
    assert '<option value="microsoft" >Microsoft DNS (WinRM)</option>' in response.text
    assert '<option value="bind" >BIND / RFC 2136 (TSIG)</option>' in response.text
    assert 'data-provider-panel="azure"' in response.text
    assert 'name="azure_tenant_id"' in response.text
    assert 'name="dns_winrm_ssl"' in response.text
    assert 'name="dns_tsig_algorithm"' in response.text


def test_zones_json_request_returns_zone_ids(client: TestClient) -> None:
    response = client.get("/zones", headers={"Accept": "application/json", "X-API-Key": "test-api-key-for-dns-endpoint"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    zones = response.json()
    example = next(zone for zone in zones if zone["zone_name"] == "example.com")
    assert isinstance(example["id"], int)
    assert set(zones[0]) == {"id", "zone_name"}


def test_zones_json_request_without_api_key_returns_access_denied(client: TestClient) -> None:
    response = client.get("/zones", headers={"Content-Type": "application/json"})
    assert response.status_code == 403
    assert response.json()["detail"] == {
        "error": "access_denied",
        "message": "You do not have access or an invalid key was provided.",
    }


def test_zones_json_schema_is_documented(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    zones_response = schema["paths"]["/zones"]["get"]["responses"]["200"]
    assert zones_response["content"]["application/json"]["schema"]["items"]["$ref"].endswith("/DnsZoneSummary")
    assert "DnsZoneSummary" in schema["components"]["schemas"]


def test_legacy_zone_page_routes_are_not_redirects(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/dns-zones", follow_redirects=False)
    assert response.status_code == 404


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


def test_api_key_management_routes_are_not_in_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api-keys" not in schema["paths"]
    assert "/api-keys/revoke" not in schema["paths"]
    assert not any(path.startswith("/api-keys/") for path in schema["paths"])


def test_session_backed_pages_are_not_in_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    hidden_paths = {
        "/",
        "/login",
        "/logout",
        "/admin",
        "/zones/new",
        "/zones/{zone_id}/edit",
        "/zones/{zone_id}",
        "/zones/{zone_id}/delete",
        "/settings",
        "/settings/users",
        "/settings/users/{user_id}/delete",
        "/settings/users/{user_id}/password",
        "/settings/users/{user_id}/roles",
        "/settings/account/password",
        "/settings/plugins/{plugin_key}/disable",
        "/settings/plugins/{plugin_key}/enable",
    }
    for path in hidden_paths:
        assert path not in schema["paths"]
    assert set(schema["paths"]) == {"/keycheck", "/zones", "/dns-record"}
    assert set(schema["paths"]["/zones"]) == {"get"}


def test_keycheck_unauthorized_response_is_documented(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    response = schema["paths"]["/keycheck"]["get"]["responses"]["401"]
    assert response["description"] == "Unauthorized"
    content = response["content"]["application/json"]
    assert content["example"] == {"status": "failure"}
    assert content["schema"]["required"] == ["status"]


def test_keycheck_success_response_is_documented(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    response = schema["paths"]["/keycheck"]["get"]["responses"]["200"]
    assert response["description"] == "API key is valid"
    content = response["content"]["application/json"]
    assert content["example"] == {"status": "success"}
    assert content["schema"]["required"] == ["status"]


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


def test_dns_record_schema_excludes_azure_zone_settings(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    request_schema = schema["components"]["schemas"]["DnsRecordRequest"]
    assert "subscription_id" not in request_schema["properties"]
    assert "resource_group" not in request_schema["properties"]


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


def _delete_users(db) -> None:
    for u in db.exec(select(User)).all():
        db.delete(u)
    db.commit()


def _create_user(db, username: str, password: str, roles=None) -> User:
    row = User(
        username=username,
        password_hash=hash_password(password),
        roles=_serialize_roles(roles or []),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_settings_redirects_to_login_without_session(client: TestClient) -> None:
    response = client.get("/settings", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_no_role_user_can_change_own_password_only(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("self-service"))
    with SessionLocal() as db:
        _delete_users(db)
        user = _create_user(db, "self-service", "old-password", [])
        original_hash = user.password_hash
        user_id = user.id
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings")
    assert response.status_code == 200
    assert "Authentication" in response.text
    assert "Change My Password" in response.text
    assert "Create user" not in response.text
    assert "Edit roles" not in response.text
    assert "Plugin Management" not in response.text
    assert "Activity Logging" not in response.text
    assert "System Backup" not in response.text

    response = client.post(
        "/settings/account/password",
        data={
            "current_password": "old-password",
            "new_password": "new-password",
            "confirm_password": "new-password",
        },
    )
    assert response.status_code == 200
    assert "Password changed." in response.text
    with SessionLocal() as db:
        changed = db.get(User, user_id)
        assert changed is not None
        assert changed.password_hash != original_hash


def test_self_password_change_rejects_wrong_current_password(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("self-service"))
    with SessionLocal() as db:
        _delete_users(db)
        user = _create_user(db, "self-service", "old-password", [])
        original_hash = user.password_hash
        user_id = user.id

    response = client.post(
        "/settings/account/password",
        data={
            "current_password": "wrong-password",
            "new_password": "new-password",
            "confirm_password": "new-password",
        },
    )
    assert response.status_code == 200
    assert "Current password is incorrect." in response.text
    with SessionLocal() as db:
        unchanged = db.get(User, user_id)
        assert unchanged is not None
        assert unchanged.password_hash == original_hash


def test_self_password_change_rejects_mismatched_confirmation(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("self-service"))
    with SessionLocal() as db:
        _delete_users(db)
        user = _create_user(db, "self-service", "old-password", [])
        original_hash = user.password_hash
        user_id = user.id

    response = client.post(
        "/settings/account/password",
        data={
            "current_password": "old-password",
            "new_password": "new-password",
            "confirm_password": "different-password",
        },
    )
    assert response.status_code == 200
    assert "New password and confirmation do not match." in response.text
    with SessionLocal() as db:
        unchanged = db.get(User, user_id)
        assert unchanged is not None
        assert unchanged.password_hash == original_hash


def test_settings_renders_for_authenticated_session(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings")
    assert response.status_code == 200
    assert "Settings" in response.text
    assert 'class="settings-sidebar"' in response.text
    assert 'class="settings-menu"' in response.text
    assert 'data-requires-role="api_keys.read"' in response.text
    assert 'data-requires-role="dns_zones.read"' in response.text
    assert "setForcedReadRole(requiredInput, changedInput.checked)" in response.text
    assert 'classList.toggle("role-forced", forced)' in response.text
    assert "Authentication" in response.text
    assert "Plugin Management" in response.text
    assert "Activity Logging" in response.text
    assert "System Backup" in response.text


def test_settings_route_hidden_from_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/settings" not in schema["paths"]
    assert not any(path.startswith("/settings") for path in schema["paths"])


def test_admin_page_links_to_settings(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/admin")
    assert response.status_code == 200
    assert 'href="/settings"' in response.text


def test_dashboard_disables_zone_and_api_key_buttons_without_roles(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("limited"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "limited", "x", [])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/admin")
    assert response.status_code == 200
    assert '<span class="button disabled" aria-disabled="true">DNS Zones</span>' in response.text
    assert '<span class="button disabled" aria-disabled="true">API Keys</span>' in response.text
    assert 'href="/zones"' not in response.text
    assert 'href="/api-keys"' not in response.text


def test_dashboard_enables_role_allowed_buttons(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("reader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "reader", "x", [ROLE_DNS_ZONES_READ, ROLE_API_KEYS_UPDATE])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/admin")
    assert response.status_code == 200
    assert '<a class="button" href="/zones">DNS Zones</a>' in response.text
    assert '<a class="button" href="/api-keys">API Keys</a>' in response.text


def test_create_user_form_defaults_to_no_roles_selected(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings")
    assert response.status_code == 200
    create_dialog = response.text.split('<dialog id="create-user-dialog"', 1)[1].split("</dialog>", 1)[0]
    assert "checked" not in create_dialog
    assert "global.read" in create_dialog
    assert "api_keys.read" in create_dialog
    assert "dns_zones.read" in create_dialog
    assert "account.read" not in create_dialog
    assert "system.read" not in create_dialog


def test_settings_create_user_persists_account(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.post(
        "/settings/users",
        data={
            "username": "alice",
            "password": "passw0rd!",
            "roles": [ROLE_DNS_ZONES_READ, ROLE_API_KEYS_READ],
        },
    )
    assert response.status_code == 200
    assert "alice" in response.text and "created" in response.text

    with SessionLocal() as db:
        alice = db.exec(select(User).where(User.username == "alice")).first()
        assert alice is not None
        assert set((alice.roles or "").split(",")) == {ROLE_DNS_ZONES_READ, ROLE_API_KEYS_READ}


def test_settings_create_user_update_role_adds_read_role(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.post(
        "/settings/users",
        data={
            "username": "api-editor",
            "password": "passw0rd!",
            "roles": [ROLE_API_KEYS_UPDATE],
        },
    )
    assert response.status_code == 200

    with SessionLocal() as db:
        api_editor = db.exec(select(User).where(User.username == "api-editor")).first()
        assert api_editor is not None
        assert set((api_editor.roles or "").split(",")) == {ROLE_API_KEYS_READ, ROLE_API_KEYS_UPDATE}


def test_settings_update_roles_update_role_adds_read_role(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        zone_editor = _create_user(db, "zone-editor", "secret", [ROLE_API_KEYS_READ])
        zone_editor_id = zone_editor.id

    response = client.post(
        f"/settings/users/{zone_editor_id}/roles",
        data={"roles": [ROLE_DNS_ZONES_UPDATE]},
    )
    assert response.status_code == 200

    with SessionLocal() as db:
        zone_editor = db.get(User, zone_editor_id)
        assert zone_editor is not None
        assert set((zone_editor.roles or "").split(",")) == {ROLE_DNS_ZONES_READ, ROLE_DNS_ZONES_UPDATE}


def test_settings_reset_password_updates_hash(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        bob = _create_user(db, "bob", "original", [ROLE_DNS_ZONES_READ])
        original_hash = bob.password_hash
        bob_id = bob.id

    response = client.post(
        f"/settings/users/{bob_id}/password",
        data={"password": "brand-new"},
    )
    assert response.status_code == 200
    assert "Password reset" in response.text and "bob" in response.text
    with SessionLocal() as db:
        bob = db.get(User, bob_id)
        assert bob is not None
        assert bob.password_hash != original_hash


def test_settings_delete_user_removes_account(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        carol = _create_user(db, "carol", "secret", [ROLE_API_KEYS_READ])
        carol_id = carol.id

    response = client.post(f"/settings/users/{carol_id}/delete")
    assert response.status_code == 200
    assert "carol" in response.text and "deleted" in response.text
    with SessionLocal() as db:
        assert db.get(User, carol_id) is None


def test_settings_cannot_delete_current_user(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("dave"))
    with SessionLocal() as db:
        _delete_users(db)
        dave = _create_user(db, "dave", "secret", ALL_ROLES)
        _create_user(db, "extra", "secret", ALL_ROLES)
        dave_id = dave.id

    response = client.post(f"/settings/users/{dave_id}/delete")
    assert response.status_code == 200
    assert "You cannot delete the user you are signed in as." in response.text
    with SessionLocal() as db:
        assert db.get(User, dave_id) is not None


def test_settings_cannot_delete_last_user(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        only = _create_user(db, "only", "secret", ALL_ROLES)
        only_id = only.id

    response = client.post(f"/settings/users/{only_id}/delete")
    assert response.status_code == 200
    assert "At least one user account must remain." in response.text
    with SessionLocal() as db:
        assert db.get(User, only_id) is not None


def test_user_without_roles_only_gets_self_service_authentication(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("limited"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "limited", "x", [])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings?area=plugins")
    assert response.status_code == 200
    assert "Authentication" in response.text
    assert "Change My Password" in response.text
    assert "Plugin Management" not in response.text
    assert "Create user" not in response.text


def test_bootstrap_admin_user_receives_all_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.app import startup_event

    monkeypatch.setenv("ADMIN_USER", "bootstrap-admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "bootstrap-secret")
    init_db()
    with SessionLocal() as db:
        db.exec(select(User).where(User.username == "bootstrap-admin"))
        existing = db.exec(select(User).where(User.username == "bootstrap-admin")).first()
        if existing:
            db.delete(existing)
            db.commit()

    startup_event()

    with SessionLocal() as db:
        admin = db.exec(select(User).where(User.username == "bootstrap-admin")).first()
        assert admin is not None
        assert set((admin.roles or "").split(",")) == set(ALL_ROLES)


def test_plugin_update_does_not_show_authentication_area(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("limited"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "limited", "x", [ROLE_PLUGIN_UPDATE])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings")
    assert response.status_code == 200
    assert "Plugin Management" in response.text
    assert "Create user" not in response.text


def test_settings_create_user_requires_account_update_role(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("readonly"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "readonly", "x", [ROLE_GLOBAL_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.post(
        "/settings/users",
        data={"username": "nope", "password": "x", "roles": []},
    )
    assert response.status_code == 403


def test_settings_reset_password_requires_reset_role(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("updater"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "updater", "x", [ROLE_ACCOUNT_UPDATE])
        target = _create_user(db, "target", "x", [])
        _create_user(db, "admin", "x", ALL_ROLES)
        target_id = target.id

    response = client.post(
        f"/settings/users/{target_id}/password",
        data={"password": "new-pass"},
    )
    assert response.status_code == 403


def test_settings_plugins_area_lists_discovered_plugins(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=plugins")
    assert response.status_code == 200
    assert "Plugin Management" in response.text
    assert "Azure DNS (REST API)" in response.text
    assert "Microsoft DNS (WinRM)" in response.text
    assert "BIND / RFC 2136 (TSIG)" in response.text
    assert "azure_tenant_id" in response.text
    assert "<details" in response.text
    assert "Configuration fields" in response.text


def test_global_read_can_view_plugins_without_update_controls(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("global-reader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "global-reader", "x", [ROLE_GLOBAL_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings?area=plugins")
    assert response.status_code == 200
    assert "Plugin Management" in response.text
    assert "/settings/plugins/bind/disable" not in response.text

    response = client.post("/settings/plugins/bind/disable")
    assert response.status_code == 403


def test_plugin_update_role_can_read_and_update_plugins(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("plugin-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "plugin-admin", "x", [ROLE_PLUGIN_UPDATE])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings?area=plugins")
    assert response.status_code == 200
    assert "Plugin Management" in response.text
    assert "/settings/plugins/bind/disable" in response.text

    response = client.post("/settings/plugins/bind/disable")
    assert response.status_code == 200
    assert "BIND / RFC 2136 (TSIG) disabled." in response.text


def test_global_read_can_view_read_only_pages(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("global-reader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "global-reader", "x", [ROLE_GLOBAL_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    for path, expected_text in (
        ("/settings?area=authentication", "Authentication"),
        ("/settings?area=plugins", "Plugin Management"),
        ("/settings?area=logging", "Activity Logging"),
        ("/settings?area=backup", "System Backup"),
        ("/zones", "Configured zones"),
        ("/api-keys", "Existing API keys"),
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert expected_text in response.text


def test_account_update_can_view_authentication_without_global_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("account-updater"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "account-updater", "x", [ROLE_ACCOUNT_UPDATE])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings?area=authentication")
    assert response.status_code == 200
    assert "Authentication" in response.text
    assert "Plugin Management" not in response.text


def test_system_update_can_view_system_placeholders_without_global_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("system-updater"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "system-updater", "x", [ROLE_SYSTEM_UPDATE])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings?area=logging")
    assert response.status_code == 200
    assert "Activity Logging" in response.text
    assert "System Backup" in response.text
    assert "Authentication" in response.text
    assert "Plugin Management" not in response.text


def test_disabling_unused_plugin_greys_card_and_hides_fields(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post("/settings/plugins/bind/disable")
    assert response.status_code == 200
    assert "BIND / RFC 2136 (TSIG) disabled." in response.text
    assert 'class="plugin-card disabled"' in response.text
    assert "dns_tsig_algorithm" not in response.text


def test_enabling_disabled_plugin_restores_fields(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    disable_response = client.post("/settings/plugins/bind/disable")
    assert disable_response.status_code == 200

    response = client.post("/settings/plugins/bind/enable")
    assert response.status_code == 200
    assert "BIND / RFC 2136 (TSIG) enabled." in response.text
    assert "dns_tsig_algorithm" in response.text


def test_disabling_plugin_used_by_zone_fails_with_zone_name(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post("/settings/plugins/azure/disable")
    assert response.status_code == 200
    assert "Cannot disable Azure DNS (REST API)." in response.text
    assert "example.com" in response.text


def test_disabling_last_enabled_plugin_is_blocked(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        for link in db.exec(select(ApiKeyAllowedZone)).all():
            db.delete(link)
        for zone in db.exec(select(DnsZoneConfig)).all():
            db.delete(zone)
        db.commit()

    assert client.post("/settings/plugins/bind/disable").status_code == 200
    assert client.post("/settings/plugins/microsoft/disable").status_code == 200
    response = client.post("/settings/plugins/azure/disable")
    assert response.status_code == 200
    assert "At least one DNS provider plugin must remain enabled." in response.text


def test_disabled_plugins_are_absent_from_new_zone_form(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post("/settings/plugins/bind/disable")
    assert response.status_code == 200

    response = client.get("/zones/new")
    assert response.status_code == 200
    assert '<option value="bind"' not in response.text
    assert '<option value="azure"' in response.text


def test_manual_zone_create_with_disabled_provider_is_rejected(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post("/settings/plugins/bind/disable")
    assert response.status_code == 200

    response = client.post(
        "/zones",
        data={
            "zone_name": "disabled-provider.example",
            "dns_provider_type": "bind",
            "dns_server": "127.0.0.1",
            "dns_username": "api-to-dns.",
            "dns_password": "secret",
            "dns_tsig_algorithm": "hmac-sha256",
        },
    )
    assert response.status_code == 200
    assert "BIND / RFC 2136 (TSIG) is disabled." in response.text
    with SessionLocal() as db:
        assert (
            db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == "disabled-provider.example")).first()
            is None
        )


def test_settings_logging_area_renders_placeholder(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=logging")
    assert response.status_code == 200
    assert "Activity Logging" in response.text
    assert "not implemented yet" in response.text


def test_settings_backup_area_renders_placeholder(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=backup")
    assert response.status_code == 200
    assert "System Backup" in response.text
    assert "not implemented yet" in response.text


def test_settings_backup_area_requires_global_read_or_system_update(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("limited"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "limited", "x", [ROLE_API_KEYS_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings?area=backup")
    assert response.status_code == 200
    assert "System Backup" not in response.text
    assert "Authentication" in response.text


def test_zones_html_requires_dns_zones_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("noreader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "noreader", "x", [ROLE_API_KEYS_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/zones", follow_redirects=False)
    assert response.status_code == 403
    assert '<div class="alert error">You do not have permission to access this resource.</div>' in response.text


def test_dns_zones_read_can_view_zones_without_global_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("zone-reader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "zone-reader", "x", [ROLE_DNS_ZONES_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/zones")
    assert response.status_code == 200
    assert "Configured zones" in response.text


def test_api_keys_page_requires_api_keys_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("nokeyread"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "nokeyread", "x", [ROLE_DNS_ZONES_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/api-keys")
    assert response.status_code == 403
    assert '<div class="alert error">You do not have permission to access this resource.</div>' in response.text


def test_api_keys_read_can_view_api_keys_without_global_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("key-reader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "key-reader", "x", [ROLE_API_KEYS_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/api-keys")
    assert response.status_code == 200
    assert "Existing API keys" in response.text


def test_zone_mutation_requires_dns_zones_update(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("zonereader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "zonereader", "x", [ROLE_DNS_ZONES_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/zones/new")
    assert response.status_code == 403


def test_api_key_mutation_requires_api_keys_update(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("keyreader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "keyreader", "x", [ROLE_API_KEYS_READ])
        _create_user(db, "admin", "x", ALL_ROLES)
        api_key = db.exec(select(ApiKey)).first()
        assert api_key is not None
        key_id = api_key.id

    response = client.post("/api-keys/revoke", data={"key_id": str(key_id)})
    assert response.status_code == 403


def test_api_key_post_to_dns_record_unaffected_by_session_roles(
    client: TestClient,
    api_key_value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SessionLocal() as db:
        _delete_users(db)

    fake = MagicMock()
    fake.create_or_update_record.return_value = False
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.post(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 200
