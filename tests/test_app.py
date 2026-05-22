import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from itsdangerous import SignatureExpired
from sqlmodel import select

import src.activity_logging as activity_logging
import src.auth as auth_module
from src.activity_logging import (
    emit_activity_event,
    infer_event_category,
    query_activity_logs,
    render_alert_template,
    run_retention_cleanup,
    set_log_level,
    set_retention_days,
    set_smtp_config,
)
from src.app import (
    ALL_ROLES,
    ROLE_GLOBAL_ADMIN,
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
    get_user_roles,
    user_has_role,
    normalize_zone_name,
    set_disabled_dns_plugins,
)
from src.auth import SESSION_IDLE_TIMEOUT_SECONDS, create_session_cookie
from src.db import SessionLocal, init_db
from src.dns_client import create_dns_client, discover_plugins, dns_provider_display_name
from src.models import (
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
    ActivityLog,
    AlertRule,
    ApiKey,
    ApiKeyAllowedZone,
    DnsZoneConfig,
    User,
)
from src.plugins.bind import BindTsigDnsClient
from src.security import hash_password
from src.time_utils import utc_now


def test_root_redirects_to_login_without_session(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_admin_redirects_to_login_without_session(client: TestClient) -> None:
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_login_sets_fifteen_minute_session_cookie(client: TestClient) -> None:
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.post(
        "/login",
        data={"username": "admin", "password": "x"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    set_cookie = response.headers["set-cookie"]
    assert "session=" in set_cookie
    assert f"Max-Age={SESSION_IDLE_TIMEOUT_SECONDS}" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie


def test_authenticated_page_refreshes_session_cookie(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))

    response = client.get("/admin")
    assert response.status_code == 200
    set_cookie = response.headers["set-cookie"]
    assert "session=" in set_cookie
    assert f"Max-Age={SESSION_IDLE_TIMEOUT_SECONDS}" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie


def test_invalid_session_redirects_to_login_without_refresh(client: TestClient) -> None:
    client.cookies.set("session", "not-a-valid-session-cookie")

    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "set-cookie" not in response.headers


def test_expired_session_redirects_to_login_without_refresh(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def expired_session(_: str) -> str:
        raise SignatureExpired("expired")

    client.cookies.set("session", create_session_cookie("admin"))
    monkeypatch.setattr(auth_module, "verify_session_cookie", expired_session)

    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "set-cookie" not in response.headers


def test_deleted_session_user_redirects_to_login(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("deleted-user"))
    with SessionLocal() as db:
        _delete_users(db)
        user = _create_user(db, "deleted-user", "x", ALL_ROLES)
        _create_user(db, "admin", "x", ALL_ROLES)
        db.delete(user)
        db.commit()

    for path in ("/admin", "/settings", "/zones"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_disabled_user_cannot_login(client: TestClient) -> None:
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "disabled-user", "x", ALL_ROLES, disabled=True)
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.post(
        "/login",
        data={"username": "disabled-user", "password": "x"},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Invalid credentials." in response.text
    assert "set-cookie" not in response.headers


def test_disabled_session_user_redirects_to_login(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("disabled-user"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "disabled-user", "x", ALL_ROLES, disabled=True)
        _create_user(db, "admin", "x", ALL_ROLES)

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
    assert set(plugins) >= {"azure", "bind", "cloudflare", "microsoft"}
    assert plugins["azure"].label == "Azure DNS (REST API)"
    assert plugins["cloudflare"].label == "Cloudflare DNS (REST API)"
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
    assert '<option value="cloudflare" >Cloudflare DNS (REST API)</option>' in response.text
    assert 'data-provider-panel="azure"' in response.text
    assert 'data-provider-panel="cloudflare"' in response.text
    assert 'name="azure_tenant_id"' in response.text
    assert 'name="cloudflare_api_token"' in response.text
    assert 'name="cloudflare_proxied"' in response.text
    assert 'name="dns_winrm_ssl"' in response.text
    assert 'name="dns_tsig_algorithm"' in response.text
    assert 'id="zone-test-btn"' in response.text
    assert 'id="test-record-type"' in response.text


def test_zone_test_requires_auth(client: TestClient) -> None:
    response = client.post(
        "/zones/test",
        data={
            "zone_name": "example.com",
            "test_record_name": "@",
            "dns_provider_type": "azure",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_zone_test_success(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    from src.models import DnsRecordInfo

    monkeypatch.setattr(
        "src.app.test_zone_record_lookup",
        lambda _cfg, **kwargs: [
            DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])
        ],
    )
    response = client.post(
        "/zones/test",
        data={
            "zone_name": "example.com",
            "test_record_name": "www",
            "test_record_type": "A",
            "dns_provider_type": "azure",
            "azure_tenant_id": "tenant",
            "azure_client_id": "client",
            "azure_client_secret": "secret",
            "azure_subscription_id": "sub",
            "azure_resource_group": "rg",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["records"] == [
        {"record_name": "www", "record_type": "A", "ttl": 300, "values": ["192.0.2.1"]}
    ]
    assert set(body["records"][0]) == {"record_name", "record_type", "ttl", "values"}


def test_zone_test_not_found(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    monkeypatch.setattr("src.app.test_zone_record_lookup", lambda _cfg, **kwargs: [])
    response = client.post(
        "/zones/test",
        data={
            "zone_name": "example.com",
            "test_record_name": "missing",
            "dns_provider_type": "azure",
            "azure_tenant_id": "tenant",
            "azure_client_id": "client",
            "azure_client_secret": "secret",
            "azure_subscription_id": "sub",
            "azure_resource_group": "rg",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "not_found"
    assert body["records"] == []


def test_zone_test_invalid_record_type(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/zones/test",
        data={
            "zone_name": "example.com",
            "test_record_name": "www",
            "test_record_type": "MX",
            "dns_provider_type": "azure",
            "azure_tenant_id": "tenant",
            "azure_client_id": "client",
            "azure_client_secret": "secret",
            "azure_subscription_id": "sub",
            "azure_resource_group": "rg",
        },
    )
    assert response.status_code == 400
    assert response.json()["status"] == "error"


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
        "/settings/users/{user_id}/disable",
        "/settings/users/{user_id}/enable",
        "/settings/users/{user_id}/delete",
        "/settings/users/{user_id}/password",
        "/settings/users/{user_id}/roles",
        "/settings/account/password",
        "/settings/plugins/{plugin_key}/disable",
        "/settings/plugins/{plugin_key}/enable",
        "/settings/system/log-level",
        "/settings/system/retention",
        "/settings/system/smtp",
        "/settings/system/log-rotation",
        "/settings/alerts",
        "/settings/alerts/{rule_id}",
        "/settings/alerts/{rule_id}/delete",
    }
    for path in hidden_paths:
        assert path not in schema["paths"]
    assert set(schema["paths"]) == {"/keycheck", "/zones", "/dns-record"}
    assert set(schema["paths"]["/zones"]) == {"get"}
    assert set(schema["paths"]["/dns-record"]) == {"get", "post", "put", "patch", "delete"}


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


def test_dns_record_get_schema_is_documented(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    get_op = schema["paths"]["/dns-record"]["get"]
    param_names = {param["name"] for param in get_op["parameters"]}
    assert {"zone_name", "record_name", "record_type", "X-API-Key", "Authorization"} <= param_names
    response_schema = get_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert response_schema["$ref"].endswith("/DnsRecordGetResponse")
    assert "DnsRecordGetResponse" in schema["components"]["schemas"]
    assert "DnsRecordInfo" in schema["components"]["schemas"]
    records_items = schema["components"]["schemas"]["DnsRecordGetResponse"]["properties"]["records"]["items"]
    assert records_items["$ref"].endswith("/DnsRecordInfo")


def test_dns_record_get_requires_api_key(client: TestClient) -> None:
    response = client.get(
        "/dns-record",
        params={
            "zone_name": "example.com",
            "record_name": "www",
        },
    )
    assert response.status_code == 401


def test_dns_record_get_with_mock_client(client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from src.models import DnsRecordInfo

    monkeypatch.setattr(
        "src.app.test_zone_record_lookup",
        lambda _settings, **kwargs: [
            DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])
        ],
    )
    response = client.get(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        params={
            "zone_name": "example.com",
            "record_name": "www",
            "record_type": "A",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["zone_name"] == "example.com"
    assert body["record_name"] == "www"
    assert body["records"] == [
        {"record_name": "www", "record_type": "A", "ttl": 300, "values": ["192.0.2.1"]}
    ]


def test_dns_record_get_untyped_multi_type(client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from src.models import DnsRecordInfo

    monkeypatch.setattr(
        "src.app.test_zone_record_lookup",
        lambda _settings, **kwargs: [
            DnsRecordInfo(record_name="@", record_type="A", ttl=500, values=["10.0.0.1"]),
            DnsRecordInfo(record_name="@", record_type="CNAME", ttl=1000, values=["target.example.com"]),
        ],
    )
    response = client.get(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        params={"zone_name": "example.com", "record_name": "@"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert len(body["records"]) == 2
    assert body["records"][0]["ttl"] == 500
    assert body["records"][1]["ttl"] == 1000


def test_dns_record_get_not_found(client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.app.test_zone_record_lookup", lambda _settings, **kwargs: [])
    response = client.get(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        params={
            "zone_name": "example.com",
            "record_name": "missing",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "not_found"
    assert body["records"] == []


def test_dns_record_get_invalid_record_type(client: TestClient, api_key_value: str) -> None:
    response = client.get(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        params={
            "zone_name": "example.com",
            "record_name": "www",
            "record_type": "MX",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_request"


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
    fake.get_record.return_value = []
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
    fake.get_record.assert_called_once()
    fake.create_or_update_record.assert_called_once()
    with SessionLocal() as db:
        event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "dns.record_created")).first()
        assert event is not None
        assert event.category == "dns"


def test_dns_record_post_conflict_returns_409(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.models import DnsRecordInfo

    fake = MagicMock()
    fake.get_record.return_value = [DnsRecordInfo(record_name="www", record_type="A")]
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
    assert response.status_code == 409
    body = response.json()
    assert body["status"] == "error"
    assert body["action"] == "record_already_exists"
    assert body["record_type"] == "A"
    fake.get_record.assert_called_once()
    fake.create_or_update_record.assert_not_called()
    with SessionLocal() as db:
        event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "dns.record_already_exists")).first()
        assert event is not None
        assert event.category == "dns"


def test_dns_record_put_replaces_existing_record(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.models import DnsRecordInfo

    fake = MagicMock()
    fake.get_record.return_value = [DnsRecordInfo(record_name="www", record_type="A")]
    fake.create_or_update_record.return_value = True
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.put(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "ttl": 600,
            "values": ["192.0.2.2"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["action"] == "updated"
    fake.get_record.assert_called_once()
    fake.create_or_update_record.assert_called_once()


def test_dns_record_put_missing_returns_404(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = MagicMock()
    fake.get_record.return_value = []
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.put(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "missing",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 404
    body = response.json()
    assert body["status"] == "error"
    assert body["action"] == "not_found"
    fake.create_or_update_record.assert_not_called()


def test_dns_record_put_requires_ttl(client: TestClient, api_key_value: str) -> None:
    response = client.put(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 422


def test_dns_record_patch_updates_values(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.models import DnsRecordInfo

    fake = MagicMock()
    fake.get_record.return_value = [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])
    ]
    fake.create_or_update_record.return_value = True
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.patch(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "values": ["192.0.2.99"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["action"] == "updated"
    assert body["values"] == ["192.0.2.99"]
    fake.get_record.assert_called_once()
    fake.create_or_update_record.assert_called_once()
    internal = fake.create_or_update_record.call_args.args[0]
    assert internal.ttl == 300


def test_dns_record_patch_ttl_only(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.models import DnsRecordInfo

    fake = MagicMock()
    fake.get_record.return_value = [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])
    ]
    fake.create_or_update_record.return_value = True
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.patch(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "ttl": 600,
        },
    )
    assert response.status_code == 200
    internal = fake.create_or_update_record.call_args.args[0]
    assert internal.ttl == 600
    assert internal.values == ["192.0.2.1"]


def test_dns_record_patch_both_fields(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.models import DnsRecordInfo

    fake = MagicMock()
    fake.get_record.return_value = [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])
    ]
    fake.create_or_update_record.return_value = True
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.patch(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "ttl": 900,
            "values": ["192.0.2.99"],
        },
    )
    assert response.status_code == 200
    internal = fake.create_or_update_record.call_args.args[0]
    assert internal.ttl == 900
    assert internal.values == ["192.0.2.99"]


def test_dns_record_patch_neither_field_returns_422(client: TestClient, api_key_value: str) -> None:
    response = client.patch(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
        },
    )
    assert response.status_code == 422


def test_dns_record_patch_empty_values_returns_422(client: TestClient, api_key_value: str) -> None:
    response = client.patch(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "values": [],
        },
    )
    assert response.status_code == 422


def test_dns_record_patch_missing_returns_404(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = MagicMock()
    fake.get_record.return_value = []
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.patch(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "missing",
            "values": ["192.0.2.99"],
        },
    )
    assert response.status_code == 404
    body = response.json()
    assert body["status"] == "error"
    assert body["action"] == "not_found"
    fake.create_or_update_record.assert_not_called()


def test_dns_record_delete_with_mock_client(client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from src.models import DnsRecordInfo

    fake = MagicMock()
    fake.get_record.return_value = [DnsRecordInfo(record_name="www", record_type="A")]
    fake.create_or_update_record.return_value = True
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.delete(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        params={"zone_name": "example.com", "record_name": "www", "record_type": "A"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["action"] == "deleted"
    assert body["record_type"] == "A"
    fake.get_record.assert_called_once()
    fake.create_or_update_record.assert_called_once()
    internal_payload = fake.create_or_update_record.call_args.args[0]
    assert internal_payload.record_type == "DELETE"
    assert internal_payload.values == ["A"]


def test_dns_record_delete_not_found_returns_404(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = MagicMock()
    fake.get_record.return_value = []
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.delete(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        params={"zone_name": "example.com", "record_name": "missing", "record_type": "A"},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["status"] == "error"
    assert body["action"] == "not_found"
    fake.create_or_update_record.assert_not_called()


def test_dns_record_delete_rejects_unknown_record_type(
    client: TestClient, api_key_value: str
) -> None:
    response = client.delete(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        params={"zone_name": "example.com", "record_name": "www", "record_type": "MX"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_request"


def test_dns_record_provider_runtime_error_returns_502(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = MagicMock()
    fake.get_record.return_value = []
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
    components = schema["components"]["schemas"]
    for model_name in ("DnsRecordCreateRequest", "DnsRecordReplaceRequest", "DnsRecordPatchRequest"):
        assert model_name in components
        request_schema = components[model_name]
        assert "subscription_id" not in request_schema["properties"]
        assert "resource_group" not in request_schema["properties"]
    assert "DnsRecordRequest" not in components


def test_dns_record_openapi_documents_all_methods(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    path = schema["paths"]["/dns-record"]
    assert set(path) == {"get", "post", "put", "patch", "delete"}
    assert "409" in path["post"]["responses"]
    for method in ("put", "patch", "delete"):
        assert "404" in path[method]["responses"]
    delete_param_names = {p["name"] for p in path["delete"]["parameters"]}
    assert {"zone_name", "record_name", "record_type"} <= delete_param_names


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


def _create_user(db, username: str, password: str, roles=None, disabled: bool = False) -> User:
    row = User(
        username=username,
        password_hash=hash_password(password),
        roles=_serialize_roles(roles or []),
        disabled=disabled,
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
    assert "System Settings" not in response.text
    assert "View Logs" not in response.text
    assert "Email Alerting" not in response.text
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


def test_change_my_password_form_is_modal_opened_by_button(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("self-service"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "self-service", "old-password", [])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/settings")
    assert response.status_code == 200
    assert 'id="open-change-password"' in response.text
    assert '<dialog id="change-password-dialog">' in response.text
    dialog = response.text.split('<dialog id="change-password-dialog">', 1)[1].split("</dialog>", 1)[0]
    assert 'action="/settings/account/password"' in dialog
    assert 'name="current_password"' in dialog
    assert 'name="new_password"' in dialog
    assert 'name="confirm_password"' in dialog


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
    assert "System Settings" in response.text
    assert "View Logs" in response.text
    assert "Email Alerting" in response.text
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
    assert '<a class="button" href="/zones">DNS Zones</a>' in response.text
    assert '<span class="button disabled" aria-disabled="true">API Keys</span>' in response.text
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


def test_create_user_form_defaults_to_required_dns_zones_read_only(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings")
    assert response.status_code == 200
    create_dialog = response.text.split('<dialog id="create-user-dialog"', 1)[1].split("</dialog>", 1)[0]
    dns_role_input = create_dialog.split('value="dns_zones.read"', 1)[1].split("/>", 1)[0]
    assert "checked" in dns_role_input
    assert "disabled" in dns_role_input
    assert 'data-mandatory-role="true"' in dns_role_input
    assert 'value="global.read"' in create_dialog
    assert 'value="api_keys.read"' in create_dialog
    assert "global.read" in create_dialog
    assert "api_keys.read" in create_dialog
    assert "dns_zones.read" in create_dialog
    assert create_dialog.count("checked") == 1
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


def test_settings_create_user_always_persists_dns_zones_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.post(
        "/settings/users",
        data={
            "username": "zone-reader-by-default",
            "password": "passw0rd!",
            "roles": [],
        },
    )
    assert response.status_code == 200

    with SessionLocal() as db:
        created = db.exec(select(User).where(User.username == "zone-reader-by-default")).first()
        assert created is not None
        assert (created.roles or "") == ROLE_DNS_ZONES_READ


def test_current_user_row_shows_read_only_roles_view(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        admin = _create_user(db, "admin", "x", ALL_ROLES)
        other = _create_user(db, "other", "x", [ROLE_DNS_ZONES_READ])
        admin_id = admin.id
        other_id = other.id

    response = client.get("/settings")
    assert response.status_code == 200
    table_row = response.text.split("<code>admin</code>", 1)[1].split("</tr>", 1)[0]
    assert "View roles" in table_row
    assert "Edit roles" not in table_row
    assert "Reset password" not in table_row

    dialog = response.text.split(f'<dialog id="view-roles-dialog-{admin_id}">', 1)[1].split("</dialog>", 1)[0]
    assert "Save roles" not in dialog
    assert 'name="roles"' not in dialog
    assert "disabled" in dialog
    assert "global.read" in dialog
    assert f'id="reset-password-dialog-{admin_id}"' not in response.text

    reset_dialog = response.text.split(f'<dialog id="reset-password-dialog-{other_id}">', 1)[1].split("</dialog>", 1)[0]
    assert 'name="password"' in reset_dialog
    assert 'name="confirm_password"' in reset_dialog


def test_enabled_user_row_shows_disable_instead_of_delete(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        _create_user(db, "enabled-user", "x", [ROLE_DNS_ZONES_READ])

    response = client.get("/settings")
    assert response.status_code == 200
    table_row = response.text.split("<code>enabled-user</code>", 1)[1].split("</tr>", 1)[0]
    assert "Disable account" in table_row
    assert "Delete" not in table_row
    assert "Edit roles" in table_row
    assert "Reset password" in table_row


def test_disabled_user_row_shows_enable_delete_and_hides_edit_actions(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        disabled_user = _create_user(db, "disabled-user", "x", [ROLE_DNS_ZONES_READ], disabled=True)
        disabled_user_id = disabled_user.id

    response = client.get("/settings")
    assert response.status_code == 200
    table_row = response.text.split("<code>disabled-user</code>", 1)[1].split("</tr>", 1)[0]
    assert "(Disabled)" in table_row
    assert "Enable account" in table_row
    assert "Delete" in table_row
    assert "Edit roles" not in table_row
    assert "Reset password" not in table_row
    assert f'id="edit-roles-dialog-{disabled_user_id}"' not in response.text
    assert f'id="reset-password-dialog-{disabled_user_id}"' not in response.text


def test_non_global_admin_sees_only_view_roles_for_global_admin_row(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("account-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "account-admin", "x", [ROLE_ACCOUNT_UPDATE, ROLE_ACCOUNT_RESET_PASSWORD])
        protected = _create_user(db, "protected-global", "x", [ROLE_GLOBAL_ADMIN])
        protected_id = protected.id

    response = client.get("/settings")
    assert response.status_code == 200
    table_row = response.text.split("<code>protected-global</code>", 1)[1].split("</tr>", 1)[0]
    assert "(Global Admin)" in table_row
    assert "View roles" in table_row
    assert "Edit roles" not in table_row
    assert "Reset password" not in table_row
    assert "Disable account" not in table_row
    assert "Enable account" not in table_row
    assert "Delete" not in table_row
    assert f'id="edit-roles-dialog-{protected_id}"' not in response.text
    view_dialog = response.text.split(f'<dialog id="view-roles-dialog-{protected_id}">', 1)[1].split("</dialog>", 1)[0]
    assert "global.admin" in view_dialog
    assert "Save roles" not in view_dialog


def test_global_admin_checkbox_visible_disabled_for_non_global_admin_create(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("account-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "account-admin", "x", [ROLE_ACCOUNT_UPDATE])
        _create_user(db, "global-admin", "x", [ROLE_GLOBAL_ADMIN])

    response = client.get("/settings")
    assert response.status_code == 200
    create_dialog = response.text.split('<dialog id="create-user-dialog"', 1)[1].split("</dialog>", 1)[0]
    global_admin_input = create_dialog.split('value="global.admin"', 1)[1].split("/>", 1)[0]
    assert "disabled" in global_admin_input
    assert 'name="roles"' not in global_admin_input


def test_global_admin_edit_dialog_checks_all_roles_and_js_locks_them(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("global-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "global-admin", "x", [ROLE_GLOBAL_ADMIN])
        target = _create_user(db, "target-global", "x", [ROLE_GLOBAL_ADMIN])
        target_id = target.id

    response = client.get("/settings")
    assert response.status_code == 200
    dialog = response.text.split(f'<dialog id="edit-roles-dialog-{target_id}">', 1)[1].split("</dialog>", 1)[0]
    global_admin_input = dialog.split('value="global.admin"', 1)[1].split("/>", 1)[0]
    account_update_input = dialog.split('value="account.update"', 1)[1].split("/>", 1)[0]
    assert "checked" in global_admin_input
    assert "disabled" not in global_admin_input
    assert "checked" in account_update_input
    assert "setGlobalAdminRoles(true)" in response.text
    assert 'input.disabled = true;' in response.text


def test_global_admin_selection_persists_all_roles(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("global-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "global-admin", "x", [ROLE_GLOBAL_ADMIN])

    response = client.post(
        "/settings/users",
        data={
            "username": "new-global-admin",
            "password": "passw0rd!",
            "roles": [ROLE_GLOBAL_ADMIN],
        },
    )
    assert response.status_code == 200

    with SessionLocal() as db:
        created = db.exec(select(User).where(User.username == "new-global-admin")).first()
        assert created is not None
        assert set((created.roles or "").split(",")) == set(ALL_ROLES)


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
        assert set((api_editor.roles or "").split(",")) == {
            ROLE_API_KEYS_READ,
            ROLE_API_KEYS_UPDATE,
            ROLE_DNS_ZONES_READ,
        }


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


def test_settings_update_roles_cannot_remove_dns_zones_read(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        user = _create_user(db, "required-zone-reader", "secret", [ROLE_API_KEYS_READ])
        user_id = user.id

    response = client.post(
        f"/settings/users/{user_id}/roles",
        data={"roles": [ROLE_API_KEYS_READ]},
    )
    assert response.status_code == 200

    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None
        assert set((user.roles or "").split(",")) == {ROLE_API_KEYS_READ, ROLE_DNS_ZONES_READ}


def test_global_admin_grants_all_effective_roles(client: TestClient) -> None:
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "super-admin", "x", [ROLE_GLOBAL_ADMIN])

        assert set(get_user_roles(db, "super-admin")) == set(ALL_ROLES)
        for role in ALL_ROLES:
            assert user_has_role(db, "super-admin", role)


def test_non_global_admin_cannot_create_global_admin_user(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("account-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "account-admin", "x", [ROLE_ACCOUNT_UPDATE])
        _create_user(db, "global-admin", "x", [ROLE_GLOBAL_ADMIN])

    response = client.post(
        "/settings/users",
        data={
            "username": "new-global-admin",
            "password": "passw0rd!",
            "roles": [ROLE_GLOBAL_ADMIN],
        },
    )
    assert response.status_code == 200
    assert "Only a global admin can grant global admin." in response.text
    with SessionLocal() as db:
        assert db.exec(select(User).where(User.username == "new-global-admin")).first() is None


def test_global_admin_can_create_global_admin_user(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("global-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "global-admin", "x", [ROLE_GLOBAL_ADMIN])

    response = client.post(
        "/settings/users",
        data={
            "username": "new-global-admin",
            "password": "passw0rd!",
            "roles": [ROLE_GLOBAL_ADMIN],
        },
    )
    assert response.status_code == 200
    assert "new-global-admin" in response.text and "created" in response.text
    with SessionLocal() as db:
        created = db.exec(select(User).where(User.username == "new-global-admin")).first()
        assert created is not None
        assert set((created.roles or "").split(",")) == set(ALL_ROLES)


def test_non_global_admin_cannot_assign_or_remove_global_admin_role(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("account-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "account-admin", "x", [ROLE_ACCOUNT_UPDATE])
        target = _create_user(db, "target", "x", [ROLE_API_KEYS_READ])
        protected = _create_user(db, "protected", "x", [ROLE_GLOBAL_ADMIN])
        target_id = target.id
        protected_id = protected.id

    response = client.post(
        f"/settings/users/{target_id}/roles",
        data={"roles": [ROLE_GLOBAL_ADMIN]},
    )
    assert response.status_code == 200
    assert "Only a global admin can change global admin role assignments." in response.text
    with SessionLocal() as db:
        target = db.get(User, target_id)
        assert target is not None
        assert ROLE_GLOBAL_ADMIN not in (target.roles or "").split(",")

    response = client.post(
        f"/settings/users/{protected_id}/roles",
        data={"roles": [ROLE_DNS_ZONES_READ]},
    )
    assert response.status_code == 200
    assert "Only a global admin can manage another global admin account." in response.text
    with SessionLocal() as db:
        protected = db.get(User, protected_id)
        assert protected is not None
        assert ROLE_GLOBAL_ADMIN in (protected.roles or "").split(",")


def test_global_admin_can_update_other_global_admin_roles(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("global-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "global-admin", "x", [ROLE_GLOBAL_ADMIN])
        target = _create_user(db, "target-global", "x", [ROLE_GLOBAL_ADMIN])
        target_id = target.id

    response = client.post(
        f"/settings/users/{target_id}/roles",
        data={"roles": [ROLE_DNS_ZONES_UPDATE]},
    )
    assert response.status_code == 200
    assert "Roles updated" in response.text
    with SessionLocal() as db:
        target = db.get(User, target_id)
        assert target is not None
        assert set((target.roles or "").split(",")) == {ROLE_DNS_ZONES_READ, ROLE_DNS_ZONES_UPDATE}


def test_settings_disable_user_marks_account_disabled(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        user = _create_user(db, "disable-me", "secret", [ROLE_API_KEYS_READ])
        user_id = user.id

    response = client.post(f"/settings/users/{user_id}/disable")
    assert response.status_code == 200
    assert "disable-me" in response.text and "disabled" in response.text
    assert "(Disabled)" in response.text

    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None
        assert user.disabled is True


def test_settings_enable_user_restores_normal_actions(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        user = _create_user(db, "enable-me", "secret", [ROLE_API_KEYS_READ], disabled=True)
        user_id = user.id

    response = client.post(f"/settings/users/{user_id}/enable")
    assert response.status_code == 200
    assert "enable-me" in response.text and "enabled" in response.text

    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None
        assert user.disabled is False

    table_row = response.text.split("<code>enable-me</code>", 1)[1].split("</tr>", 1)[0]
    assert "Disable account" in table_row
    assert "Enable account" not in table_row
    assert "Edit roles" in table_row
    assert "Reset password" in table_row


def test_non_global_admin_cannot_manage_global_admin_account(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("account-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "account-admin", "x", [ROLE_ACCOUNT_UPDATE, ROLE_ACCOUNT_RESET_PASSWORD])
        protected = _create_user(db, "protected-global", "x", [ROLE_GLOBAL_ADMIN])
        protected_id = protected.id

    for method, data in (
        ("disable", None),
        ("password", {"password": "new-pass", "confirm_password": "new-pass"}),
        ("roles", {"roles": [ROLE_API_KEYS_READ]}),
    ):
        response = client.post(f"/settings/users/{protected_id}/{method}", data=data)
        assert response.status_code == 200
        assert "Only a global admin can manage another global admin account." in response.text

    with SessionLocal() as db:
        protected = db.get(User, protected_id)
        assert protected is not None
        assert protected.disabled is False
        assert set((protected.roles or "").split(",")) == set(ALL_ROLES)


def test_non_global_admin_cannot_delete_or_enable_disabled_global_admin(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("account-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "account-admin", "x", [ROLE_ACCOUNT_UPDATE])
        protected = _create_user(db, "protected-global", "x", [ROLE_GLOBAL_ADMIN], disabled=True)
        protected_id = protected.id

    for method in ("enable", "delete"):
        response = client.post(f"/settings/users/{protected_id}/{method}")
        assert response.status_code == 200
        assert "Only a global admin can manage another global admin account." in response.text

    with SessionLocal() as db:
        protected = db.get(User, protected_id)
        assert protected is not None
        assert protected.disabled is True


def test_global_admin_can_manage_other_global_admin_account(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("global-admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "global-admin", "x", [ROLE_GLOBAL_ADMIN])
        protected = _create_user(db, "protected-global", "x", [ROLE_GLOBAL_ADMIN])
        protected_id = protected.id

    response = client.post(f"/settings/users/{protected_id}/disable")
    assert response.status_code == 200
    assert "protected-global" in response.text and "disabled" in response.text

    response = client.post(f"/settings/users/{protected_id}/enable")
    assert response.status_code == 200
    assert "protected-global" in response.text and "enabled" in response.text


def test_settings_cannot_disable_current_user(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        admin = _create_user(db, "admin", "x", ALL_ROLES)
        _create_user(db, "other", "x", ALL_ROLES)
        admin_id = admin.id

    response = client.post(f"/settings/users/{admin_id}/disable")
    assert response.status_code == 200
    assert "You cannot disable the user you are signed in as." in response.text
    with SessionLocal() as db:
        admin = db.get(User, admin_id)
        assert admin is not None
        assert admin.disabled is False


def test_settings_cannot_disable_last_enabled_user(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("only-enabled"))
    with SessionLocal() as db:
        _delete_users(db)
        only_enabled = _create_user(db, "only-enabled", "x", ALL_ROLES)
        _create_user(db, "disabled-user", "x", ALL_ROLES, disabled=True)
        only_enabled_id = only_enabled.id

    response = client.post(f"/settings/users/{only_enabled_id}/disable")
    assert response.status_code == 200
    assert "At least one enabled user account must remain." in response.text
    with SessionLocal() as db:
        only_enabled = db.get(User, only_enabled_id)
        assert only_enabled is not None
        assert only_enabled.disabled is False


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
        data={"password": "brand-new", "confirm_password": "brand-new"},
    )
    assert response.status_code == 200
    assert "Password reset" in response.text and "bob" in response.text
    with SessionLocal() as db:
        bob = db.get(User, bob_id)
        assert bob is not None
        assert bob.password_hash != original_hash


def test_privileged_reset_password_rejects_mismatched_confirmation(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        bob = _create_user(db, "bob", "original", [ROLE_DNS_ZONES_READ])
        original_hash = bob.password_hash
        bob_id = bob.id

    response = client.post(
        f"/settings/users/{bob_id}/password",
        data={"password": "brand-new", "confirm_password": "different"},
    )
    assert response.status_code == 200
    assert "New password and confirmation do not match." in response.text
    with SessionLocal() as db:
        bob = db.get(User, bob_id)
        assert bob is not None
        assert bob.password_hash == original_hash


def test_settings_delete_user_removes_account(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        carol = _create_user(db, "carol", "secret", [ROLE_API_KEYS_READ], disabled=True)
        carol_id = carol.id

    response = client.post(f"/settings/users/{carol_id}/delete")
    assert response.status_code == 200
    assert "carol" in response.text and "deleted" in response.text
    with SessionLocal() as db:
        assert db.get(User, carol_id) is None


def test_settings_cannot_delete_enabled_user(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "admin", "x", ALL_ROLES)
        carol = _create_user(db, "carol", "secret", [ROLE_API_KEYS_READ])
        carol_id = carol.id

    response = client.post(f"/settings/users/{carol_id}/delete")
    assert response.status_code == 200
    assert "Disable the user account before deleting it." in response.text
    with SessionLocal() as db:
        carol = db.get(User, carol_id)
        assert carol is not None
        assert carol.disabled is False


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
    client.cookies.set("session", create_session_cookie("only"))
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
        data={"password": "new-pass", "confirm_password": "new-pass"},
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
        ("/settings?area=logging", "View Logs"),
        ("/settings?area=system_settings", "System Settings"),
        ("/settings?area=email_alerting", "Email Alerting"),
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
    assert "View Logs" in response.text
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
    assert client.post("/settings/plugins/cloudflare/disable").status_code == 200
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


def test_settings_activity_logging_sections_render(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=system_settings")
    assert response.status_code == 200
    assert "System Settings" in response.text
    assert 'class="settings-submenu"' in response.text
    assert "Logging Level" in response.text
    assert "SMTP Delivery" in response.text
    assert "App DNS Name" in response.text
    assert "SSL Certificate" in response.text
    assert 'name="log_level"' not in response.text
    submenu = response.text.split('class="settings-submenu"')[1].split("</nav>")[0]
    assert submenu.index("App DNS Name") < submenu.index("SSL Certificate")

    response = client.get("/settings?area=log_viewing")
    assert response.status_code == 200
    assert "View Logs" in response.text
    assert "Advanced Search" in response.text
    assert "Category" in response.text

    response = client.get("/settings?area=email_alerting")
    assert response.status_code == 200
    assert "Email Alerting" in response.text
    assert "Template Variables" in response.text


def test_settings_system_section_shows_single_panel(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=system_settings&section=smtp_delivery")
    assert response.status_code == 200
    assert 'name="smtp_servers"' in response.text
    assert 'name="log_level"' not in response.text
    assert 'settings-submenu-item selected' in response.text or "settings-submenu-item selected" in response.text
    assert "section=smtp_delivery" in response.text

    response = client.get("/settings?area=system_settings&section=logging_configuration")
    assert response.status_code == 200
    assert 'name="log_level"' in response.text
    assert 'name="smtp_servers"' not in response.text


def test_settings_plugins_area_has_no_system_submenu(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=plugins")
    assert response.status_code == 200
    assert "Plugin Management" in response.text
    assert 'class="settings-submenu"' not in response.text


def test_settings_log_level_post_redirects_to_section(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/settings/system/log-level",
        data={
            "log_level": "informational",
            "redirect_area": "system_settings",
            "redirect_section": "logging_configuration",
        },
    )
    assert response.status_code == 200
    assert "Activity log level set to INFORMATIONAL" in response.text
    assert 'name="log_level"' in response.text
    assert 'name="smtp_servers"' not in response.text


def test_settings_app_dns_name_section_is_editable(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=system_settings&section=system_identity")
    assert response.status_code == 200
    assert "App DNS Name" in response.text
    assert 'name="app_dns_name"' in response.text
    assert 'action="/settings/system/app-dns-name"' in response.text


def test_settings_app_dns_name_post_persists(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/settings/system/app-dns-name",
        data={"app_dns_name": "my-dns.example", "redirect_section": "system_identity"},
    )
    assert response.status_code == 200
    assert "App DNS name saved as my-dns.example" in response.text
    with SessionLocal() as db:
        from src.activity_logging import get_app_dns_name

        assert get_app_dns_name(db) == "my-dns.example"


def test_default_app_dns_name_uses_docker_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(activity_logging, "is_running_in_docker", lambda: True)
    assert activity_logging.default_app_dns_name() == "apitodns.local"


def test_default_app_dns_name_uses_hostname_off_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(activity_logging, "is_running_in_docker", lambda: False)
    monkeypatch.setattr(activity_logging, "_host_system_dns_name", lambda: "host.example")
    assert activity_logging.default_app_dns_name() == "host.example"


def test_settings_operational_log_rotation_docker_shows_message_only(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src import settings_context

    monkeypatch.setattr(activity_logging, "is_running_in_docker", lambda: True)
    monkeypatch.setattr(settings_context, "is_running_in_docker", lambda: True)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=system_settings&section=operational_log_rotation")
    assert response.status_code == 200
    assert "Docker stdout/stderr logs are rotated by Docker." in response.text
    assert 'action="/settings/system/log-rotation"' not in response.text
    assert 'name="log_file"' not in response.text


def test_settings_operational_log_rotation_non_docker_shows_form(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src import settings_context

    monkeypatch.setattr(activity_logging, "is_running_in_docker", lambda: False)
    monkeypatch.setattr(settings_context, "is_running_in_docker", lambda: False)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=system_settings&section=operational_log_rotation")
    assert response.status_code == 200
    assert 'action="/settings/system/log-rotation"' in response.text
    assert 'name="log_file"' in response.text


def _generate_test_pem_pair(common_name: str = "ssl-test.example") -> tuple[bytes, bytes]:
    """Generate an unencrypted PKCS8 PEM key and a matching self-signed cert."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name), x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _clear_ssl_state() -> None:
    """Remove any installed SSL files and reset the ssl_enabled DB toggle."""
    from src import ssl_certs as _ssl

    key_path, cert_path = _ssl.cert_paths()
    for p in (key_path, cert_path, _ssl.cert_dir() / _ssl.SOURCE_FILENAME):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    with SessionLocal() as db:
        _ssl.set_ssl_enabled(db, False)


def test_settings_ssl_section_renders_without_cert(client: TestClient) -> None:
    _clear_ssl_state()
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=system_settings&section=ssl_certificate")
    assert response.status_code == 200
    assert "SSL Certificate" in response.text
    assert "Upload Certificate" in response.text
    assert "Enable HTTPS" in response.text
    assert "Create self-signed certificate" in response.text
    assert 'name="ssl_enabled"' in response.text
    assert "Install a certificate below before enabling SSL." in response.text


def _le_config_post_data(**overrides) -> dict:
    data = {
        "email": "admin@example.com",
        "root_dns_domain": "example.com",
        "common_name": "api.example.com",
        "subject_alt_names": "api.example.com",
        "challenge_type": "dns-01",
        "renew_before_expiry_days": "30",
        "scheduled_restart_time": "03:00",
    }
    data.update(overrides)
    return data


def test_letsencrypt_config_notice_auto_renew_on_and_off(client: TestClient) -> None:
    from src import letsencrypt, ssl_certs

    _clear_ssl_state()
    with SessionLocal() as db:
        letsencrypt.save_config(
            db,
            email="admin@example.com",
            root_dns_domain="example.com",
            common_name="api.example.com",
            subject_alt_names="api.example.com",
            challenge_type=letsencrypt.CHALLENGE_HTTP,
            zone_id=None,
            staging=True,
            auto_renew_enabled=False,
        )
    ssl_certs._write_source(ssl_certs.SOURCE_LETSENCRYPT)
    client.cookies.set("session", create_session_cookie("admin"))

    on_response = client.post(
        "/settings/system/ssl-letsencrypt/config",
        data=_le_config_post_data(config_notice="auto_renew_on", auto_renew_enabled="on"),
    )
    assert on_response.status_code == 200
    assert "Automatic certificate renewal was turned on." in on_response.text

    off_response = client.post(
        "/settings/system/ssl-letsencrypt/config",
        data=_le_config_post_data(config_notice="auto_renew_off"),
    )
    assert off_response.status_code == 200
    assert "Automatic certificate renewal was turned off." in off_response.text

    with SessionLocal() as db:
        config = letsencrypt.get_config(db)
        assert config is not None
        assert config["auto_renew_enabled"] is False


def test_settings_ssl_legacy_section_key_still_redirects(client: TestClient) -> None:
    _clear_ssl_state()
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings?area=system_settings&section=ssl_planned")
    assert response.status_code == 200
    # ssl_planned is aliased to ssl_certificate in rbac.normalize_system_settings_section.
    assert "SSL Certificate" in response.text


def test_settings_ssl_post_enable_without_cert_is_rejected(client: TestClient) -> None:
    _clear_ssl_state()
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/settings/system/ssl",
        data={"ssl_enabled": "on", "redirect_section": "ssl_certificate"},
    )
    assert response.status_code == 200
    assert "no certificate is installed" in response.text.lower()
    with SessionLocal() as db:
        from src.ssl_certs import is_ssl_enabled

        assert is_ssl_enabled(db) is False


def test_settings_ssl_upload_installs_and_unlocks_enable(client: TestClient) -> None:
    _clear_ssl_state()
    client.cookies.set("session", create_session_cookie("admin"))
    key_pem, cert_pem = _generate_test_pem_pair("upload-section.example")
    response = client.post(
        "/settings/system/ssl-upload",
        data={"redirect_section": "ssl_certificate"},
        files={
            "ssl_key": ("server.key", key_pem, "application/x-pem-file"),
            "ssl_cert": ("server.crt", cert_pem, "application/x-pem-file"),
        },
    )
    assert response.status_code == 200
    assert "SSL certificate uploaded" in response.text
    from src import ssl_certs as _ssl

    assert _ssl.cert_exists()

    response = client.get("/settings?area=system_settings&section=ssl_certificate")
    assert "upload-section.example" in response.text
    assert "Installed certificate" in response.text
    # With a cert installed, the Enable SSL checkbox is no longer disabled.
    assert 'name="ssl_enabled"' in response.text
    assert "before enabling SSL" not in response.text


def test_settings_ssl_upload_rejects_mismatched_key(client: TestClient) -> None:
    _clear_ssl_state()
    client.cookies.set("session", create_session_cookie("admin"))
    _, cert_pem = _generate_test_pem_pair("leaf.example")
    other_key_pem, _ = _generate_test_pem_pair("other.example")
    response = client.post(
        "/settings/system/ssl-upload",
        data={"redirect_section": "ssl_certificate"},
        files={
            "ssl_key": ("server.key", other_key_pem, "application/x-pem-file"),
            "ssl_cert": ("server.crt", cert_pem, "application/x-pem-file"),
        },
    )
    assert response.status_code == 200
    assert "does not match" in response.text.lower()
    from src import ssl_certs as _ssl

    assert not _ssl.cert_exists()


def test_settings_ssl_enable_persists_after_cert_installed(client: TestClient) -> None:
    _clear_ssl_state()
    client.cookies.set("session", create_session_cookie("admin"))
    key_pem, cert_pem = _generate_test_pem_pair("enable.example")
    client.post(
        "/settings/system/ssl-upload",
        data={"redirect_section": "ssl_certificate"},
        files={
            "ssl_key": ("server.key", key_pem, "application/x-pem-file"),
            "ssl_cert": ("server.crt", cert_pem, "application/x-pem-file"),
        },
    )

    response = client.post(
        "/settings/system/ssl",
        data={"ssl_enabled": "on", "redirect_section": "ssl_certificate"},
    )
    assert response.status_code == 200
    assert "SSL setting saved" in response.text
    with SessionLocal() as db:
        from src.ssl_certs import is_ssl_enabled

        assert is_ssl_enabled(db) is True

    # Disable path: no certificate check, always allowed.
    response = client.post(
        "/settings/system/ssl",
        data={"redirect_section": "ssl_certificate"},
    )
    assert response.status_code == 200
    assert "SSL setting saved" in response.text
    with SessionLocal() as db:
        from src.ssl_certs import is_ssl_enabled

        assert is_ssl_enabled(db) is False


def test_settings_ssl_regenerate_without_openssl_returns_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_ssl_state()
    from src import ssl_certs as _ssl

    monkeypatch.setattr(_ssl, "_openssl_executable", lambda: None)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/settings/system/ssl-regenerate",
        data={"redirect_section": "ssl_certificate"},
    )
    assert response.status_code == 200
    assert "openssl" in response.text.lower()


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


def test_dns_zones_read_is_required_on_all_user_accounts(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("noreader"))
    with SessionLocal() as db:
        _delete_users(db)
        _create_user(db, "noreader", "x", [ROLE_API_KEYS_READ])
        _create_user(db, "admin", "x", ALL_ROLES)

    response = client.get("/zones", follow_redirects=False)
    assert response.status_code == 200
    assert "Configured zones" in response.text


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
    fake.get_record.return_value = []
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


def _delete_activity_logs(db) -> None:
    for row in db.exec(select(ActivityLog)).all():
        db.delete(row)
    for rule in db.exec(select(AlertRule)).all():
        db.delete(rule)
    db.commit()
    activity_logging._retention_state.clear()


def test_activity_events_written_for_api_key_creation_and_revocation(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)
        zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None

    response = client.post("/api-keys", data={"label": "audit-key", "zone_ids": str(zone.id)})
    assert response.status_code == 200
    with SessionLocal() as db:
        created = db.exec(select(ApiKey).where(ApiKey.label == "audit-key")).first()
        assert created is not None
        create_event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "api_key.created")).first()
        assert create_event is not None
        assert create_event.actor_label == "admin"
        assert "audit-key" in (create_event.message or "")

    response = client.post("/api-keys/revoke", data={"key_id": str(created.id)})
    assert response.status_code == 200
    with SessionLocal() as db:
        revoke_event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "api_key.revoked")).first()
        assert revoke_event is not None
        assert revoke_event.level == LOG_LEVEL_WARNING
        assert "audit-key" in (revoke_event.message or "")


def test_dns_provider_failure_writes_error_activity_log(
    client: TestClient, api_key_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)

    fake = MagicMock()
    fake.get_record.return_value = []
    fake.create_or_update_record.side_effect = RuntimeError("WinRM failed with password=supersecret")
    monkeypatch.setattr("src.app.get_dns_client_from_settings", lambda _settings: fake)

    response = client.post(
        "/dns-record",
        headers={"X-API-Key": api_key_value},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "broken",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 502
    with SessionLocal() as db:
        event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "dns.provider_failed")).first()
        assert event is not None
        assert event.level == LOG_LEVEL_ERROR
        assert event.zone_name == "example.com"
        assert event.record_name == "broken"
        assert event.details_json is not None
        assert "supersecret" not in event.details_json


def test_infer_event_category_uses_prefix_except_security() -> None:
    assert infer_event_category("http.request") == "http"
    assert infer_event_category("plugin.disabled") == "plugin"
    assert infer_event_category("plugin.enabled") == "plugin"
    assert infer_event_category("dns_zone.created") == "dns_zone"
    assert infer_event_category("system.smtp_updated") == "system"
    assert infer_event_category("alert.email_sent") == "alert"
    assert infer_event_category("alert_rule.created") == "alert_rule"
    assert infer_event_category("dns.provider_failed") == "dns"
    assert infer_event_category("auth.login_failed") == "security"
    assert infer_event_category("api_key.created") == "security"
    assert infer_event_category("user.roles_updated") == "security"
    assert infer_event_category("dns.record_created") == "dns"
    assert infer_event_category("dns.record_updated") == "dns"


def test_request_activity_respects_configured_log_level(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_VERBOSE)

    response = client.get("/admin")
    assert response.status_code == 200
    with SessionLocal() as db:
        verbose_event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "http.request")).first()
        assert verbose_event is not None
        assert verbose_event.level == LOG_LEVEL_VERBOSE
        assert verbose_event.category == "http"
        assert verbose_event.request_path == "/admin"
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)

    response = client.get("/admin")
    assert response.status_code == 200
    with SessionLocal() as db:
        suppressed = db.exec(select(ActivityLog).where(ActivityLog.event_type == "http.request")).first()
        assert suppressed is None
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)


def test_invalid_api_key_activity_log_uses_fingerprint_not_secret(client: TestClient) -> None:
    bad_key = "invalid-api-key-secret-value"
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)

    response = client.post(
        "/dns-record",
        headers={"X-API-Key": bad_key},
        json={
            "zone_name": "example.com",
            "record_type": "A",
            "record_name": "www",
            "ttl": 300,
            "values": ["192.0.2.1"],
        },
    )
    assert response.status_code == 401
    with SessionLocal() as db:
        event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "dns.access_denied")).first()
        assert event is not None
        assert event.details_json is not None
        assert bad_key not in event.details_json
        assert "sha256:" in event.details_json


def test_activity_log_filtering_by_event_type_and_level(client: TestClient) -> None:
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)
        emit_activity_event(
            db,
            event_type="pytest.filter.info",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            message="filter me",
        )
        emit_activity_event(
            db,
            event_type="pytest.filter.error",
            level=LOG_LEVEL_ERROR,
            category="alert",
            status="error",
            message="other row",
        )

        rows, total = query_activity_logs(db, event_type="pytest.filter.error", level=LOG_LEVEL_ERROR, category="alert")

    assert total == 1
    assert len(rows) == 1
    assert rows[0].event_type == "pytest.filter.error"
    assert rows[0].category == "alert"


def test_security_category_events_are_always_logged(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_ERROR)
        zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None

    response = client.post("/api-keys", data={"label": "security-key", "zone_ids": str(zone.id)})
    assert response.status_code == 200

    with SessionLocal() as db:
        api_key_event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "api_key.created")).first()
        emit_activity_event(
            db,
            event_type="user.roles_updated",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label="admin",
            message="User roles changed",
        )
        user_event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "user.roles_updated")).first()
        assert api_key_event is not None
        assert api_key_event.category == "security"
        assert user_event is not None
        assert user_event.category == "security"
        assert user_event.level == LOG_LEVEL_INFORMATIONAL
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)


def test_alert_rules_trigger_render_templates_and_respect_cooldown(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent_messages = []

    def fake_send_alert_email(db, *, recipients, subject, body):
        sent_messages.append({"recipients": recipients, "subject": subject, "body": body})
        return True, []

    monkeypatch.setattr(activity_logging, "send_alert_email", fake_send_alert_email)
    monkeypatch.setattr(
        activity_logging,
        "system_identity",
        lambda db: {"system_dns_name": "dns-host.example", "system_ip_address": "192.0.2.44"},
    )

    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)
        rule = AlertRule(
            enabled=True,
            name="provider failures",
            event_type="pytest.alert",
            minimum_level=LOG_LEVEL_WARNING,
            message_contains="Provider",
            email_recipients="first@example.com, second@example.com",
            email_subject_template="Alert {level} {event_type} {missing}",
            email_body_template="System {system_dns_name} {system_ip_address} {zone_name} {record_name}",
            cooldown_minutes=60,
        )
        db.add(rule)
        db.commit()
        emit_activity_event(
            db,
            event_type="pytest.alert",
            level=LOG_LEVEL_ERROR,
            status="error",
            zone_name="example.com",
            record_name="www",
            message="Provider failed",
        )
        emit_activity_event(
            db,
            event_type="pytest.alert",
            level=LOG_LEVEL_ERROR,
            status="error",
            zone_name="example.com",
            record_name="www",
            message="Provider failed again",
        )

    assert len(sent_messages) == 1
    assert sent_messages[0]["recipients"] == ["first@example.com", "second@example.com"]
    assert sent_messages[0]["subject"] == "Alert ERROR pytest.alert "
    assert "dns-host.example 192.0.2.44 example.com www" in sent_messages[0]["body"]
    assert render_alert_template("Missing {not_present}", {}) == "Missing "
    with SessionLocal() as db:
        sent_event = db.exec(select(ActivityLog).where(ActivityLog.event_type == "alert.email_sent")).first()
        assert sent_event is not None
        assert sent_event.level == LOG_LEVEL_INFORMATIONAL
        assert sent_event.category == "alert"


def test_smtp_alert_delivery_tries_csv_servers_in_order(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = []
    sent_subjects = []

    class FakeSmtp:
        def ehlo(self):
            return None

        def send_message(self, message):
            sent_subjects.append(message["Subject"])

        def quit(self):
            return None

    def fake_build_smtp_client(server: str, port: int, security: str, timeout: int):
        attempts.append((server, port, security, timeout))
        if server == "smtp-fail.example":
            raise OSError("connection refused")
        return FakeSmtp()

    monkeypatch.setattr(activity_logging, "_build_smtp_client", fake_build_smtp_client)
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_smtp_config(
            db,
            servers="smtp-fail.example, smtp-ok.example",
            port=2525,
            anonymous=True,
            username="",
            password="",
            from_address="api-to-dns@example.com",
            security="none",
            timeout=7,
        )
        sent, failures = activity_logging.send_alert_email(
            db,
            recipients=["ops@example.com"],
            subject="test subject",
            body="test body",
        )

    assert sent is True
    assert [attempt[0] for attempt in attempts] == ["smtp-fail.example", "smtp-ok.example"]
    assert failures == [{"server": "smtp-fail.example", "error": "connection refused"}]
    assert sent_subjects == ["test subject"]


def test_smtp_failures_are_reported_without_exception(client: TestClient) -> None:
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_smtp_config(
            db,
            servers="",
            port=25,
            anonymous=True,
            username="",
            password="",
            from_address="api-to-dns@example.com",
            security="none",
            timeout=5,
        )
        sent, failures = activity_logging.send_alert_email(
            db,
            recipients=["ops@example.com"],
            subject="test",
            body="body",
        )

    assert sent is False
    assert failures[0]["error"] == "No SMTP servers configured"


def test_retention_cleanup_deletes_only_rows_older_than_retention(client: TestClient) -> None:
    with SessionLocal() as db:
        _delete_activity_logs(db)
        set_log_level(db, LOG_LEVEL_INFORMATIONAL)
        set_retention_days(db, 30)
        old_row = ActivityLog(
            timestamp=utc_now() - timedelta(days=31),
            level=LOG_LEVEL_INFORMATIONAL,
            event_type="pytest.retention.old",
        )
        boundary_row = ActivityLog(
            timestamp=utc_now() - timedelta(days=30) + timedelta(seconds=5),
            level=LOG_LEVEL_INFORMATIONAL,
            event_type="pytest.retention.boundary",
        )
        db.add(old_row)
        db.add(boundary_row)
        db.commit()
        db.refresh(old_row)
        db.refresh(boundary_row)
        old_id = old_row.id
        boundary_id = boundary_row.id

        removed = run_retention_cleanup(db, force=True)

        assert removed == 1
        assert db.get(ActivityLog, old_id) is None
        assert db.get(ActivityLog, boundary_id) is not None
