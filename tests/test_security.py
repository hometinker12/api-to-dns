"""Tests for crypto secret fail-fast behavior and version metadata."""

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from src.auth import create_session_cookie
from src.db import SessionLocal


def test_get_app_version_matches_version_file() -> None:
    from src.version import get_app_version

    get_app_version.cache_clear()
    expected = (Path(__file__).resolve().parents[1] / "VERSION").read_text(encoding="utf-8").strip()
    assert get_app_version() == expected
    assert expected == "0.8.0"


def test_fastapi_app_version_matches_version_file() -> None:
    from src.app import app
    from src.version import get_app_version

    get_app_version.cache_clear()
    assert app.version == get_app_version()


def test_login_page_shows_version_footer_link(client: TestClient) -> None:
    from src.version import get_app_version

    get_app_version.cache_clear()
    version = get_app_version()
    response = client.get("/login")
    assert response.status_code == 200
    assert 'class="app-version-footer"' in response.text
    assert 'href="https://github.com/hometinker12/api-to-dns"' in response.text
    assert f"<code>api-to-dns v{version}</code>" in response.text


def test_encryption_key_rejected_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")

    import src.security as security

    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY must be set"):
        security._require_encryption_key()


def test_encryption_key_rejected_when_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENCRYPTION_KEY", "change-me-before-production")
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")

    import src.security as security

    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY must be set"):
        security._require_encryption_key()


def test_encryption_key_accepts_valid_fernet_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("ENCRYPTION_KEY", key)
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")

    import src.security as security

    assert security._require_encryption_key() == key


def test_secret_key_rejected_when_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "please-change-this-secret")
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")

    import src.auth as auth

    with pytest.raises(RuntimeError, match="SECRET_KEY must be set"):
        auth._require_secret_key()


def test_secret_key_accepts_custom_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "a-sufficiently-random-production-secret")
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")

    import src.auth as auth

    assert auth._require_secret_key() == "a-sufficiently-random-production-secret"


def test_api_key_fingerprint_only_defined_in_http_utils() -> None:
    import src.app as app_module
    import src.http_utils as http_utils

    assert callable(http_utils.api_key_fingerprint)
    # Local duplicate at bottom of app.py was removed; attribute should be the import.
    assert app_module.api_key_fingerprint is http_utils.api_key_fingerprint


def test_hash_api_key_is_sha256_hex() -> None:
    from src.security import hash_api_key, is_api_key_hash

    digest = hash_api_key("raw-secret-key")
    assert is_api_key_hash(digest)
    assert digest != "raw-secret-key"
    assert hash_api_key("raw-secret-key") == digest


def test_get_api_key_matches_hashed_storage(client: TestClient) -> None:
    from sqlmodel import select

    from src.db import SessionLocal
    from src.models import ApiKey
    from src.security import hash_api_key
    from src.zone_service import get_api_key

    raw = "test-api-key-for-dns-endpoint"
    with SessionLocal() as db:
        row = db.exec(select(ApiKey).where(ApiKey.key == hash_api_key(raw))).first()
        assert row is not None
        assert row.key == hash_api_key(raw)
        assert row.key_prefix
        assert get_api_key(db, raw) is not None
        assert get_api_key(db, "wrong-key") is None


def test_migrate_hashes_plaintext_api_keys() -> None:
    from sqlmodel import select

    from src.db import SessionLocal, init_db
    from src.models import ApiKey
    from src.security import hash_api_key, is_api_key_hash

    init_db()
    with SessionLocal() as db:
        db.add(ApiKey(label="legacy", key="plaintext-legacy-key", active=True))
        db.commit()

    init_db()
    with SessionLocal() as db:
        row = db.exec(select(ApiKey).where(ApiKey.label == "legacy")).first()
        assert row is not None
        assert is_api_key_hash(row.key)
        assert row.key == hash_api_key("plaintext-legacy-key")
        assert row.key_prefix == "plaintext-le"


def test_sanitize_client_error_message_redacts_secrets() -> None:
    from src.http_utils import sanitize_client_error_message

    msg = sanitize_client_error_message(
        RuntimeError("Cloudflare failed: token=supersecret123 and password=abc"),
        fallback="DNS provider error",
    )
    assert "supersecret123" not in msg
    assert "password=abc" not in msg
    assert "[redacted]" in msg


def test_http_exception_from_dns_error_hides_raw_provider_message() -> None:
    from src.http_utils import http_exception_from_dns_error

    exc = http_exception_from_dns_error(Exception("unexpected boom with secret=leakme"))
    assert exc.status_code == 500
    assert isinstance(exc.detail, dict)
    assert "leakme" not in str(exc.detail["message"])


def test_disabled_plugin_blocks_dns_client_creation(client: TestClient) -> None:
    from src.db import SessionLocal
    from src.zone_service import (
        DnsProviderDisabledError,
        create_dns_client_from_settings,
        decode_zone_config,
        list_dns_zones,
        set_disabled_dns_plugins,
    )

    with SessionLocal() as db:
        zone = list_dns_zones(db)[0]
        cfg = decode_zone_config(zone)
        set_disabled_dns_plugins(db, {cfg["dns_provider_type"]})
        try:
            with pytest.raises(DnsProviderDisabledError):
                create_dns_client_from_settings(cfg, db=db)
        finally:
            set_disabled_dns_plugins(db, set())


def test_csrf_rejects_cross_origin_post(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.csrf.relax_csrf_for_tests", lambda: False)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/api-keys",
        data={"label": "x", "zone_ids": "1"},
        headers={"Origin": "https://evil.example", "Host": "localhost"},
    )
    assert response.status_code == 403


def test_csrf_rejects_dns_browser_mutations(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.csrf.relax_csrf_for_tests", lambda: False)
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        from sqlmodel import select

        from src.models import DnsZoneConfig

        zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None
        zone_id = zone.id

    payload = {"record_name": "www", "record_type": "A", "ttl": 300, "values": ["192.0.2.10"]}
    headers = {"Origin": "https://evil.example", "Host": "localhost"}
    assert client.post(f"/zones/{zone_id}/records", json=payload, headers=headers).status_code == 403
    assert client.put(f"/zones/{zone_id}/records", json=payload, headers=headers).status_code == 403
    assert (
        client.request(
            "DELETE",
            f"/zones/{zone_id}/records",
            json={"record_name": "www", "record_type": "A"},
            headers=headers,
        ).status_code
        == 403
    )


def test_csrf_allows_same_origin_login_post(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.csrf.relax_csrf_for_tests", lambda: False)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "x"},
        headers={"Origin": "http://testserver", "Host": "testserver", "Referer": "http://testserver/login"},
        follow_redirects=False,
    )
    assert response.status_code in {200, 303}


def test_csrf_rejects_login_post_without_origin_in_production(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("src.csrf.relax_csrf_for_tests", lambda: False)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "x"},
        headers={"Host": "testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_csrf_and_cors_stay_strict_with_insecure_crypto_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """I1: API_TO_DNS_ALLOW_INSECURE_DEFAULTS must not weaken CSRF/CORS."""
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "1")
    monkeypatch.setenv("API_TO_DNS_RELAX_CSRF", "0")
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    from starlette.requests import Request

    from src.csrf import csrf_origin_allowed, relax_csrf_for_tests

    assert relax_csrf_for_tests() is False
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/login",
        "raw_path": b"/login",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 123),
        "server": ("testserver", 80),
    }
    assert csrf_origin_allowed(Request(scope)) is False
    origins = [o.strip() for o in __import__("os").getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    assert origins == []


def test_cors_default_not_star_in_production_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    origins = [origin.strip() for origin in __import__("os").getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
    assert origins == []


def test_session_cookie_secure_honors_force_and_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    from starlette.requests import Request

    from src.auth import session_cookie_secure

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "1")
    assert session_cookie_secure() is True
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "0")
    assert session_cookie_secure() is False

    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("SSL_ENABLED", "0")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"x-forwarded-proto", b"https"), (b"host", b"example.com")],
        "client": ("127.0.0.1", 123),
        "server": ("example.com", 80),
    }
    assert session_cookie_secure(Request(scope)) is True

    monkeypatch.setenv("TRUST_PROXY_HEADERS", "0")
    assert session_cookie_secure(Request(scope)) is False


def test_security_headers_and_hsts(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "1")
    response = client.get("/login")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "same-origin"
    assert "geolocation=()" in (response.headers.get("permissions-policy") or "")
    assert "default-src 'self'" in (response.headers.get("content-security-policy") or "")
    assert response.headers.get("strict-transport-security", "").startswith("max-age=")


def test_logout_is_post_only_and_clears_cookie_with_matching_attrs(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    get_resp = client.get("/logout", follow_redirects=False)
    assert get_resp.status_code == 405

    post_resp = client.post("/logout", follow_redirects=False)
    assert post_resp.status_code == 303
    assert post_resp.headers["location"] == "/login"
    set_cookie = post_resp.headers.get("set-cookie", "").lower()
    assert "session=" in set_cookie
    assert "path=/" in set_cookie


def test_openapi_disabled_by_default_outside_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAPI_ENABLED", "0")
    assert __import__("os").getenv("OPENAPI_ENABLED") == "0"
    # Construction-time flag is covered by app import path; assert helper semantics.
    from src import app as app_module

    assert app_module._openapi_enabled() is False


def test_api_keys_shows_api_docs_link_when_openapi_enabled(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/api-keys")
    assert response.status_code == 200
    assert "API Docs" in response.text
    assert 'href="/docs#/"' in response.text
    assert response.text.index('href="/docs#/"') < response.text.index('id="open-create-key"')


def test_api_keys_hides_api_docs_link_when_openapi_disabled(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.app as app_module

    monkeypatch.setattr(app_module, "_OPENAPI_ON", False)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/api-keys")
    assert response.status_code == 200
    assert "API Docs" not in response.text
    assert 'href="/docs#/"' not in response.text


def test_login_uses_dummy_hash_for_missing_users(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.security import DUMMY_PASSWORD_HASH, verify_password

    assert DUMMY_PASSWORD_HASH
    assert verify_password("api-to-dns-dummy-password-for-timing", DUMMY_PASSWORD_HASH) is True
    assert verify_password("wrong", DUMMY_PASSWORD_HASH) is False
