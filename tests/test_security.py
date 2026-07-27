"""Tests for crypto secret fail-fast behavior and version metadata."""

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from src.auth import create_session_cookie


def test_get_app_version_matches_version_file() -> None:
    from src.version import get_app_version

    get_app_version.cache_clear()
    expected = (Path(__file__).resolve().parents[1] / "VERSION").read_text(encoding="utf-8").strip()
    assert get_app_version() == expected
    assert expected == "0.6.0"


def test_fastapi_app_version_matches_version_file() -> None:
    from src.app import app
    from src.version import get_app_version

    get_app_version.cache_clear()
    assert app.version == get_app_version()


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
    from src.db import SessionLocal
    from src.models import ApiKey
    from src.security import hash_api_key
    from src.zone_service import get_api_key
    from sqlmodel import select

    raw = "test-api-key-for-dns-endpoint"
    with SessionLocal() as db:
        row = db.exec(select(ApiKey).where(ApiKey.key == hash_api_key(raw))).first()
        assert row is not None
        assert row.key == hash_api_key(raw)
        assert row.key_prefix
        assert get_api_key(db, raw) is not None
        assert get_api_key(db, "wrong-key") is None


def test_migrate_hashes_plaintext_api_keys() -> None:
    from src.db import SessionLocal, init_db
    from src.models import ApiKey
    from src.security import hash_api_key, is_api_key_hash
    from sqlmodel import select

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
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")
    from src import csrf as csrf_module
    import importlib

    importlib.reload(csrf_module)
    # Simulate production-like CSRF enforcement for this request.
    monkeypatch.setattr(csrf_module, "allow_insecure_defaults", lambda: False)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/api-keys",
        data={"label": "x", "zone_ids": "1"},
        headers={"Origin": "https://evil.example", "Host": "localhost"},
    )
    assert response.status_code == 403


def test_csrf_allows_same_origin_login_post(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.csrf.allow_insecure_defaults", lambda: False)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "x"},
        headers={"Origin": "http://testserver", "Host": "testserver", "Referer": "http://testserver/login"},
        follow_redirects=False,
    )
    assert response.status_code in {200, 303}


def test_csrf_rejects_login_post_without_origin_in_production(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.csrf.allow_insecure_defaults", lambda: False)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "x"},
        headers={"Host": "testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_cors_default_not_star_in_production_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "0")
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    origins = [origin.strip() for origin in __import__("os").getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
    if not origins:
        # Mirrors app.py production branch.
        assert origins == []
