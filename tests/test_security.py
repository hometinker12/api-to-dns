"""Tests for crypto secret fail-fast behavior and version metadata."""

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient


def test_get_app_version_matches_version_file() -> None:
    from src.version import get_app_version

    get_app_version.cache_clear()
    expected = (Path(__file__).resolve().parents[1] / "VERSION").read_text(encoding="utf-8").strip()
    assert get_app_version() == expected
    assert expected == "0.5.0"


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
