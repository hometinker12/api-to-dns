"""Tests for crypto secret fail-fast behavior and version metadata."""

from pathlib import Path

import pytest
from cryptography.fernet import Fernet


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
