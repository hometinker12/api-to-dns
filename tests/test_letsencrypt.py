import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from src import letsencrypt, ssl_certs
from src.db import SessionLocal, init_db
from src.models import DnsZoneConfig
from src.settings_store import delete_setting, set_setting


def _ensure_db() -> None:
    init_db()


def _sample_config_kwargs(**overrides):
    base = {
        "email": "admin@example.com",
        "root_dns_domain": "example.com",
        "common_name": "api.example.com",
        "subject_alt_names": "other.example.com",
        "challenge_type": letsencrypt.CHALLENGE_HTTP,
        "zone_id": None,
        "staging": True,
    }
    base.update(overrides)
    return base


def test_cert_identities_dedupes_and_orders_cn_first() -> None:
    identities = letsencrypt._cert_identities(
        {"common_name": "api.example.com", "subject_alt_names": ["api.example.com", "other.example.com"]}
    )
    assert identities == ["api.example.com", "other.example.com"]


def test_dns_txt_verify_delay_is_thirty_seconds() -> None:
    assert letsencrypt.DNS_TXT_VERIFY_DELAY_SECONDS == 30
    assert letsencrypt.DNS_TXT_CHALLENGE_TTL == 1


def test_create_dns_txt_challenge_uses_ttl_one(monkeypatch) -> None:
    captured: dict = {}

    class FakeClient:
        def create_or_update_record(self, request, **_kwargs) -> bool:
            captured["ttl"] = request.ttl
            return False

    monkeypatch.setattr(letsencrypt, "create_dns_client_from_settings", lambda _cfg: FakeClient())
    _ensure_db()
    with SessionLocal() as db:
        zone = db.exec(select(DnsZoneConfig)).first()
        if zone is None:
            from tests.conftest import _seed_example_zone_and_permission

            _seed_example_zone_and_permission(db, "test-api-key-for-dns-endpoint")
            zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None
        letsencrypt.create_dns_txt_challenge(
            db,
            zone_id=int(zone.id),
            domain="api.example.com",
            value="txt-value",
        )
    assert captured["ttl"] == 1


def test_save_config_defaults_common_name_to_app_dns_name(monkeypatch) -> None:
    _ensure_db()
    monkeypatch.setattr(letsencrypt, "get_app_dns_name", lambda _db: "api.example.com")
    with SessionLocal() as db:
        config = letsencrypt.save_config(
            db,
            **_sample_config_kwargs(common_name="", subject_alt_names=""),
        )
        assert config["common_name"] == "api.example.com"


def test_save_config_rejects_name_outside_root() -> None:
    _ensure_db()
    with SessionLocal() as db:
        with pytest.raises(letsencrypt.LetsEncryptError, match="must be within root DNS domain"):
            letsencrypt.save_config(
                db,
                **_sample_config_kwargs(common_name="other.com", subject_alt_names=""),
            )


def test_legacy_domains_config_normalizes() -> None:
    _ensure_db()
    with SessionLocal() as db:
        delete_setting(db, letsencrypt.SETTING_CONFIG)
        set_setting(
            db,
            letsencrypt.SETTING_CONFIG,
            json.dumps(
                {
                    "email": "admin@example.com",
                    "domains": ["api.example.com", "extra.example.com"],
                    "challenge_type": "dns-01",
                    "zone_id": None,
                    "staging": True,
                    "renew_before_expiry_days": 30,
                    "scheduled_restart_enabled": True,
                    "scheduled_restart_time": "03:00",
                    "directory_url": letsencrypt.STAGING_DIRECTORY,
                }
            ),
        )
        config = letsencrypt.get_config(db)
        assert config is not None
        assert config["common_name"] == "api.example.com"
        assert config["subject_alt_names"] == ["extra.example.com"]
        assert config.get("domains") is None


def test_renew_threshold_honors_configured_days() -> None:
    metadata = {
        "source": ssl_certs.SOURCE_LETSENCRYPT,
        "not_after": datetime.now(timezone.utc) + timedelta(days=10),
    }
    assert letsencrypt.should_renew_cert(metadata, 30) is True
    assert letsencrypt.should_renew_cert(metadata, 7) is False


def test_save_config_persists_auto_renew_disabled() -> None:
    _ensure_db()
    with SessionLocal() as db:
        config = letsencrypt.save_config(
            db,
            **_sample_config_kwargs(),
            auto_renew_enabled=False,
        )
        assert config["auto_renew_enabled"] is False
        reloaded = letsencrypt.get_config(db)
        assert reloaded is not None
        assert reloaded["auto_renew_enabled"] is False


def test_maybe_renew_certificate_skips_when_auto_renew_disabled(client: TestClient, monkeypatch) -> None:
    called = False

    def prepare(_config):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(letsencrypt, "_acme_prepare_order", prepare)
    monkeypatch.setattr(letsencrypt, "_read_source", lambda: ssl_certs.SOURCE_LETSENCRYPT)
    monkeypatch.setattr(
        letsencrypt,
        "cert_metadata",
        lambda: {
            "source": ssl_certs.SOURCE_LETSENCRYPT,
            "not_after": datetime.now(timezone.utc) + timedelta(days=10),
        },
    )
    _ensure_db()
    with SessionLocal() as db:
        letsencrypt.save_config(db, **_sample_config_kwargs(), auto_renew_enabled=False)
        assert letsencrypt.maybe_renew_certificate(db) is None
    assert called is False


def test_config_view_omits_renewal_hint_when_auto_renew_disabled(monkeypatch) -> None:
    monkeypatch.setattr(
        letsencrypt,
        "cert_metadata",
        lambda: {
            "source": ssl_certs.SOURCE_LETSENCRYPT,
            "not_after": datetime.now(timezone.utc) + timedelta(days=60),
        },
    )
    _ensure_db()
    with SessionLocal() as db:
        letsencrypt.save_config(db, **_sample_config_kwargs(), auto_renew_enabled=False)
        view = letsencrypt.config_view(db)
        assert view["renewal_hint"] == ""


def test_self_signed_cert_never_renews(client: TestClient, monkeypatch) -> None:
    called = False

    def prepare(_config):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(letsencrypt, "_acme_prepare_order", prepare)
    monkeypatch.setattr(letsencrypt, "_read_source", lambda: ssl_certs.SOURCE_SELF_SIGNED)
    with SessionLocal() as db:
        delete_setting(db, letsencrypt.SETTING_CONFIG)
        letsencrypt.save_config(db, **_sample_config_kwargs())
        assert letsencrypt.maybe_renew_certificate(db) is None
    assert called is False


def test_http_challenge_state_round_trip(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(
        letsencrypt,
        "_acme_prepare_order",
        lambda _config: {
            "challenges": [
                {
                    "domain": "api.example.com",
                    "token": "abc",
                    "key_authorization": "abc.response",
                    "response": "abc.response",
                }
            ],
            "challenge": {
                "token": "abc",
                "response": "abc.response",
            },
        },
    )
    with SessionLocal() as db:
        letsencrypt.start_enrollment(db, **_sample_config_kwargs())
    response = client.get("/.well-known/acme-challenge/abc")
    assert response.status_code == 200
    assert response.text == "abc.response"


def test_dns_txt_verify_succeeds_on_second_attempt(monkeypatch) -> None:
    attempts = {"count": 0}

    class FakeClient:
        def create_or_update_record(self, *_args, **_kwargs) -> bool:
            return False

        def get_record(self, **_kwargs):
            attempts["count"] += 1
            if attempts["count"] >= 2:
                return [SimpleNamespace(values=["txt-value"])]
            return []

    monkeypatch.setattr(letsencrypt, "_sleep_fn", lambda _seconds: None)
    monkeypatch.setattr(letsencrypt, "create_dns_client_from_settings", lambda _cfg: FakeClient())
    _ensure_db()
    with SessionLocal() as db:
        zone = db.exec(select(DnsZoneConfig)).first()
        if zone is None:
            from tests.conftest import _seed_example_zone_and_permission

            _seed_example_zone_and_permission(db, "test-api-key-for-dns-endpoint")
            zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None
        letsencrypt._verify_dns_txt_challenge(
            db,
            zone_id=int(zone.id),
            domain="api.example.com",
            expected_value="txt-value",
        )
    assert attempts["count"] == 2


def test_dns_automation_fails_and_cleans_up_after_verify_timeout(monkeypatch) -> None:
    deleted: list[str] = []

    class FakeClient:
        def create_or_update_record(self, *_args, **_kwargs) -> bool:
            return False

        def get_record(self, **_kwargs):
            return []

    monkeypatch.setattr(letsencrypt, "_sleep_fn", lambda _seconds: None)
    monkeypatch.setattr(letsencrypt, "create_dns_client_from_settings", lambda _cfg: FakeClient())

    def track_delete(db, *, zone_id: int, domain: str) -> None:
        deleted.append(domain)

    monkeypatch.setattr(letsencrypt, "delete_dns_txt_challenge", track_delete)
    monkeypatch.setattr(
        letsencrypt,
        "_acme_prepare_order",
        lambda _config: {
            "challenges": [
                {
                    "domain": "api.example.com",
                    "dns_value": "txt-value",
                    "value": "txt-value",
                }
            ],
            "challenge": {"domain": "api.example.com", "dns_value": "txt-value"},
        },
    )

    _ensure_db()
    with SessionLocal() as db:
        zone = db.exec(select(DnsZoneConfig)).first()
        if zone is None:
            from tests.conftest import _seed_example_zone_and_permission

            _seed_example_zone_and_permission(db, "test-api-key-for-dns-endpoint")
            zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None
        delete_setting(db, letsencrypt.SETTING_ENROLLMENT)
        with pytest.raises(letsencrypt.LetsEncryptError, match="did not propagate"):
            letsencrypt.start_enrollment(
                db,
                **_sample_config_kwargs(
                    challenge_type=letsencrypt.CHALLENGE_DNS,
                    zone_id=int(zone.id),
                    root_dns_domain=zone.zone_name,
                ),
            )
        assert letsencrypt.get_enrollment(db) is None
    assert deleted == ["api.example.com"]
