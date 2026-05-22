import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from src import letsencrypt, ssl_certs
from src.db import SessionLocal, init_db
from src.models import ActivityLog, DnsZoneConfig
from src.settings_store import delete_setting, set_setting
from src.zone_service import encode_zone_config_dict


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


def test_le_dns_challenge_emits_audit_events(monkeypatch) -> None:
    class FakeClient:
        def create_or_update_record(self, *_args, **_kwargs) -> bool:
            return False

        def get_record(self, **_kwargs):
            return []

    monkeypatch.setattr(letsencrypt, "create_dns_client_from_settings", lambda _cfg: FakeClient())
    monkeypatch.setattr(letsencrypt, "_sleep_fn", lambda _seconds: None)
    _ensure_db()
    with SessionLocal() as db:
        zone = db.exec(select(DnsZoneConfig)).first()
        if zone is None:
            from tests.conftest import _seed_example_zone_and_permission

            _seed_example_zone_and_permission(db, "test-api-key-for-dns-endpoint")
            zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None
        record_name = "_acme-challenge.api"
        letsencrypt.create_dns_txt_challenge(
            db,
            zone_id=int(zone.id),
            domain="api.example.com",
            value="txt-value",
        )
        created = db.exec(
            select(ActivityLog).where(
                ActivityLog.event_type == "dns.record_created",
                ActivityLog.record_name == record_name,
                ActivityLog.zone_name == zone.zone_name,
            )
        ).first()
        assert created is not None
        assert created.actor_type == "system"
        assert created.actor_label == "letsencrypt"
        assert created.category == "dns"

        with pytest.raises(letsencrypt.LetsEncryptError, match="did not propagate"):
            letsencrypt._verify_dns_txt_challenge(
                db,
                zone_id=int(zone.id),
                domain="api.example.com",
                expected_value="txt-value",
                attempt_total=1,
            )
        lookup = db.exec(
            select(ActivityLog).where(
                ActivityLog.event_type == "dns.record_lookup",
                ActivityLog.record_name == record_name,
            )
        ).first()
        assert lookup is not None

        letsencrypt.delete_dns_txt_challenge(db, zone_id=int(zone.id), domain="api.example.com")
        deleted = db.exec(
            select(ActivityLog).where(
                ActivityLog.event_type == "dns.record_deleted",
                ActivityLog.record_name == record_name,
            )
        ).first()
        assert deleted is not None


def test_create_dns_txt_challenge_uses_provider_dns_zone_not_config_name(monkeypatch) -> None:
    captured: dict = {}

    class FakeClient:
        def create_or_update_record(self, request, **_kwargs) -> bool:
            captured["dns_zone"] = _kwargs.get("dns_zone")
            captured["zone_name"] = request.zone_name
            return False

    monkeypatch.setattr(letsencrypt, "create_dns_client_from_settings", lambda _cfg: FakeClient())
    _ensure_db()
    with SessionLocal() as db:
        row = DnsZoneConfig(
            zone_name="config-label-only",
            encrypted_config=encode_zone_config_dict(
                {
                    "dns_provider_type": "azure",
                    "dns_zone": "provider.example.com",
                    "azure_tenant_id": "t",
                    "azure_client_id": "c",
                    "azure_client_secret": "s",
                    "azure_subscription_id": "sub",
                    "azure_resource_group": "rg",
                }
            ),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        letsencrypt.create_dns_txt_challenge(
            db,
            zone_id=int(row.id),
            domain="api.provider.example.com",
            value="txt-value",
        )
    assert captured["dns_zone"] == "provider.example.com"
    assert captured["zone_name"] == "config-label-only"


def test_save_config_accepts_when_dns_zone_matches_root_not_config_name() -> None:
    _ensure_db()
    with SessionLocal() as db:
        row = DnsZoneConfig(
            zone_name="le-config-azure",
            encrypted_config=encode_zone_config_dict(
                {
                    "dns_provider_type": "azure",
                    "dns_zone": "example.com",
                    "azure_tenant_id": "t",
                    "azure_client_id": "c",
                    "azure_client_secret": "s",
                    "azure_subscription_id": "sub",
                    "azure_resource_group": "rg",
                }
            ),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        config = letsencrypt.save_config(
            db,
            **_sample_config_kwargs(
                challenge_type=letsencrypt.CHALLENGE_DNS,
                zone_id=int(row.id),
                root_dns_domain="example.com",
                common_name="api.example.com",
            ),
        )
        assert config["root_dns_domain"] == "example.com"
        assert config["zone_id"] == int(row.id)


def test_save_config_defaults_common_name_to_app_dns_name(monkeypatch) -> None:
    _ensure_db()
    monkeypatch.setattr(letsencrypt, "get_app_dns_name", lambda _db: "api.example.com")
    with SessionLocal() as db:
        config = letsencrypt.save_config(
            db,
            **_sample_config_kwargs(common_name="", subject_alt_names=""),
        )
        assert config["common_name"] == "api.example.com"


def test_save_config_dns_zone_must_match_root_not_config_name() -> None:
    _ensure_db()
    with SessionLocal() as db:
        row = DnsZoneConfig(
            zone_name="le-config-name",
            encrypted_config=encode_zone_config_dict(
                {
                    "dns_provider_type": "azure",
                    "dns_zone": "other.com",
                    "azure_tenant_id": "t",
                    "azure_client_id": "c",
                    "azure_client_secret": "s",
                    "azure_subscription_id": "sub",
                    "azure_resource_group": "rg",
                }
            ),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        with pytest.raises(letsencrypt.LetsEncryptError, match="DNS domain must match Root DNS Domain"):
            letsencrypt.save_config(
                db,
                **_sample_config_kwargs(
                    challenge_type=letsencrypt.CHALLENGE_DNS,
                    zone_id=int(row.id),
                    root_dns_domain="example.com",
                ),
            )


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


def test_save_config_defaults_scheduled_restart_enabled() -> None:
    _ensure_db()
    with SessionLocal() as db:
        config = letsencrypt.save_config(
            db,
            **_sample_config_kwargs(),
            scheduled_restart_enabled=True,
        )
        assert config["scheduled_restart_enabled"] is True


def test_legacy_config_missing_scheduled_restart_defaults_enabled() -> None:
    _ensure_db()
    with SessionLocal() as db:
        delete_setting(db, letsencrypt.SETTING_CONFIG)
        set_setting(
            db,
            letsencrypt.SETTING_CONFIG,
            json.dumps(
                {
                    "email": "admin@example.com",
                    "root_dns_domain": "example.com",
                    "common_name": "api.example.com",
                    "subject_alt_names": [],
                    "challenge_type": "dns-01",
                    "zone_id": None,
                    "staging": True,
                    "renew_before_expiry_days": 30,
                    "directory_url": letsencrypt.STAGING_DIRECTORY,
                }
            ),
        )
        config = letsencrypt.get_config(db)
        assert config is not None
        assert config["scheduled_restart_enabled"] is True


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


def _le_zone_row(db, *, zone_name: str = "le-detach-zone") -> DnsZoneConfig:
    row = DnsZoneConfig(
        zone_name=zone_name,
        encrypted_config=encode_zone_config_dict(
            {
                "dns_provider_type": "azure",
                "dns_zone": "example.com",
                "azure_tenant_id": "t",
                "azure_client_id": "c",
                "azure_client_secret": "s",
                "azure_subscription_id": "sub",
                "azure_resource_group": "rg",
            }
        ),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_zone_referenced_by_letsencrypt_config_and_enrollment() -> None:
    _ensure_db()
    with SessionLocal() as db:
        row = _le_zone_row(db, zone_name="le-ref-check")
        zone_id = int(row.id)
        assert letsencrypt.zone_referenced_by_letsencrypt(db, zone_id) is False
        letsencrypt.save_config(
            db,
            **_sample_config_kwargs(
                challenge_type=letsencrypt.CHALLENGE_DNS,
                zone_id=zone_id,
                root_dns_domain="example.com",
            ),
        )
        assert letsencrypt.zone_referenced_by_letsencrypt(db, zone_id) is True
        letsencrypt._write_json_setting(
            db,
            letsencrypt.SETTING_CONFIG,
            {"zone_id": None, "email": "a@b.com", "root_dns_domain": "example.com", "common_name": "api.example.com"},
        )
        letsencrypt._write_json_setting(
            db,
            letsencrypt.SETTING_ENROLLMENT,
            {"config": {"zone_id": zone_id}, "order": {}},
        )
        assert letsencrypt.zone_referenced_by_letsencrypt(db, zone_id) is True


def test_detach_dns_zone_clears_zone_id_and_disables_auto_renew() -> None:
    _ensure_db()
    with SessionLocal() as db:
        row = _le_zone_row(db, zone_name="le-detach-clear")
        letsencrypt.save_config(
            db,
            **_sample_config_kwargs(
                challenge_type=letsencrypt.CHALLENGE_DNS,
                zone_id=int(row.id),
                root_dns_domain="example.com",
            ),
            auto_renew_enabled=True,
        )
        assert letsencrypt.detach_dns_zone_from_letsencrypt(db, int(row.id)) is True
        config = letsencrypt.get_config(db)
        assert config is not None
        assert config["zone_id"] is None
        assert config["auto_renew_enabled"] is False


def test_detach_dns_zone_leaves_auto_renew_off_when_already_disabled() -> None:
    _ensure_db()
    with SessionLocal() as db:
        row = _le_zone_row(db, zone_name="le-detach-off")
        letsencrypt.save_config(
            db,
            **_sample_config_kwargs(
                challenge_type=letsencrypt.CHALLENGE_DNS,
                zone_id=int(row.id),
                root_dns_domain="example.com",
            ),
            auto_renew_enabled=False,
        )
        assert letsencrypt.detach_dns_zone_from_letsencrypt(db, int(row.id)) is True
        config = letsencrypt.get_config(db)
        assert config is not None
        assert config["zone_id"] is None
        assert config["auto_renew_enabled"] is False


def test_detach_dns_zone_noop_when_zone_not_referenced() -> None:
    _ensure_db()
    with SessionLocal() as db:
        row = _le_zone_row(db, zone_name="le-detach-referenced")
        other = _le_zone_row(db, zone_name="le-detach-other")
        letsencrypt.save_config(
            db,
            **_sample_config_kwargs(
                challenge_type=letsencrypt.CHALLENGE_DNS,
                zone_id=int(row.id),
                root_dns_domain="example.com",
            ),
        )
        assert letsencrypt.detach_dns_zone_from_letsencrypt(db, int(other.id)) is False
        config = letsencrypt.get_config(db)
        assert config is not None
        assert config["zone_id"] == int(row.id)


def test_detach_dns_zone_cancels_enrollment_referencing_zone(monkeypatch) -> None:
    deleted: list[str] = []

    def track_delete(_db, *, zone_id: int, domain: str) -> None:
        deleted.append(domain)

    monkeypatch.setattr(letsencrypt, "delete_dns_txt_challenge", track_delete)

    _ensure_db()
    with SessionLocal() as db:
        row = _le_zone_row(db, zone_name="le-detach-enroll")
        letsencrypt._write_json_setting(
            db,
            letsencrypt.SETTING_ENROLLMENT,
            {
                "status": "awaiting_manual",
                "config": {
                    "zone_id": int(row.id),
                    "challenge_type": letsencrypt.CHALLENGE_DNS,
                },
                "order": {"challenges": [{"domain": "api.example.com"}]},
            },
        )
        assert letsencrypt.detach_dns_zone_from_letsencrypt(db, int(row.id)) is True
        assert letsencrypt.get_enrollment(db) is None
    assert deleted == ["api.example.com"]
