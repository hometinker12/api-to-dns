from datetime import datetime, timezone

from sqlmodel import select

from src.db import SessionLocal, init_db
from src.models import ActivityLog, ApiKey, ApiKeyAllowedZone, DnsZoneConfig
from src.zone_service import (
    api_key_count_for_zone,
    api_key_last_used_at,
    api_key_zone_count,
    dns_zone_admin_dict,
    encode_zone_config_dict,
    format_api_key_last_used_label,
)


def _ensure_db() -> None:
    init_db()


def test_api_key_count_for_zone() -> None:
    _ensure_db()
    with SessionLocal() as db:
        zone = DnsZoneConfig(
            zone_name="count-zone-a",
            encrypted_config=encode_zone_config_dict(
                {"dns_provider_type": "azure", "dns_zone": "example.com", "azure_subscription_id": "s", "azure_resource_group": "rg"}
            ),
        )
        db.add(zone)
        db.commit()
        db.refresh(zone)
        zone_id = int(zone.id)
        assert api_key_count_for_zone(db, zone_id) == 0
        for label in ("key-one", "key-two"):
            key = ApiKey(label=label, key=f"secret-{label}", active=True)
            db.add(key)
            db.commit()
            db.refresh(key)
            db.add(ApiKeyAllowedZone(api_key_id=int(key.id), dns_zone_config_id=zone_id))
        db.commit()
        assert api_key_count_for_zone(db, zone_id) == 2


def test_api_key_last_used_at_from_activity_log() -> None:
    _ensure_db()
    with SessionLocal() as db:
        key = ApiKey(label="used-key", key="secret-used-key", active=True)
        db.add(key)
        db.commit()
        db.refresh(key)
        key_id = int(key.id)
        assert api_key_last_used_at(db, key_id) is None
        ts = datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc)
        db.add(
            ActivityLog(
                event_type="dns.record_lookup",
                status="success",
                actor_type="api_key",
                actor_id=str(key_id),
                actor_label="used-key",
                timestamp=ts,
            )
        )
        db.commit()
        last_used = api_key_last_used_at(db, key_id)
        assert last_used is not None
        assert last_used.replace(tzinfo=timezone.utc) == ts
        assert format_api_key_last_used_label(ts) == "2026-05-20 12:00 UTC"
        assert format_api_key_last_used_label(None) == "Never used"


def test_api_key_last_used_at_counts_not_found_lookup() -> None:
    _ensure_db()
    with SessionLocal() as db:
        key = ApiKey(label="lookup-key", key="secret-lookup-key", active=True)
        db.add(key)
        db.commit()
        db.refresh(key)
        key_id = int(key.id)
        ts = datetime(2026, 5, 21, 9, 30, tzinfo=timezone.utc)
        db.add(
            ActivityLog(
                event_type="dns.record_lookup",
                status="not_found",
                actor_type="api_key",
                actor_id=str(key_id),
                actor_label="lookup-key",
                timestamp=ts,
            )
        )
        db.commit()
        last_used = api_key_last_used_at(db, key_id)
        assert last_used is not None
        assert last_used.replace(tzinfo=timezone.utc) == ts


def test_dns_zone_admin_dict_includes_counts() -> None:
    _ensure_db()
    with SessionLocal() as db:
        zone = DnsZoneConfig(
            zone_name="admin-dict-zone",
            encrypted_config=encode_zone_config_dict(
                {"dns_provider_type": "azure", "dns_zone": "example.com", "azure_subscription_id": "s", "azure_resource_group": "rg"}
            ),
        )
        db.add(zone)
        db.commit()
        db.refresh(zone)
        view = dns_zone_admin_dict(db, zone)
        assert view["api_key_count"] == 0
        assert view["letsencrypt_referenced"] is False
