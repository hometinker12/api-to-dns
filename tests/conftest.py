"""Pytest configuration and shared fixtures."""

import os
import tempfile

_db = tempfile.NamedTemporaryFile(prefix="api-to-dns-test-", suffix=".db", delete=False)
_db.close()
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.abspath(_db.name).replace("\\", "/")

# Keep the test client on plain HTTP regardless of any persisted ssl_enabled
# setting, and isolate any SSL artefacts under a per-test-process temp dir so
# CI runners do not need openssl on PATH and never share cert state with the
# host repository checkout.
_ssl_cert_dir = tempfile.mkdtemp(prefix="api-to-dns-test-ssl-")
os.environ["APP_SSL_DIR"] = _ssl_cert_dir
os.environ["SSL_ENABLED"] = "0"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import select  # noqa: E402

from src.app import ALL_ROLES, _serialize_roles, app  # noqa: E402
from src.db import SessionLocal, init_db  # noqa: E402
from src.models import ApiKey, ApiKeyAllowedZone, DnsZoneConfig, User  # noqa: E402
from src.security import hash_password  # noqa: E402
from src.zone_service import encode_zone_config_dict, normalize_zone_name, set_disabled_dns_plugins  # noqa: E402


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
        if not db.exec(select(User).where(User.username == "admin")).first():
            db.add(User(username="admin", password_hash=hash_password("x"), roles=_serialize_roles(ALL_ROLES)))
            db.commit()
    return TestClient(app)
