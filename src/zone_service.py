import json
from datetime import UTC, datetime
from typing import Any

from sqlmodel import select

from .dns_client import create_dns_client, dns_provider_display_name, provider_options_for_template

__all__ = [
    "DISABLED_DNS_PLUGINS_SETTING",
    "DnsProviderDisabledError",
    "LEGACY_DNS_SETTING_NAMES",
    "api_key_admin_dict",
    "api_key_allowed_zone_names",
    "api_key_count_for_zone",
    "api_key_last_used_at",
    "api_key_public_dict",
    "api_key_zone_count",
    "dns_zone_admin_dict",
    "build_zone_config_from_form",
    "create_dns_client_from_settings",
    "decode_zone_config",
    "dns_provider_display_name",
    "dns_provider_options_with_state",
    "dns_zone_public_dict",
    "dns_zone_summary_dict",
    "enabled_dns_provider_options",
    "encode_zone_config_dict",
    "get_api_key",
    "get_disabled_dns_plugins",
    "get_dns_provider_options",
    "get_known_dns_provider_keys",
    "list_dns_zones",
    "migrate_legacy_dns_settings_if_needed",
    "normalize_zone_name",
    "provider_dns_zone",
    "set_disabled_dns_plugins",
    "test_zone_record_lookup",
    "zones_using_dns_provider",
]
from .models import ActivityLog, ApiKey, ApiKeyAllowedZone, DnsRecordInfo, DnsZoneConfig
from .security import decrypt_value, encrypt_value
from .settings_store import delete_setting, get_setting, set_setting

DISABLED_DNS_PLUGINS_SETTING = "disabled_dns_plugins"


class DnsProviderDisabledError(RuntimeError):
    """Raised when a zone's DNS provider plugin has been disabled in Settings."""


LEGACY_DNS_SETTING_NAMES = [
    "dns_provider_type",
    "dns_server",
    "dns_zone",
    "dns_username",
    "dns_password",
    "dns_tsig_algorithm",
    "dns_winrm_ssl",
    "azure_tenant_id",
    "azure_client_id",
    "azure_client_secret",
    "azure_subscription_id",
    "azure_resource_group",
]


def normalize_zone_name(zone: str) -> str:
    return zone.strip().rstrip(".").lower()


def provider_dns_zone(settings: dict[str, Any]) -> str:
    zone = normalize_zone_name(str(settings.get("dns_zone") or ""))
    if not zone:
        raise ValueError("DNS zone (domain) is required in the zone configuration.")
    return zone


def get_dns_provider_options() -> list[dict]:
    return provider_options_for_template()


def get_known_dns_provider_keys() -> set[str]:
    return {plugin["key"] for plugin in get_dns_provider_options()}


def create_dns_client_from_settings(settings: dict, db=None):
    provider = (settings.get("dns_provider_type") or "azure").strip().lower()
    if db is not None and provider in get_disabled_dns_plugins(db):
        raise DnsProviderDisabledError(
            f"{dns_provider_display_name(provider)} is disabled. "
            "Enable it in Settings before using it for DNS operations."
        )
    return create_dns_client(settings)


def get_disabled_dns_plugins(db) -> set[str]:
    raw = get_setting(db, DISABLED_DNS_PLUGINS_SETTING)
    if not raw:
        return set()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return set()
    if not isinstance(parsed, list):
        return set()
    known_keys = get_known_dns_provider_keys()
    return {str(key).strip().lower() for key in parsed if str(key).strip().lower() in known_keys}


def set_disabled_dns_plugins(db, plugin_keys) -> None:
    known_keys = get_known_dns_provider_keys()
    cleaned = sorted({str(key).strip().lower() for key in plugin_keys if str(key).strip().lower() in known_keys})
    if cleaned:
        set_setting(db, DISABLED_DNS_PLUGINS_SETTING, json.dumps(cleaned))
    else:
        delete_setting(db, DISABLED_DNS_PLUGINS_SETTING)


def dns_provider_options_with_state(db) -> list[dict]:
    disabled = get_disabled_dns_plugins(db)
    options: list[dict] = []
    for plugin in get_dns_provider_options():
        row = dict(plugin)
        row["enabled"] = row["key"] not in disabled
        row["disabled"] = not row["enabled"]
        options.append(row)
    return options


def enabled_dns_provider_options(db) -> list[dict]:
    return [plugin for plugin in dns_provider_options_with_state(db) if plugin["enabled"]]


def list_dns_zones(db) -> list[DnsZoneConfig]:
    return sorted(db.exec(select(DnsZoneConfig)).all(), key=lambda z: z.zone_name)


def decode_zone_config(row: DnsZoneConfig) -> dict[str, Any]:
    raw = decrypt_value(row.encrypted_config)
    return json.loads(raw)


def encode_zone_config_dict(cfg: dict[str, Any]) -> str:
    return encrypt_value(json.dumps(cfg))


def zones_using_dns_provider(db, provider_key: str) -> list[str]:
    matches: list[str] = []
    for zone in list_dns_zones(db):
        settings = decode_zone_config(zone)
        provider = (settings.get("dns_provider_type") or "azure").strip().lower()
        if provider == provider_key:
            matches.append(zone.zone_name)
    return matches


def migrate_legacy_dns_settings_if_needed(db) -> None:
    if db.exec(select(DnsZoneConfig)).first():
        return
    zone_raw = get_setting(db, "dns_zone")
    if not zone_raw or not str(zone_raw).strip():
        return
    canonical = normalize_zone_name(zone_raw)
    cfg = {
        "dns_provider_type": get_setting(db, "dns_provider_type") or "azure",
        "dns_server": get_setting(db, "dns_server") or "",
        "dns_username": get_setting(db, "dns_username") or "",
        "dns_password": get_setting(db, "dns_password") or "",
        "dns_tsig_algorithm": get_setting(db, "dns_tsig_algorithm") or "",
        "dns_winrm_ssl": get_setting(db, "dns_winrm_ssl") or "",
        "azure_tenant_id": get_setting(db, "azure_tenant_id") or "",
        "azure_client_id": get_setting(db, "azure_client_id") or "",
        "azure_client_secret": get_setting(db, "azure_client_secret") or "",
        "azure_subscription_id": get_setting(db, "azure_subscription_id") or "",
        "azure_resource_group": get_setting(db, "azure_resource_group") or "",
    }
    row = DnsZoneConfig(zone_name=canonical, encrypted_config=encode_zone_config_dict(cfg))
    db.add(row)
    db.commit()
    db.refresh(row)
    for key in db.exec(select(ApiKey).where(ApiKey.active.is_(True))).all():
        db.add(ApiKeyAllowedZone(api_key_id=key.id, dns_zone_config_id=row.id))
    db.commit()
    for name in LEGACY_DNS_SETTING_NAMES:
        delete_setting(db, name)


def api_key_allowed_zone_names(db, api_key_id: int) -> list[str]:
    links = db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == api_key_id)).all()
    names: list[str] = []
    for link in links:
        z = db.get(DnsZoneConfig, link.dns_zone_config_id)
        if z:
            names.append(z.zone_name)
    return sorted(names)


def api_key_count_for_zone(db, zone_id: int) -> int:
    links = db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.dns_zone_config_id == zone_id)).all()
    return len(links)


def api_key_zone_count(db, api_key_id: int) -> int:
    links = db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == api_key_id)).all()
    return len(links)


def _is_api_key_dns_usage(row: ActivityLog) -> bool:
    event_type = row.event_type or ""
    if not event_type.startswith("dns."):
        return False
    status = (row.status or "").lower()
    # GET lookups log status=not_found when no record exists (still a successful API call).
    return status in ("success", "not_found")


def api_key_last_used_at(db, api_key_id: int) -> datetime | None:
    rows = db.exec(
        select(ActivityLog)
        .where(ActivityLog.actor_type == "api_key")
        .where(ActivityLog.actor_id == str(api_key_id))
        .order_by(ActivityLog.timestamp.desc())  # type: ignore[arg-type]
    ).all()
    for row in rows:
        if _is_api_key_dns_usage(row):
            return row.timestamp
    return None


def format_api_key_last_used_label(last_used: datetime | None) -> str:
    if last_used is None:
        return "Never used"
    if last_used.tzinfo is None:
        last_used = last_used.replace(tzinfo=UTC)
    else:
        last_used = last_used.astimezone(UTC)
    return last_used.strftime("%Y-%m-%d %H:%M UTC")


def dns_zone_admin_dict(db, z: DnsZoneConfig) -> dict[str, Any]:
    from . import letsencrypt

    base = dns_zone_public_dict(z)
    zone_id = z.id
    assert zone_id is not None
    base["api_key_count"] = api_key_count_for_zone(db, zone_id)
    base["letsencrypt_referenced"] = letsencrypt.zone_referenced_by_letsencrypt(db, zone_id)
    return base


def dns_zone_public_dict(z: DnsZoneConfig) -> dict[str, Any]:
    cfg = decode_zone_config(z)
    provider_key = cfg.get("dns_provider_type", "") or "azure"
    dns_zone = (cfg.get("dns_zone") or "").strip()
    return {
        "id": z.id,
        "zone_name": z.zone_name,
        "dns_zone": dns_zone,
        "dns_provider_type": provider_key,
        "dns_provider_label": dns_provider_display_name(provider_key),
        "dns_server": cfg.get("dns_server", "") or "",
    }


def dns_zone_summary_dict(z: DnsZoneConfig) -> dict[str, Any]:
    cfg = decode_zone_config(z)
    return {"id": z.id, "zone_name": z.zone_name, "dns_zone": provider_dns_zone(cfg)}


def api_key_public_dict(k: ApiKey) -> dict[str, Any]:
    # Never expose the stored hash; UI shows the non-secret prefix only.
    display = (k.key_prefix or "").strip() or "********"
    return {"id": k.id, "label": k.label, "key": display, "key_prefix": display, "active": k.active}


def api_key_admin_dict(db, k: ApiKey) -> dict[str, Any]:
    base = api_key_public_dict(k)
    key_id = k.id
    assert key_id is not None
    last_used = api_key_last_used_at(db, key_id)
    base["zone_count"] = api_key_zone_count(db, key_id)
    base["last_used_at"] = last_used
    base["last_used_label"] = format_api_key_last_used_label(last_used)
    return base


def get_api_key(db, api_key: str):
    from .security import hash_api_key

    digest = hash_api_key(api_key)
    return db.exec(select(ApiKey).where(ApiKey.key == digest, ApiKey.active.is_(True))).first()


def _blank_preserve_secret(new_val: str, old_val: str) -> str:
    return old_val if not (new_val or "").strip() else new_val


def build_zone_config_from_form(
    form,
    existing: dict[str, Any] | None = None,
    provider_plugins: list[dict] | None = None,
) -> dict[str, Any]:
    ex = existing or {}
    provider = (form.get("dns_provider_type") or ex.get("dns_provider_type") or "azure").strip().lower()
    plugins = provider_plugins if provider_plugins is not None else get_dns_provider_options()
    plugin = next((p for p in plugins if p["key"] == provider), None)
    if plugin is None:
        if provider in get_known_dns_provider_keys():
            raise ValueError(
                f"{dns_provider_display_name(provider)} is disabled. Enable it in Settings before using it for a DNS zone."
            )
        available = ", ".join(p["key"] for p in plugins) or "none"
        raise ValueError(f"Unknown DNS provider type: {provider}. Available providers: {available}.")

    cfg: dict[str, Any] = {"dns_provider_type": provider}
    for field in plugin["fields"]:
        name = field["name"]
        if field["type"] == "checkbox":
            value = "true" if name in form else ""
        else:
            value = (form.get(name) or "").strip()
        if field["preserve_on_blank"]:
            value = _blank_preserve_secret(value, ex.get(name, ""))
        elif not value and field["default"] and not ex.get(name):
            value = field["default"]
        cfg[name] = value
    return cfg


def test_zone_record_lookup(
    cfg: dict[str, Any],
    *,
    record_name: str,
    record_type: str | None = None,
    db=None,
) -> list[DnsRecordInfo]:
    client = create_dns_client_from_settings(cfg, db=db)
    return client.get_record(
        record_name=record_name,
        record_type=record_type,
        dns_server=cfg.get("dns_server"),
        dns_zone=provider_dns_zone(cfg),
    )
