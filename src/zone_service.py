import json
from typing import Any, Dict, List, Optional, Set

from sqlmodel import select

from .dns_client import create_dns_client, dns_provider_display_name, provider_options_for_template

__all__ = [
    "DISABLED_DNS_PLUGINS_SETTING",
    "LEGACY_DNS_SETTING_NAMES",
    "api_key_allowed_zone_names",
    "api_key_public_dict",
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
    "set_disabled_dns_plugins",
    "test_zone_record_lookup",
    "zones_using_dns_provider",
]
from .models import ApiKey, ApiKeyAllowedZone, DnsRecordInfo, DnsZoneConfig
from .security import decrypt_value, encrypt_value
from .settings_store import delete_setting, get_setting, set_setting

DISABLED_DNS_PLUGINS_SETTING = "disabled_dns_plugins"

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


def get_dns_provider_options() -> List[dict]:
    return provider_options_for_template()


def get_known_dns_provider_keys() -> Set[str]:
    return {plugin["key"] for plugin in get_dns_provider_options()}


def create_dns_client_from_settings(settings: dict):
    return create_dns_client(settings)


def get_disabled_dns_plugins(db) -> Set[str]:
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


def dns_provider_options_with_state(db) -> List[dict]:
    disabled = get_disabled_dns_plugins(db)
    options: List[dict] = []
    for plugin in get_dns_provider_options():
        row = dict(plugin)
        row["enabled"] = row["key"] not in disabled
        row["disabled"] = not row["enabled"]
        options.append(row)
    return options


def enabled_dns_provider_options(db) -> List[dict]:
    return [plugin for plugin in dns_provider_options_with_state(db) if plugin["enabled"]]


def list_dns_zones(db) -> List[DnsZoneConfig]:
    return sorted(db.exec(select(DnsZoneConfig)).all(), key=lambda z: z.zone_name)


def decode_zone_config(row: DnsZoneConfig) -> Dict[str, Any]:
    raw = decrypt_value(row.encrypted_config)
    return json.loads(raw)


def encode_zone_config_dict(cfg: Dict[str, Any]) -> str:
    return encrypt_value(json.dumps(cfg))


def zones_using_dns_provider(db, provider_key: str) -> List[str]:
    matches: List[str] = []
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
    for key in db.exec(select(ApiKey).where(ApiKey.active == True)).all():
        db.add(ApiKeyAllowedZone(api_key_id=key.id, dns_zone_config_id=row.id))
    db.commit()
    for name in LEGACY_DNS_SETTING_NAMES:
        delete_setting(db, name)


def api_key_allowed_zone_names(db, api_key_id: int) -> List[str]:
    links = db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == api_key_id)).all()
    names: List[str] = []
    for link in links:
        z = db.get(DnsZoneConfig, link.dns_zone_config_id)
        if z:
            names.append(z.zone_name)
    return sorted(names)


def dns_zone_public_dict(z: DnsZoneConfig) -> Dict[str, Any]:
    cfg = decode_zone_config(z)
    provider_key = cfg.get("dns_provider_type", "") or "azure"
    return {
        "id": z.id,
        "zone_name": z.zone_name,
        "dns_provider_type": provider_key,
        "dns_provider_label": dns_provider_display_name(provider_key),
        "dns_server": cfg.get("dns_server", "") or "",
    }


def dns_zone_summary_dict(z: DnsZoneConfig) -> Dict[str, Any]:
    return {"id": z.id, "zone_name": z.zone_name}


def api_key_public_dict(k: ApiKey) -> Dict[str, Any]:
    return {"id": k.id, "label": k.label, "key": k.key, "active": k.active}


def get_api_key(db, api_key: str):
    return db.exec(select(ApiKey).where(ApiKey.key == api_key, ApiKey.active == True)).first()


def _blank_preserve_secret(new_val: str, old_val: str) -> str:
    return old_val if not (new_val or "").strip() else new_val


def build_zone_config_from_form(
    form,
    existing: Optional[Dict[str, Any]] = None,
    provider_plugins: Optional[List[dict]] = None,
) -> Dict[str, Any]:
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

    cfg: Dict[str, Any] = {"dns_provider_type": provider}
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
    cfg: Dict[str, Any],
    *,
    record_name: str,
    zone_name: str,
    record_type: Optional[str] = None,
) -> List[DnsRecordInfo]:
    client = create_dns_client_from_settings(cfg)
    return client.get_record(
        record_name=record_name,
        record_type=record_type,
        dns_server=cfg.get("dns_server"),
        dns_zone=zone_name,
    )
