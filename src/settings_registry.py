"""Inventory of persistent encrypted Setting rows (not .env secrets)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ValueType = Literal["str", "bool", "int", "json"]


@dataclass(frozen=True)
class SettingSpec:
    key: str
    value_type: ValueType
    default: str | None
    sensitive: bool
    area: str
    description: str


def _spec(
    key: str,
    value_type: ValueType,
    *,
    default: str | None = None,
    sensitive: bool = False,
    area: str,
    description: str,
) -> SettingSpec:
    return SettingSpec(
        key=key,
        value_type=value_type,
        default=default,
        sensitive=sensitive,
        area=area,
        description=description,
    )


SETTING_SPECS: tuple[SettingSpec, ...] = (
    _spec("ssl_enabled", "bool", default="false", area="ssl", description="Serve the admin UI and API over HTTPS."),
    _spec("restart_required", "bool", default="false", area="restart", description="Pending application restart flag."),
    _spec(
        "restart_reason",
        "str",
        default="Application restart required.",
        area="restart",
        description="Operator-visible restart reason.",
    ),
    _spec(
        "last_scheduled_restart_date",
        "str",
        area="restart",
        description="UTC date of the last scheduled certificate restart.",
    ),
    _spec(
        "letsencrypt_renewal_pending_restart",
        "bool",
        default="false",
        area="restart",
        description="Let's Encrypt renewal is waiting for a scheduled restart.",
    ),
    _spec("letsencrypt_config", "json", area="ssl", description="Let's Encrypt enrollment and renewal configuration."),
    _spec("letsencrypt_enrollment", "json", area="ssl", description="In-progress Let's Encrypt enrollment state."),
    _spec(
        "letsencrypt_enrollment_progress",
        "json",
        area="ssl",
        description="Let's Encrypt enrollment progress shown in the admin UI.",
    ),
    _spec(
        "disabled_dns_plugins", "json", default="[]", area="plugins", description="Disabled DNS provider plugin keys."
    ),
    _spec(
        "backup_restore_progress",
        "json",
        area="backup",
        description="In-progress backup restore status (not exported).",
    ),
    _spec("log_level", "str", default="INFORMATIONAL", area="logging", description="Activity log storage level."),
    _spec(
        "activity_retention_days", "int", default="90", area="logging", description="Activity log retention in days."
    ),
    _spec(
        "last_activity_retention_cleanup",
        "str",
        area="logging",
        description="Timestamp of the last activity-log retention cleanup.",
    ),
    _spec(
        "operational_log_file",
        "str",
        default="",
        area="logging",
        description="Optional rotating operational log file path.",
    ),
    _spec(
        "operational_log_max_bytes",
        "int",
        default="1048576",
        area="logging",
        description="Operational log rotation size in bytes.",
    ),
    _spec(
        "operational_log_backup_count",
        "int",
        default="5",
        area="logging",
        description="Number of rotated operational log files to keep.",
    ),
    _spec("app_dns_name", "str", default="", area="system", description="Configured application DNS name."),
    _spec("smtp_servers", "str", default="", area="smtp", description="Ordered CSV list of SMTP servers."),
    _spec("smtp_port", "int", default="587", area="smtp", description="SMTP port."),
    _spec("smtp_anonymous", "bool", default="false", area="smtp", description="Skip SMTP authentication."),
    _spec("smtp_username", "str", default="", area="smtp", description="SMTP username."),
    _spec("smtp_password", "str", default="", sensitive=True, area="smtp", description="SMTP password."),
    _spec("smtp_from", "str", default="", area="smtp", description="SMTP From address."),
    _spec(
        "smtp_security",
        "str",
        default="starttls",
        area="smtp",
        description="SMTP transport security (none, starttls, ssl).",
    ),
    _spec("smtp_timeout", "int", default="10", area="smtp", description="SMTP timeout in seconds."),
    _spec(
        "smtp_allow_insecure_auth",
        "bool",
        default="false",
        area="smtp",
        description="Allow SMTP authentication without TLS.",
    ),
    _spec(
        "remote_syslog_enabled",
        "bool",
        default="false",
        area="syslog",
        description="Forward stored activity events to remote syslog.",
    ),
    _spec("remote_syslog_host", "str", default="", area="syslog", description="Remote syslog hostname or IP."),
    _spec("remote_syslog_port", "int", default="6514", area="syslog", description="Remote syslog port."),
    _spec(
        "remote_syslog_protocol",
        "str",
        default="tls",
        area="syslog",
        description="Remote syslog protocol (tls, tcp, udp).",
    ),
    _spec("remote_syslog_facility", "str", default="local0", area="syslog", description="Remote syslog facility."),
    _spec(
        "remote_syslog_minimum_level",
        "str",
        default="INFORMATIONAL",
        area="syslog",
        description="Minimum activity level to forward.",
    ),
    _spec(
        "remote_syslog_timeout",
        "str",
        default="5.0",
        area="syslog",
        description="Remote syslog network timeout in seconds.",
    ),
    _spec(
        "remote_syslog_queue_size",
        "int",
        default="1000",
        area="syslog",
        description="In-process remote syslog queue size.",
    ),
    _spec(
        "remote_syslog_allow_insecure_plaintext",
        "bool",
        default="false",
        area="syslog",
        description="Allow plaintext UDP/TCP syslog without TLS.",
    ),
    # Legacy global DNS credentials (migrated into per-zone encrypted_config).
    _spec(
        "dns_provider_type",
        "str",
        default="azure",
        sensitive=True,
        area="legacy_dns",
        description="Legacy global DNS provider type.",
    ),
    _spec(
        "dns_server", "str", default="", sensitive=True, area="legacy_dns", description="Legacy global DNS server host."
    ),
    _spec("dns_zone", "str", default="", area="legacy_dns", description="Legacy global DNS zone name."),
    _spec(
        "dns_username",
        "str",
        default="",
        sensitive=True,
        area="legacy_dns",
        description="Legacy global DNS username or TSIG key name.",
    ),
    _spec(
        "dns_password",
        "str",
        default="",
        sensitive=True,
        area="legacy_dns",
        description="Legacy global DNS password or TSIG secret.",
    ),
    _spec("dns_tsig_algorithm", "str", default="", area="legacy_dns", description="Legacy global TSIG algorithm."),
    _spec("dns_winrm_ssl", "str", default="", area="legacy_dns", description="Legacy global WinRM SSL flag."),
    _spec(
        "azure_tenant_id",
        "str",
        default="",
        sensitive=True,
        area="legacy_dns",
        description="Legacy global Azure tenant ID.",
    ),
    _spec(
        "azure_client_id",
        "str",
        default="",
        sensitive=True,
        area="legacy_dns",
        description="Legacy global Azure client ID.",
    ),
    _spec(
        "azure_client_secret",
        "str",
        default="",
        sensitive=True,
        area="legacy_dns",
        description="Legacy global Azure client secret.",
    ),
    _spec(
        "azure_subscription_id",
        "str",
        default="",
        sensitive=True,
        area="legacy_dns",
        description="Legacy global Azure subscription ID.",
    ),
    _spec(
        "azure_resource_group", "str", default="", area="legacy_dns", description="Legacy global Azure resource group."
    ),
)

SETTINGS: dict[str, SettingSpec] = {spec.key: spec for spec in SETTING_SPECS}
if len(SETTINGS) != len(SETTING_SPECS):
    raise RuntimeError("Duplicate setting keys in SETTING_SPECS")


def get_spec(key: str) -> SettingSpec | None:
    return SETTINGS.get(key)
