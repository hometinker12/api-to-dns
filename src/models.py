from datetime import datetime

from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel

from .log_constants import (  # noqa: F401
    LOG_CATEGORY_ALERT,
    LOG_CATEGORY_ALERT_RULE,
    LOG_CATEGORY_DNS,
    LOG_CATEGORY_DNS_ZONE,
    LOG_CATEGORY_HTTP,
    LOG_CATEGORY_PLUGIN,
    LOG_CATEGORY_SECURITY,
    LOG_CATEGORY_SYSTEM,
    LOG_CATEGORY_USER,
    LOG_CATEGORY_VALUES,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_ORDER,
    LOG_LEVEL_VALUES,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
    SECURITY_EVENT_PREFIXES,
)
from .schemas.dns import (  # noqa: F401
    DnsRecordCreateRequest,
    DnsRecordGetResponse,
    DnsRecordInfo,
    DnsRecordListResult,
    DnsRecordPatchRequest,
    DnsRecordReplaceRequest,
    DnsRecordRequest,
    DnsRecordResponse,
    DnsZoneSummary,
)
from .time_utils import utc_now


class User(SQLModel, table=True):
    id: int | None = SQLField(default=None, primary_key=True)
    username: str = SQLField(index=True, unique=True)
    password_hash: str
    roles: str = SQLField(default="dns_zones.read")
    disabled: bool = SQLField(default=False)
    session_version: int = SQLField(default=0)


class RateLimitBucket(SQLModel, table=True):
    """Shared SQLite-backed rate-limit counters for multi-worker deployments."""

    __tablename__ = "rate_limit_bucket"
    __table_args__ = (UniqueConstraint("route_prefix", "identity_hash", "window_start", name="uq_rate_limit_bucket"),)

    id: int | None = SQLField(default=None, primary_key=True)
    route_prefix: str = SQLField(index=True)
    identity_hash: str = SQLField(index=True)
    window_start: int = SQLField(index=True)
    count: int = SQLField(default=0)
    expires_at: int = SQLField(index=True)


API_KEY_ACCESS_READ_ONLY = "read_only"
API_KEY_ACCESS_READ_WRITE = "read_write"
API_KEY_ACCESS_MODES = frozenset({API_KEY_ACCESS_READ_ONLY, API_KEY_ACCESS_READ_WRITE})


class ApiKey(SQLModel, table=True):
    id: int | None = SQLField(default=None, primary_key=True)
    label: str
    key: str = SQLField(index=True, unique=True)  # SHA-256 hex digest of the raw key
    key_prefix: str | None = SQLField(default="")
    access_mode: str = SQLField(default=API_KEY_ACCESS_READ_ONLY)
    active: bool = SQLField(default=True)
    created_at: datetime = SQLField(default_factory=utc_now)


class DnsZoneConfig(SQLModel, table=True):
    """One row per DNS zone; zone_name is the unique key (normalized). Provider settings stored encrypted."""

    __tablename__ = "dns_zone_config"

    id: int | None = SQLField(default=None, primary_key=True)
    zone_name: str = SQLField(index=True, unique=True)
    encrypted_config: str


class ApiKeyAllowedZone(SQLModel, table=True):
    """Which configured zones an API key may modify."""

    __tablename__ = "api_key_allowed_zone"
    __table_args__ = (UniqueConstraint("api_key_id", "dns_zone_config_id", name="uq_api_key_zone"),)

    id: int | None = SQLField(default=None, primary_key=True)
    api_key_id: int = SQLField(foreign_key="apikey.id", index=True)
    dns_zone_config_id: int = SQLField(foreign_key="dns_zone_config.id", index=True)


class Setting(SQLModel, table=True):
    id: int | None = SQLField(default=None, primary_key=True)
    name: str = SQLField(index=True, unique=True)
    value: str


class ActivityLog(SQLModel, table=True):
    """Searchable audit/activity event row.

    ``details_json`` should be trimmed/capped (target ~4 KB) before storage.
    DNS provider error messages and similar payloads can be verbose and
    SQLite text columns have no built-in size constraint.
    """

    __tablename__ = "activity_log"
    __table_args__ = (
        Index("ix_activity_log_timestamp", "timestamp"),
        Index("ix_activity_log_event_type", "event_type"),
        Index("ix_activity_log_level", "level"),
        Index("ix_activity_log_category", "category"),
        Index("ix_activity_log_zone_name", "zone_name"),
    )

    id: int | None = SQLField(default=None, primary_key=True)
    timestamp: datetime = SQLField(default_factory=utc_now)
    level: str = SQLField(default=LOG_LEVEL_INFORMATIONAL)
    category: str | None = SQLField(default=None)
    event_type: str = SQLField(default="")
    status: str | None = SQLField(default=None)
    actor_type: str | None = SQLField(default=None)
    actor_id: str | None = SQLField(default=None)
    actor_label: str | None = SQLField(default=None)
    zone_name: str | None = SQLField(default=None)
    record_name: str | None = SQLField(default=None)
    message: str | None = SQLField(default=None)
    details_json: str | None = SQLField(default=None)
    request_method: str | None = SQLField(default=None)
    request_path: str | None = SQLField(default=None)
    request_status_code: int | None = SQLField(default=None)
    request_ip: str | None = SQLField(default=None)


class AlertRule(SQLModel, table=True):
    __tablename__ = "alert_rule"

    id: int | None = SQLField(default=None, primary_key=True)
    enabled: bool = SQLField(default=True)
    name: str = SQLField(default="")
    event_type: str | None = SQLField(default=None)
    category: str | None = SQLField(default=None)
    minimum_level: str = SQLField(default=LOG_LEVEL_WARNING)
    message_contains: str | None = SQLField(default=None)
    email_recipients: str = SQLField(default="")
    email_subject_template: str = SQLField(default="")
    email_body_template: str = SQLField(default="")
    cooldown_minutes: int = SQLField(default=0)
    last_triggered_at: datetime | None = SQLField(default=None)
