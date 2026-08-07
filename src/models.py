from datetime import datetime

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel

from .dns_record_types import MUTABLE_RECORD_TYPES, PUBLIC_RECORD_TYPES, normalize_public_record_type
from .time_utils import utc_now

_ALLOWED_DELETE_RR = MUTABLE_RECORD_TYPES
_ALLOWED_PUBLIC_RECORD_TYPES = PUBLIC_RECORD_TYPES

LOG_LEVEL_VERBOSE = "VERBOSE"
LOG_LEVEL_INFORMATIONAL = "INFORMATIONAL"
LOG_LEVEL_WARNING = "WARNING"
LOG_LEVEL_ERROR = "ERROR"
LOG_LEVEL_VALUES = (LOG_LEVEL_VERBOSE, LOG_LEVEL_INFORMATIONAL, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR)
LOG_LEVEL_ORDER = {LOG_LEVEL_VERBOSE: 0, LOG_LEVEL_INFORMATIONAL: 10, LOG_LEVEL_WARNING: 20, LOG_LEVEL_ERROR: 30}

LOG_CATEGORY_SECURITY = "security"
LOG_CATEGORY_HTTP = "http"
LOG_CATEGORY_DNS = "dns"
LOG_CATEGORY_PLUGIN = "plugin"
LOG_CATEGORY_DNS_ZONE = "dns_zone"
LOG_CATEGORY_ALERT = "alert"
LOG_CATEGORY_ALERT_RULE = "alert_rule"
LOG_CATEGORY_SYSTEM = "system"
LOG_CATEGORY_USER = "user"
LOG_CATEGORY_VALUES = (
    LOG_CATEGORY_SECURITY,
    LOG_CATEGORY_HTTP,
    LOG_CATEGORY_DNS,
    LOG_CATEGORY_PLUGIN,
    LOG_CATEGORY_DNS_ZONE,
    LOG_CATEGORY_ALERT,
    LOG_CATEGORY_ALERT_RULE,
    LOG_CATEGORY_SYSTEM,
    LOG_CATEGORY_USER,
)

# Event types with these prefixes always use the security category (see infer_event_category).
SECURITY_EVENT_PREFIXES = (
    "auth.",
    "api_key.",
    "user.",
)


class DnsRecordRequest(BaseModel):
    """Internal plugin-facing record request. Not exposed in the public OpenAPI surface.

    Supports a synthetic ``DELETE`` record type used to drive plugin delete translation;
    the public REST API uses dedicated HTTP methods (POST/PUT/PATCH/DELETE) on ``/dns-record``.
    """

    zone_name: str | None = Field(
        None,
        description=(
            "Configured zone name (required). Unique key for this zone configuration in the admin UI; "
            "must match a configured zone and be allowed for this API key. Not necessarily the DNS domain."
        ),
    )
    record_type: str = Field(
        ...,
        description="DNS record type: A, AAAA, CNAME, TXT, or DELETE (internal) to remove a record.",
    )
    record_name: str = Field(..., description="Record name relative to the zone, e.g. www")
    ttl: int | None = Field(300, description="Time to live in seconds")
    values: list[str] = Field(
        default_factory=list,
        description='Record values. For record_type DELETE, send the RR type to remove as the first element, e.g. ["A"].',
    )

    @model_validator(mode="after")
    def validate_values_for_operation(self):
        rt = self.record_type.strip().upper()
        if rt == "DELETE":
            if not self.values:
                raise ValueError('DELETE requires values: first element must be the RR type to remove (e.g. ["A"]).')
            inner = self.values[0].strip().upper()
            if inner not in _ALLOWED_DELETE_RR:
                raise ValueError(
                    f"DELETE target type must be one of {', '.join(sorted(_ALLOWED_DELETE_RR))}; got {inner!r}."
                )
        elif not self.values:
            raise ValueError("values is required for this record type.")
        return self


def _validate_public_record_type(record_type: str) -> str:
    return normalize_public_record_type(record_type)


class DnsRecordCreateRequest(BaseModel):
    """Body for ``POST /dns-record`` (create only). Returns 409 if the record type already exists."""

    zone_name: str | None = Field(
        None,
        description=(
            "Configured zone name (required). Unique key for this zone configuration; "
            "must match a configured zone and be allowed for this API key. Not necessarily the DNS domain."
        ),
    )
    record_type: str = Field(..., description="DNS record type: A, AAAA, CNAME, or TXT.")
    record_name: str = Field(..., description="Record name relative to the zone, e.g. www")
    ttl: int | None = Field(300, description="Time to live in seconds (default 300).")
    values: list[str] = Field(
        default_factory=list,
        description="Record values; must contain at least one entry.",
    )

    @model_validator(mode="after")
    def _validate(self):
        _validate_public_record_type(self.record_type)
        if not self.values:
            raise ValueError("values is required and must contain at least one entry.")
        return self


class DnsRecordReplaceRequest(BaseModel):
    """Body for ``PUT /dns-record`` (full replacement). Returns 404 if the record type does not exist."""

    zone_name: str | None = Field(
        None,
        description=(
            "Configured zone name (required). Unique key for this zone configuration; "
            "must match a configured zone and be allowed for this API key. Not necessarily the DNS domain."
        ),
    )
    record_type: str = Field(..., description="DNS record type: A, AAAA, CNAME, or TXT.")
    record_name: str = Field(..., description="Record name relative to the zone, e.g. www")
    ttl: int = Field(..., description="Time to live in seconds (required for full replacement).")
    values: list[str] = Field(
        default_factory=list,
        description="Replacement values; must contain at least one entry.",
    )

    @model_validator(mode="after")
    def _validate(self):
        _validate_public_record_type(self.record_type)
        if not self.values:
            raise ValueError("values is required and must contain at least one entry.")
        return self


class DnsRecordPatchRequest(BaseModel):
    """Body for ``PATCH /dns-record`` (partial update). Returns 404 if the record type does not exist.

    Send ``ttl`` and/or ``values``; omitted fields are preserved from the live record.
    """

    zone_name: str | None = Field(
        None,
        description=(
            "Configured zone name (required). Unique key for this zone configuration; "
            "must match a configured zone and be allowed for this API key. Not necessarily the DNS domain."
        ),
    )
    record_type: str = Field(..., description="DNS record type: A, AAAA, CNAME, or TXT.")
    record_name: str = Field(..., description="Record name relative to the zone, e.g. www")
    ttl: int | None = Field(None, description="New TTL in seconds; omit to preserve the existing TTL.")
    values: list[str] | None = Field(
        None,
        description="New record values; omit to preserve existing values.",
    )

    @model_validator(mode="after")
    def _validate(self):
        _validate_public_record_type(self.record_type)
        if self.ttl is None and self.values is None:
            raise ValueError("At least one of ttl or values must be provided.")
        if self.values is not None and not self.values:
            raise ValueError("values must contain at least one entry when provided.")
        return self


class DnsRecordInfo(BaseModel):
    record_name: str = Field(..., description="Record name relative to the zone, e.g. www or @")
    record_type: str = Field(..., description="DNS record type: A, AAAA, CNAME, or TXT")
    ttl: int | None = Field(None, description="Time to live in seconds when the record exists.")
    values: list[str] | None = Field(
        None,
        description="Record rdata values in the same format as POST/PUT when available from the provider.",
    )


class DnsRecordListResult(BaseModel):
    """Internal provider result for bounded DNS browser browse/pattern searches."""

    records: list[DnsRecordInfo] = Field(default_factory=list)
    truncated: bool = False


class DnsRecordGetResponse(BaseModel):
    status: str = Field(
        ...,
        description='Outcome: "success" when one or more records are found; "not_found" when none match.',
    )
    zone_name: str
    dns_zone: str
    record_name: str
    records: list[DnsRecordInfo] = Field(
        default_factory=list,
        description=(
            "Matching records at the name. Each element includes record_name, record_type, and ttl "
            "(and values when returned by the provider). Empty when status is not_found."
        ),
    )


class DnsRecordResponse(BaseModel):
    status: str = Field(
        ...,
        description=(
            'Outcome: "success" on 2xx; "error" on 4xx (e.g. 409 record_already_exists '
            "on POST, 404 not_found on PUT/PATCH/DELETE)."
        ),
    )
    action: str = Field(
        ...,
        description=(
            'Mutation outcome: "created" (POST), "updated" (PUT/PATCH), "deleted" (DELETE), '
            '"record_already_exists" (POST 409), or "not_found" (404 on PUT/PATCH/DELETE).'
        ),
    )
    zone_name: str
    dns_zone: str
    record_name: str
    record_type: str
    values: list[str]


class DnsZoneSummary(BaseModel):
    id: int
    zone_name: str
    dns_zone: str


class User(SQLModel, table=True):
    id: int | None = SQLField(default=None, primary_key=True)
    username: str = SQLField(index=True, unique=True)
    password_hash: str
    roles: str | None = SQLField(default="")
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


class ApiKey(SQLModel, table=True):
    id: int | None = SQLField(default=None, primary_key=True)
    label: str
    key: str = SQLField(index=True, unique=True)  # SHA-256 hex digest of the raw key
    key_prefix: str | None = SQLField(default="")
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
