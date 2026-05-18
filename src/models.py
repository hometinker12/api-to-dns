from datetime import datetime

from .time_utils import utc_now
from typing import List, Optional

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field as SQLField, SQLModel

_ALLOWED_DELETE_RR = frozenset({"A", "AAAA", "CNAME", "TXT"})

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
    zone_name: Optional[str] = Field(
        None,
        description="DNS zone name (required). Must match a configured zone and be allowed for this API key.",
    )
    record_type: str = Field(
        ...,
        description="DNS record type: A, AAAA, CNAME, TXT, or DELETE to remove a record.",
    )
    record_name: str = Field(..., description="Record name relative to the zone, e.g. www")
    ttl: Optional[int] = Field(300, description="Time to live in seconds")
    values: List[str] = Field(
        default_factory=list,
        description="Record values. For record_type DELETE, send the RR type to remove as the first element, e.g. [\"A\"].",
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


class DnsRecordResponse(BaseModel):
    status: str = Field(..., description='Outcome: "success" or "error" (e.g. DELETE when the record does not exist).')
    action: str
    zone_name: str
    record_name: str
    record_type: str
    values: List[str]


class DnsZoneSummary(BaseModel):
    id: int
    zone_name: str


class User(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    username: str = SQLField(index=True, unique=True)
    password_hash: str
    roles: Optional[str] = SQLField(default="")
    disabled: bool = SQLField(default=False)


class ApiKey(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    label: str
    key: str = SQLField(index=True, unique=True)
    active: bool = SQLField(default=True)
    created_at: datetime = SQLField(default_factory=utc_now)


class DnsZoneConfig(SQLModel, table=True):
    """One row per DNS zone; zone_name is the unique key (normalized). Provider settings stored encrypted."""

    __tablename__ = "dns_zone_config"

    id: Optional[int] = SQLField(default=None, primary_key=True)
    zone_name: str = SQLField(index=True, unique=True)
    encrypted_config: str


class ApiKeyAllowedZone(SQLModel, table=True):
    """Which configured zones an API key may modify."""

    __tablename__ = "api_key_allowed_zone"
    __table_args__ = (UniqueConstraint("api_key_id", "dns_zone_config_id", name="uq_api_key_zone"),)

    id: Optional[int] = SQLField(default=None, primary_key=True)
    api_key_id: int = SQLField(foreign_key="apikey.id", index=True)
    dns_zone_config_id: int = SQLField(foreign_key="dns_zone_config.id", index=True)


class Setting(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
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

    id: Optional[int] = SQLField(default=None, primary_key=True)
    timestamp: datetime = SQLField(default_factory=utc_now)
    level: str = SQLField(default=LOG_LEVEL_INFORMATIONAL)
    category: Optional[str] = SQLField(default=None)
    event_type: str = SQLField(default="")
    status: Optional[str] = SQLField(default=None)
    actor_type: Optional[str] = SQLField(default=None)
    actor_id: Optional[str] = SQLField(default=None)
    actor_label: Optional[str] = SQLField(default=None)
    zone_name: Optional[str] = SQLField(default=None)
    record_name: Optional[str] = SQLField(default=None)
    message: Optional[str] = SQLField(default=None)
    details_json: Optional[str] = SQLField(default=None)
    request_method: Optional[str] = SQLField(default=None)
    request_path: Optional[str] = SQLField(default=None)
    request_status_code: Optional[int] = SQLField(default=None)
    request_ip: Optional[str] = SQLField(default=None)


class AlertRule(SQLModel, table=True):
    __tablename__ = "alert_rule"

    id: Optional[int] = SQLField(default=None, primary_key=True)
    enabled: bool = SQLField(default=True)
    name: str = SQLField(default="")
    event_type: Optional[str] = SQLField(default=None)
    category: Optional[str] = SQLField(default=None)
    minimum_level: str = SQLField(default=LOG_LEVEL_WARNING)
    message_contains: Optional[str] = SQLField(default=None)
    email_recipients: str = SQLField(default="")
    email_subject_template: str = SQLField(default="")
    email_body_template: str = SQLField(default="")
    cooldown_minutes: int = SQLField(default=0)
    last_triggered_at: Optional[datetime] = SQLField(default=None)
