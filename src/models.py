from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import UniqueConstraint
from sqlmodel import Field as SQLField, SQLModel

_ALLOWED_DELETE_RR = frozenset({"A", "AAAA", "CNAME", "TXT"})


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


class ApiKey(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    label: str
    key: str = SQLField(index=True, unique=True)
    active: bool = SQLField(default=True)
    created_at: datetime = SQLField(default_factory=datetime.utcnow)


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
