from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, model_validator
from sqlmodel import Field as SQLField, SQLModel

_ALLOWED_DELETE_RR = frozenset({"A", "AAAA", "CNAME", "TXT"})


class DnsRecordRequest(BaseModel):
    subscription_id: Optional[str] = Field(
        None,
        description="Azure subscription ID (optional if a default is saved in admin settings; not used for BIND or Microsoft WinRM).",
    )
    resource_group: Optional[str] = Field(
        None,
        description="Azure resource group containing the DNS zone (optional if a default is saved in settings).",
    )
    zone_name: Optional[str] = Field(
        None,
        description="DNS zone name (optional if Target DNS Zone is configured in settings).",
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

class User(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    username: str = SQLField(index=True, unique=True)
    password_hash: str

class ApiKey(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    label: str
    key: str = SQLField(index=True, unique=True)
    active: bool = SQLField(default=True)
    created_at: datetime = SQLField(default_factory=datetime.utcnow)

class Setting(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    name: str = SQLField(index=True, unique=True)
    value: str
