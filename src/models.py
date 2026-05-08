from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from sqlmodel import Field as SQLField, SQLModel

class DnsRecordRequest(BaseModel):
    subscription_id: Optional[str] = Field(None, description="Azure subscription ID")
    resource_group: Optional[str] = Field(None, description="Azure resource group containing the DNS zone")
    zone_name: Optional[str] = Field(None, description="DNS zone name, e.g. example.com")
    record_type: str = Field(..., description="DNS record type, e.g. A, AAAA, CNAME, TXT")
    record_name: str = Field(..., description="Record name relative to the zone, e.g. www")
    ttl: Optional[int] = Field(300, description="Time to live in seconds")
    values: List[str] = Field(..., description="Record values (addresses or targets)")

class DnsRecordResponse(BaseModel):
    status: str
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
