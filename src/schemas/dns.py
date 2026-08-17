"""Public and plugin-facing DNS request/response models.

ORM tables stay in ``src.models``. These Pydantic models are the OpenAPI contract
and the plugin record DTO surface.
"""

from pydantic import BaseModel, Field, model_validator

from ..dns_record_types import MUTABLE_RECORD_TYPES, PUBLIC_RECORD_TYPES, normalize_public_record_type

_ALLOWED_DELETE_RR = MUTABLE_RECORD_TYPES
_ALLOWED_PUBLIC_RECORD_TYPES = PUBLIC_RECORD_TYPES


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
    record_type: str = Field(
        ...,
        description="DNS record type returned by lookup: A, AAAA, CNAME, TXT, MX, NS, SRV, CAA, PTR, or SOA.",
    )
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


__all__ = (
    "DnsRecordCreateRequest",
    "DnsRecordGetResponse",
    "DnsRecordInfo",
    "DnsRecordListResult",
    "DnsRecordPatchRequest",
    "DnsRecordReplaceRequest",
    "DnsRecordRequest",
    "DnsRecordResponse",
    "DnsZoneSummary",
)
