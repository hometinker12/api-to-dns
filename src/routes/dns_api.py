from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from starlette.status import HTTP_404_NOT_FOUND, HTTP_409_CONFLICT

from ..activity_logging import emit_activity_event
from ..db import SessionLocal
from ..dns_api_service import (
    _MUTATION_RESPONSES,
    _apply_dns_mutation,
    _resolve_dns_api_zone,
)
from ..http_utils import (
    api_key_from_headers,
    http_exception_from_dns_error,
    sanitize_client_error_message,
)
from ..models import (
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_WARNING,
    DnsRecordCreateRequest,
    DnsRecordGetResponse,
    DnsRecordPatchRequest,
    DnsRecordReplaceRequest,
    DnsRecordResponse,
)
from ..plugins.utils import normalize_lookup_record_type
from ..web import record_activity
from ..zone_service import get_api_key, provider_dns_zone


def _test_zone_record_lookup(*args, **kwargs):
    from .. import app as app_module

    return app_module.test_zone_record_lookup(*args, **kwargs)


router = APIRouter(tags=["dns"])


@router.get(
    "/keycheck",
    responses={
        200: {
            "description": "API key is valid",
            "content": {
                "application/json": {
                    "example": {"status": "success"},
                    "schema": {
                        "type": "object",
                        "properties": {"status": {"type": "string", "example": "success"}},
                        "required": ["status"],
                    },
                }
            },
        },
        401: {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "example": {"status": "failure"},
                    "schema": {
                        "type": "object",
                        "properties": {"status": {"type": "string", "example": "failure"}},
                        "required": ["status"],
                    },
                }
            },
        },
    },
)
def keycheck(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)

    if not api_key:
        return JSONResponse(status_code=401, content={"status": "failure"})

    with SessionLocal() as db:
        key = get_api_key(db, api_key)
        if key is None:
            return JSONResponse(status_code=401, content={"status": "failure"})

    return {"status": "success"}


@router.get(
    "/dns-record",
    response_model=DnsRecordGetResponse,
    summary="Look up DNS records",
    description=(
        "Return records at a name in a configured zone as a ``records`` array. "
        "Each found record includes ``record_name``, ``record_type``, ``ttl``, and ``values`` when "
        "returned by the provider. Optional ``record_type`` filters which types appear in the array. "
        "Requires a valid API key with access to the zone."
    ),
    responses={
        400: {"description": "Invalid request, record type, or zone configuration."},
        401: {"description": "API key is missing or invalid."},
        403: {"description": "API key is not allowed to use this zone, or the zone is not configured."},
        502: {"description": "DNS provider reported a failure (e.g. WinRM or dynamic update)."},
        503: {"description": "A required component is not installed or misconfigured."},
    },
)
def get_dns_record(
    zone_name: str = Query(..., description="DNS zone name. Must match a configured zone allowed for this API key."),
    record_name: str = Query(..., description="Record name relative to the zone, e.g. www or @"),
    record_type: str | None = Query(
        None,
        description=(
            "Optional DNS record type: A, AAAA, CNAME, TXT, MX, NS, SRV, CAA, PTR, or SOA. "
            "Omit to return all supported types at the name."
        ),
    ),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)

    if not api_key:
        record_activity(
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            message="API key missing on GET /dns-record",
        )
        raise HTTPException(status_code=401, detail="API key is required")

    with SessionLocal() as db:
        _key, zone_row, settings, actor_id, actor_label, provider = _resolve_dns_api_zone(
            db,
            api_key=api_key,
            zone_name=zone_name,
            record_name=record_name,
            endpoint="GET /dns-record",
        )
        provider_domain = provider_dns_zone(settings)

        try:
            lookup_type = normalize_lookup_record_type(record_type)
            records = _test_zone_record_lookup(
                settings,
                record_name=record_name,
                record_type=lookup_type,
                db=db,
            )
        except ValueError as exc:
            emit_activity_event(
                db,
                event_type="dns.invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=str(exc),
            )
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "message": str(exc)},
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            mapped = http_exception_from_dns_error(exc)
            sanitized_error = sanitize_client_error_message(exc, fallback="DNS provider error")
            emit_activity_event(
                db,
                event_type="dns.provider_failed",
                level=LOG_LEVEL_ERROR,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=sanitized_error,
                details={
                    "provider": provider,
                    "record_type": record_type,
                    "exception_type": type(exc).__name__,
                },
            )
            raise mapped from exc

        status = "success" if records else "not_found"
        message = (
            f"Found {len(records)} record(s) at {record_name!r} in zone {provider_domain!r}."
            if records
            else (
                f"No {lookup_type} record found at {record_name!r} in zone {provider_domain!r}."
                if lookup_type
                else f"No supported records found at {record_name!r} in zone {provider_domain!r}."
            )
        )
        emit_activity_event(
            db,
            event_type="dns.record_lookup",
            level=LOG_LEVEL_INFORMATIONAL,
            status=status,
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            zone_name=zone_row.zone_name,
            record_name=record_name,
            message=message,
            details={
                "provider": provider,
                "record_type": record_type,
                "records_found": len(records),
            },
        )
        return DnsRecordGetResponse(
            status=status,
            zone_name=zone_row.zone_name,
            dns_zone=provider_domain,
            record_name=record_name,
            records=records,
        )


@router.post(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Create a DNS record",
    description=(
        "Create a new DNS record of the given type. "
        "Pre-checks the zone with ``get_record`` and returns **409** "
        "``record_already_exists`` if a record of that type is already present at the name."
    ),
    responses={
        HTTP_409_CONFLICT: {
            "description": "A record of this type already exists at this name.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def create_dns_record(
    payload: DnsRecordCreateRequest,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=payload.zone_name,
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=payload.ttl,
        values=payload.values,
        mode="create",
        endpoint="POST /dns-record",
    )


@router.put(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Replace a DNS record (full update)",
    description=(
        "Replace the record's type, TTL, and values. "
        "Pre-checks with ``get_record`` and returns **404** ``not_found`` if no record "
        "of the given type exists at the name."
    ),
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "No matching record exists at this name and type.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def replace_dns_record(
    payload: DnsRecordReplaceRequest,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=payload.zone_name,
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=payload.ttl,
        values=payload.values,
        mode="replace",
        endpoint="PUT /dns-record",
    )


@router.patch(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Update a DNS record (partial update)",
    description=(
        "Update ``ttl`` and/or ``values`` on an existing record. Omitted fields are preserved "
        "from the live record (via ``get_record``). Returns **404** ``not_found`` if no record "
        "of the given type exists at the name."
    ),
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "No matching record exists at this name and type.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def patch_dns_record(
    payload: DnsRecordPatchRequest,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=payload.zone_name,
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=None,
        values=[],
        mode="patch",
        endpoint="PATCH /dns-record",
        patch_ttl=payload.ttl,
        patch_values=payload.values,
    )


@router.delete(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Delete a DNS record",
    description=(
        "Delete the record of the given type at the given name. "
        "Identity is taken from query parameters (same as ``GET /dns-record``). "
        "Pre-checks with ``get_record`` and returns **404** ``not_found`` if no record "
        "of the given type exists at the name."
    ),
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "No matching record exists at this name and type.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def delete_dns_record(
    zone_name: str = Query(..., description="DNS zone name. Must match a configured zone allowed for this API key."),
    record_name: str = Query(..., description="Record name relative to the zone, e.g. www or @"),
    record_type: str = Query(..., description="DNS record type to remove: A, AAAA, CNAME, or TXT."),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    try:
        from ..dns_record_types import normalize_public_record_type

        normalized_type = normalize_public_record_type(record_type)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": str(exc)},
        ) from exc
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=zone_name,
        record_name=record_name,
        record_type=normalized_type,
        ttl=None,
        values=[],
        mode="delete",
        endpoint="DELETE /dns-record",
    )
