"""DNS public API helpers shared by route handlers and tests."""

from typing import Any, Literal

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import select
from starlette.status import HTTP_404_NOT_FOUND, HTTP_409_CONFLICT

from . import zone_service
from .activity_logging import emit_activity_event
from .dns_mutation import (
    PatchMergeError,
    apply_patch_mutation,
    apply_rrset_mutation,
    prepare_mutation,
    record_exists_at_type,
)
from .http_utils import api_key_fingerprint, http_exception_from_dns_error, sanitize_client_error_message
from .models import (
    API_KEY_ACCESS_READ_WRITE,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_WARNING,
    ApiKey,
    ApiKeyAllowedZone,
    DnsRecordResponse,
    DnsZoneConfig,
)
from .web import record_activity
from .zone_service import (
    DnsProviderDisabledError,
    decode_zone_config,
    dns_provider_display_name,
    get_api_key,
    get_disabled_dns_plugins,
    normalize_zone_name,
    provider_dns_zone,
)

ACCESS_DENIED_DETAIL: dict[str, str] = {
    "error": "access_denied",
    "message": "You do not have access or an invalid key was provided.",
}

_MUTATION_RESPONSES: dict[int, dict[str, Any]] = {
    400: {"description": "Invalid request, record type, or configuration."},
    401: {"description": "API key is missing or invalid."},
    403: {"description": "API key is read-only, is not allowed to use this zone, or the zone is not configured."},
    502: {"description": "DNS provider reported a failure (e.g. WinRM or dynamic update)."},
    503: {"description": "A required component is not installed or misconfigured."},
}


def _resolve_dns_api_zone(
    db,
    *,
    api_key: str,
    zone_name: str,
    record_name: str,
    endpoint: str,
) -> tuple[ApiKey, DnsZoneConfig, dict[str, Any], str | None, str, str]:
    key = get_api_key(db, api_key)
    if key is None:
        emit_activity_event(
            db,
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_label="invalid",
            message=f"Invalid or revoked API key used on {endpoint}",
            details={"key_fingerprint": api_key_fingerprint(api_key)},
        )
        raise HTTPException(status_code=401, detail="Invalid API key")

    actor_id = str(key.id) if key.id is not None else None
    actor_label = key.label

    if not zone_name or not str(zone_name).strip():
        emit_activity_event(
            db,
            event_type="dns.invalid_request",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            record_name=record_name,
            message=f"zone_name is required on {endpoint}",
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": "zone_name is required on every request."},
        )

    canonical = normalize_zone_name(zone_name)
    zone_row = db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == canonical)).first()
    if zone_row is None:
        emit_activity_event(
            db,
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            zone_name=canonical,
            record_name=record_name,
            message=f"Unknown DNS zone {canonical!r}",
        )
        raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)

    perm = db.exec(
        select(ApiKeyAllowedZone).where(
            ApiKeyAllowedZone.api_key_id == key.id,
            ApiKeyAllowedZone.dns_zone_config_id == zone_row.id,
        )
    ).first()
    if perm is None:
        emit_activity_event(
            db,
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            zone_name=canonical,
            record_name=record_name,
            message=f"API key {actor_label!r} not allowed for zone {canonical!r}",
        )
        raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)

    settings = decode_zone_config(zone_row)
    provider = (settings.get("dns_provider_type") or "azure").strip().lower()
    if provider == "azure":
        if not settings.get("azure_subscription_id"):
            emit_activity_event(
                db,
                event_type="dns.invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=canonical,
                record_name=record_name,
                message="Azure subscription ID is required on the zone configuration.",
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "message": "Azure subscription ID is required on the zone configuration.",
                },
            )
        if not settings.get("azure_resource_group"):
            emit_activity_event(
                db,
                event_type="dns.invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=canonical,
                record_name=record_name,
                message="Azure resource group is required on the zone configuration.",
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "message": "Azure resource group is required on the zone configuration.",
                },
            )

    return key, zone_row, settings, actor_id, actor_label, provider


def _require_dns_api_key_write_access(
    db,
    *,
    key: ApiKey,
    actor_id: str | None,
    actor_label: str,
    zone_name: str,
    record_name: str,
    endpoint: str,
) -> None:
    """Reject DNS mutations unless the resolved API key explicitly allows writes."""
    if key.access_mode == API_KEY_ACCESS_READ_WRITE:
        return
    emit_activity_event(
        db,
        event_type="dns.access_denied",
        level=LOG_LEVEL_WARNING,
        status="error",
        actor_type="api_key",
        actor_id=actor_id,
        actor_label=actor_label,
        zone_name=zone_name,
        record_name=record_name,
        message=f"Read-only API key {actor_label!r} denied on {endpoint}",
        details={"access_mode": key.access_mode, "required_access_mode": API_KEY_ACCESS_READ_WRITE},
    )
    raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)


def _record_exists_at_type(
    client,
    *,
    settings: dict[str, Any],
    record_name: str,
    record_type: str,
) -> bool:
    """Return True if the DNS provider reports any record of *record_type* at *record_name*."""
    return record_exists_at_type(
        client,
        settings=settings,
        record_name=record_name,
        record_type=record_type,
    )


def _apply_dns_mutation(
    db,
    *,
    api_key: str | None,
    zone_name: str | None,
    record_name: str,
    record_type: str,
    ttl: int | None,
    values: list[str],
    mode: Literal["create", "replace", "patch", "delete"],
    endpoint: str,
    patch_ttl: int | None = None,
    patch_values: list[str] | None = None,
):
    """Shared pre-check + mutation flow for POST/PUT/PATCH/DELETE on ``/dns-record``."""

    if not api_key:
        record_activity(
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            message=f"API key missing on {endpoint}",
        )
        raise HTTPException(status_code=401, detail="API key is required")

    rt_upper = (record_type or "").strip().upper()

    key, zone_row, settings, actor_id, actor_label, provider = _resolve_dns_api_zone(
        db,
        api_key=api_key,
        zone_name=zone_name or "",
        record_name=record_name,
        endpoint=endpoint,
    )
    _require_dns_api_key_write_access(
        db,
        key=key,
        actor_id=actor_id,
        actor_label=actor_label,
        zone_name=zone_row.zone_name,
        record_name=record_name,
        endpoint=endpoint,
    )

    try:
        if provider in get_disabled_dns_plugins(db):
            raise DnsProviderDisabledError(
                f"{dns_provider_display_name(provider)} is disabled. "
                "Enable it in Settings before using it for DNS operations."
            )
        client = zone_service.create_dns_client_from_settings(settings, db=db)
        provider_domain = provider_dns_zone(settings)
        prepared = prepare_mutation(
            record_name=record_name,
            record_type=rt_upper,
            ttl=ttl if mode != "patch" else patch_ttl,
            values=list(values) if mode not in ("delete", "patch") else list(patch_values or []),
            dns_zone=provider_domain,
            require_values=mode not in ("delete", "patch") or (mode == "patch" and patch_values is not None),
            require_ttl=mode == "replace",
        )

        if mode == "patch":
            try:
                outcome = apply_patch_mutation(
                    client,
                    settings=settings,
                    zone_name=zone_row.zone_name,
                    record_name=prepared.record_name,
                    record_type=prepared.record_type,
                    patch_ttl=prepared.ttl if patch_ttl is not None else None,
                    patch_values=prepared.values if patch_values is not None else None,
                )
            except PatchMergeError as exc:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "error": "dns_provider_failed",
                        "message": str(exc),
                    },
                ) from exc
            body = DnsRecordResponse(
                status=outcome.status,
                action=outcome.action,
                zone_name=zone_row.zone_name,
                dns_zone=outcome.dns_zone,
                record_name=outcome.record_name,
                record_type=outcome.record_type,
                values=outcome.values,
            )
            if outcome.http_status == HTTP_404_NOT_FOUND:
                emit_activity_event(
                    db,
                    event_type="dns.record_not_found",
                    level=LOG_LEVEL_WARNING,
                    status="error",
                    actor_type="api_key",
                    actor_id=actor_id,
                    actor_label=actor_label,
                    zone_name=zone_row.zone_name,
                    record_name=record_name,
                    message=f"DNS record {record_name}.{provider_domain} {prepared.record_type} not found",
                    details={"record_type": prepared.record_type, "provider": provider},
                )
                return JSONResponse(status_code=HTTP_404_NOT_FOUND, content=body.model_dump())
            emit_activity_event(
                db,
                event_type="dns.record_updated",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=f"DNS record {record_name}.{provider_domain} updated",
                details={
                    "record_type": prepared.record_type,
                    "values_count": len(outcome.values),
                    "provider": provider,
                },
            )
            return body

        outcome = apply_rrset_mutation(
            client,
            settings=settings,
            zone_name=zone_row.zone_name,
            record_name=prepared.record_name,
            record_type=prepared.record_type,
            ttl=prepared.ttl,
            values=list(prepared.values),
            mode=mode,  # type: ignore[arg-type]
        )
        body = DnsRecordResponse(
            status=outcome.status,
            action=outcome.action,
            zone_name=zone_row.zone_name,
            dns_zone=outcome.dns_zone,
            record_name=outcome.record_name,
            record_type=outcome.record_type,
            values=outcome.values,
        )
        if outcome.http_status == HTTP_409_CONFLICT:
            emit_activity_event(
                db,
                event_type="dns.record_already_exists",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=f"DNS record {record_name}.{provider_domain} {rt_upper} already exists",
                details={"record_type": rt_upper, "provider": provider},
            )
            return JSONResponse(status_code=HTTP_409_CONFLICT, content=body.model_dump())
        if outcome.http_status == HTTP_404_NOT_FOUND:
            emit_activity_event(
                db,
                event_type="dns.record_not_found",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=f"DNS record {record_name}.{provider_domain} {rt_upper} not found",
                details={"record_type": rt_upper, "provider": provider},
            )
            return JSONResponse(status_code=HTTP_404_NOT_FOUND, content=body.model_dump())

        emit_activity_event(
            db,
            event_type=f"dns.record_{outcome.action}",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            zone_name=zone_row.zone_name,
            record_name=record_name,
            message=f"DNS record {record_name}.{provider_domain} {outcome.action}",
            details={
                "record_type": rt_upper,
                "values_count": len(values),
                "provider": provider,
            },
        )
        return body
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
                "record_type": rt_upper,
                "exception_type": type(exc).__name__,
            },
        )
        raise mapped from exc
