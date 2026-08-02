"""DNS public API helpers shared by route handlers and tests."""

from typing import Any, Literal

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import select
from starlette.status import HTTP_404_NOT_FOUND, HTTP_409_CONFLICT

from .activity_logging import emit_activity_event
from .db import SessionLocal
from .http_utils import api_key_fingerprint, http_exception_from_dns_error, sanitize_client_error_message
from .models import (
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_WARNING,
    ApiKey,
    ApiKeyAllowedZone,
    DnsRecordRequest,
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
    403: {"description": "API key is not allowed to use this zone, or the zone is not configured."},
    502: {"description": "DNS provider reported a failure (e.g. WinRM or dynamic update)."},
    503: {"description": "A required component is not installed or misconfigured."},
}


def _get_dns_client_from_settings(settings: dict[str, Any]):
    """Resolve DNS client factory via ``app`` so tests can monkeypatch ``src.app.get_dns_client_from_settings``."""
    from . import app as app_module

    return app_module.get_dns_client_from_settings(settings)


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


def _record_exists_at_type(
    client,
    *,
    settings: dict[str, Any],
    record_name: str,
    record_type: str,
) -> bool:
    """Return True if the DNS provider reports any record of *record_type* at *record_name*."""

    records = client.get_record(
        record_name=record_name,
        record_type=record_type,
        dns_server=settings.get("dns_server"),
        dns_zone=provider_dns_zone(settings),
    )
    return bool(records)


def _apply_dns_mutation(
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

    with SessionLocal() as db:
        _key, zone_row, settings, actor_id, actor_label, provider = _resolve_dns_api_zone(
            db,
            api_key=api_key,
            zone_name=zone_name or "",
            record_name=record_name,
            endpoint=endpoint,
        )

        try:
            if provider in get_disabled_dns_plugins(db):
                raise DnsProviderDisabledError(
                    f"{dns_provider_display_name(provider)} is disabled. "
                    "Enable it in Settings before using it for DNS operations."
                )
            client = _get_dns_client_from_settings(settings)
            provider_domain = provider_dns_zone(settings)

            if mode == "patch":
                records = client.get_record(
                    record_name=record_name,
                    record_type=rt_upper,
                    dns_server=settings.get("dns_server"),
                    dns_zone=provider_domain,
                )
                if not records:
                    body = DnsRecordResponse(
                        status="error",
                        action="not_found",
                        zone_name=zone_row.zone_name,
                        dns_zone=provider_domain,
                        record_name=record_name,
                        record_type=rt_upper,
                        values=list(patch_values or []),
                    )
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

                existing = records[0]
                if existing.ttl is None or not existing.values:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "error": "dns_provider_failed",
                            "message": "Could not read existing TTL and values for PATCH merge.",
                        },
                    )
                final_ttl = patch_ttl if patch_ttl is not None else existing.ttl
                final_values = list(patch_values) if patch_values is not None else list(existing.values)
                internal = DnsRecordRequest(
                    zone_name=zone_row.zone_name,
                    record_type=rt_upper,
                    record_name=record_name,
                    ttl=final_ttl,
                    values=final_values,
                )
                client.create_or_update_record(
                    internal,
                    dns_server=settings.get("dns_server"),
                    dns_zone=provider_domain,
                )
                body = DnsRecordResponse(
                    status="success",
                    action="updated",
                    zone_name=zone_row.zone_name,
                    dns_zone=provider_domain,
                    record_name=record_name,
                    record_type=rt_upper,
                    values=final_values,
                )
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
                        "record_type": rt_upper,
                        "values_count": len(final_values),
                        "provider": provider,
                    },
                )
                return body

            exists = _record_exists_at_type(
                client,
                settings=settings,
                record_name=record_name,
                record_type=rt_upper,
            )

            if mode == "create" and exists:
                body = DnsRecordResponse(
                    status="error",
                    action="record_already_exists",
                    zone_name=zone_row.zone_name,
                    dns_zone=provider_domain,
                    record_name=record_name,
                    record_type=rt_upper,
                    values=list(values),
                )
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

            if mode in ("replace", "delete") and not exists:
                body = DnsRecordResponse(
                    status="error",
                    action="not_found",
                    zone_name=zone_row.zone_name,
                    dns_zone=provider_domain,
                    record_name=record_name,
                    record_type=rt_upper,
                    values=[] if mode == "delete" else list(values),
                )
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

            if mode == "delete":
                internal = DnsRecordRequest(
                    zone_name=zone_row.zone_name,
                    record_type="DELETE",
                    record_name=record_name,
                    ttl=ttl or 300,
                    values=[rt_upper],
                )
            else:
                internal = DnsRecordRequest(
                    zone_name=zone_row.zone_name,
                    record_type=rt_upper,
                    record_name=record_name,
                    ttl=ttl if ttl is not None else 300,
                    values=list(values),
                )

            client.create_or_update_record(
                internal,
                dns_server=settings.get("dns_server"),
                dns_zone=provider_domain,
            )

            action = {
                "create": "created",
                "replace": "updated",
                "patch": "updated",
                "delete": "deleted",
            }[mode]
            response_values: list[str] = [] if mode == "delete" else list(values)
            body = DnsRecordResponse(
                status="success",
                action=action,
                zone_name=zone_row.zone_name,
                dns_zone=provider_domain,
                record_name=record_name,
                record_type=rt_upper,
                values=response_values,
            )
            emit_activity_event(
                db,
                event_type=f"dns.record_{action}",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=f"DNS record {record_name}.{provider_domain} {action}",
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
