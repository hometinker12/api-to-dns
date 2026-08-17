"""Session-authenticated DNS browser helpers (admin UI)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from .activity_logging import emit_activity_event
from .db import SessionLocal
from .dns_mutation import apply_rrset_mutation, prepare_mutation
from .dns_record_types import (
    normalize_lookup_record_type,
    normalize_mutable_record_type,
    normalize_record_values,
    record_type_options,
    validate_ttl,
)
from .http_utils import http_exception_from_dns_error, sanitize_client_error_message
from .models import (
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_WARNING,
    DnsRecordInfo,
    DnsZoneConfig,
)
from .plugins.utils import has_dns_glob
from .zone_service import (
    create_dns_client_from_settings,
    decode_zone_config,
    dns_provider_display_name,
    dns_zone_public_dict,
    provider_dns_zone,
)

DNS_BROWSER_RECORD_LIMIT = 100


class AdminRecordMutation(BaseModel):
    record_name: str = Field(..., min_length=1)
    record_type: str
    ttl: int | None = 300
    values: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self):
        self.record_type = normalize_mutable_record_type(self.record_type)
        self.record_name = self.record_name.strip()
        if not self.record_name:
            raise ValueError("record_name is required.")
        self.ttl = validate_ttl(self.ttl)
        self.values = normalize_record_values(self.record_type, list(self.values))
        return self


class AdminRecordDelete(BaseModel):
    record_name: str = Field(..., min_length=1)
    record_type: str

    @model_validator(mode="after")
    def _validate(self):
        self.record_type = normalize_mutable_record_type(self.record_type)
        self.record_name = self.record_name.strip()
        if not self.record_name:
            raise ValueError("record_name is required.")
        return self


@dataclass(frozen=True)
class AdminZoneContext:
    row: DnsZoneConfig
    settings: dict[str, Any]
    client: Any


def resolve_admin_zone(db, zone_id: int) -> AdminZoneContext:
    row = db.get(DnsZoneConfig, zone_id)
    if row is None:
        raise HTTPException(status_code=404, detail="DNS zone not found")
    settings = decode_zone_config(row)
    client = create_dns_client_from_settings(settings, db=db)
    return AdminZoneContext(row=row, settings=settings, client=client)


def browser_page_context(db, zone_id: int, *, user: str, can_update: bool) -> dict[str, Any]:
    row = db.get(DnsZoneConfig, zone_id)
    if row is None:
        raise HTTPException(status_code=404, detail="DNS zone not found")
    zone_view = dns_zone_public_dict(row)
    settings = decode_zone_config(row)
    provider = (settings.get("dns_provider_type") or "azure").strip().lower()
    cloudflare_proxy_enabled = provider == "cloudflare" and str(
        settings.get("cloudflare_proxied") or ""
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return {
        "user": user,
        "zone": zone_view,
        "zone_id": zone_id,
        "can_update_records": can_update,
        "record_type_options": record_type_options(),
        "page_title": "DNS Browser",
        "page_subtitle": zone_view["zone_name"],
        "cloudflare_proxy_enabled": cloudflare_proxy_enabled,
    }


def lookup_admin_records(
    zone_id: int,
    *,
    record_name: str | None,
    record_type: str | None,
    actor: str,
) -> dict[str, Any]:
    name = (record_name or "").strip()
    try:
        lookup_type = normalize_lookup_record_type(record_type)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": str(exc)},
        ) from exc

    with SessionLocal() as db:
        ctx = resolve_admin_zone(db, zone_id)
        provider = (ctx.settings.get("dns_provider_type") or "azure").strip().lower()
        dns_zone = provider_dns_zone(ctx.settings)
        match_mode = "browse" if not name else ("glob" if has_dns_glob(name) else "exact")
        try:
            truncated = False
            if match_mode == "exact":
                records: list[DnsRecordInfo] = ctx.client.get_record(
                    record_name=name,
                    record_type=lookup_type,
                    dns_server=ctx.settings.get("dns_server"),
                    dns_zone=dns_zone,
                )
            else:
                result = ctx.client.list_records(
                    name_pattern=name or None,
                    record_type=lookup_type,
                    limit=DNS_BROWSER_RECORD_LIMIT,
                    dns_server=ctx.settings.get("dns_server"),
                    dns_zone=dns_zone,
                )
                records = result.records
                truncated = result.truncated
        except Exception as exc:
            sanitized = sanitize_client_error_message(exc, fallback="DNS provider error")
            emit_activity_event(
                db,
                event_type="dns.browser_lookup_failed",
                level=LOG_LEVEL_ERROR,
                status="error",
                actor_type="user",
                actor_label=actor,
                zone_name=ctx.row.zone_name,
                record_name=name,
                message=sanitized,
                details={
                    "provider": provider,
                    "record_type": lookup_type,
                    "dns_zone": dns_zone,
                    "match_mode": match_mode,
                    "exception_type": type(exc).__name__,
                },
            )
            raise http_exception_from_dns_error(exc) from exc

        status = "success" if records else "not_found"
        emit_activity_event(
            db,
            event_type="dns.browser_lookup",
            level=LOG_LEVEL_INFORMATIONAL,
            status=status,
            actor_type="user",
            actor_label=actor,
            zone_name=ctx.row.zone_name,
            record_name=name,
            message=f"DNS browser {match_mode} lookup for {name or '*'} in {ctx.row.zone_name}",
            details={
                "provider": provider,
                "dns_zone": dns_zone,
                "record_type": lookup_type,
                "record_count": len(records),
                "match_mode": match_mode,
                "truncated": truncated,
            },
        )
        if records:
            message = None
        elif match_mode == "browse":
            message = "No records found in this zone."
        else:
            message = "No matching records found."
        return {
            "status": status,
            "zone_name": ctx.row.zone_name,
            "dns_zone": dns_zone,
            "record_name": name,
            "record_type": lookup_type,
            "records": [r.model_dump() for r in records],
            "truncated": truncated,
            "match_mode": match_mode,
            "message": message,
        }


def mutate_admin_record(
    zone_id: int,
    *,
    mode: Literal["create", "replace", "delete"],
    record_name: str,
    record_type: str,
    ttl: int | None = None,
    values: list[str] | None = None,
    actor: str,
):
    with SessionLocal() as db:
        row = db.get(DnsZoneConfig, zone_id)
        if row is None:
            raise HTTPException(status_code=404, detail="DNS zone not found")
        settings = decode_zone_config(row)
        provider = (settings.get("dns_provider_type") or "azure").strip().lower()
        dns_zone = provider_dns_zone(settings)
        try:
            prepared = prepare_mutation(
                record_name=record_name,
                record_type=record_type,
                ttl=ttl,
                values=list(values or []),
                dns_zone=dns_zone,
                require_values=mode != "delete",
            )
            client = create_dns_client_from_settings(settings, db=db)
            outcome = apply_rrset_mutation(
                client,
                settings=settings,
                zone_name=row.zone_name,
                record_name=prepared.record_name,
                record_type=prepared.record_type,
                ttl=prepared.ttl,
                values=list(prepared.values),
                mode=mode,
            )
        except HTTPException:
            raise
        except ValueError as exc:
            emit_activity_event(
                db,
                event_type="dns.browser_invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="user",
                actor_label=actor,
                zone_name=row.zone_name,
                record_name=record_name,
                message=str(exc),
                details={"provider": provider, "record_type": record_type, "mode": mode},
            )
            raise HTTPException(
                status_code=400,
                detail={"status": "error", "message": str(exc)},
            ) from exc
        except Exception as exc:
            sanitized = sanitize_client_error_message(exc, fallback="DNS provider error")
            emit_activity_event(
                db,
                event_type="dns.browser_provider_failed",
                level=LOG_LEVEL_ERROR,
                status="error",
                actor_type="user",
                actor_label=actor,
                zone_name=row.zone_name,
                record_name=record_name,
                message=sanitized,
                details={
                    "provider": provider,
                    "record_type": record_type,
                    "mode": mode,
                    "exception_type": type(exc).__name__,
                },
            )
            raise http_exception_from_dns_error(exc) from exc

        body = {
            "status": outcome.status,
            "action": outcome.action,
            "zone_name": row.zone_name,
            "dns_zone": outcome.dns_zone,
            "record_name": outcome.record_name,
            "record_type": outcome.record_type,
            "values": outcome.values,
            "message": None
            if outcome.status == "success"
            else ("Record already exists." if outcome.action == "record_already_exists" else "Record not found."),
        }
        event_suffix = {
            "created": "created",
            "updated": "updated",
            "deleted": "deleted",
            "record_already_exists": "already_exists",
            "not_found": "not_found",
        }.get(outcome.action, outcome.action)
        emit_activity_event(
            db,
            event_type=f"dns.browser_record_{event_suffix}",
            level=LOG_LEVEL_INFORMATIONAL if outcome.status == "success" else LOG_LEVEL_WARNING,
            status=outcome.status,
            actor_type="user",
            actor_label=actor,
            zone_name=row.zone_name,
            record_name=outcome.record_name,
            message=(f"DNS browser {outcome.action} {outcome.record_name}/{outcome.record_type} in {row.zone_name}"),
            details={
                "provider": provider,
                "dns_zone": dns_zone,
                "record_type": outcome.record_type,
                "provider_label": dns_provider_display_name(provider),
                "values_count": len(outcome.values),
            },
        )
        if outcome.http_status != 200:
            return JSONResponse(status_code=outcome.http_status, content=body)
        return body
