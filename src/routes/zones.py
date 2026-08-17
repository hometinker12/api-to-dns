from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select
from starlette.status import HTTP_303_SEE_OTHER

from .. import letsencrypt, zone_service
from ..activity_logging import (
    emit_activity_event,
)
from ..auth import (
    get_current_user,
    get_current_user_db,
)
from ..db import get_db
from ..dns_api_service import ACCESS_DENIED_DETAIL
from ..http_utils import (
    api_key_fingerprint,
    api_key_from_headers,
    http_exception_from_dns_error,
    wants_json_response,
)
from ..log_constants import (
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_WARNING,
)
from ..models import (
    ApiKeyAllowedZone,
    DnsZoneConfig,
    DnsZoneSummary,
)
from ..plugins.utils import normalize_lookup_record_type
from ..rbac import (
    ROLE_DNS_ZONES_READ,
    ROLE_DNS_ZONES_UPDATE,
    require_role,
    user_has_role,
)
from ..web import (
    record_activity,
    render_error_response,
    templates,
)
from ..zone_service import (
    build_zone_config_from_form,
    decode_zone_config,
    dns_zone_admin_dict,
    dns_zone_public_dict,
    dns_zone_summary_dict,
    enabled_dns_provider_options,
    encode_zone_config_dict,
    get_api_key,
    list_dns_zones,
    normalize_zone_name,
)

router = APIRouter(tags=["zones"])


def _zones_html_context(db, *, message: str | None = None, user: str | None = None) -> dict[str, Any]:
    can_view_zones = user is not None and (
        user_has_role(db, user, ROLE_DNS_ZONES_READ) or user_has_role(db, user, ROLE_DNS_ZONES_UPDATE)
    )
    ctx: dict[str, Any] = {
        "zones": [dns_zone_admin_dict(db, z) for z in list_dns_zones(db)] if can_view_zones else [],
        "message": message,
        "can_view_zones": can_view_zones,
        "can_update_zones": user is not None and user_has_role(db, user, ROLE_DNS_ZONES_UPDATE),
    }
    if user is not None:
        ctx["user"] = user
    return ctx


@router.get("/", response_class=RedirectResponse, include_in_schema=False)
def root(request: Request) -> RedirectResponse:
    try:
        get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/admin")


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
def admin(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user_db),
):
    try:
        ctx = _zones_html_context(db, user=user)
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={"request": request, **ctx},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@router.get(
    "/zones",
    response_model=list[DnsZoneSummary],
    responses={
        200: {
            "description": "JSON zone summaries when requested with application/json.",
        },
        303: {"description": "Authenticated browser requests redirect to the dashboard."},
    },
)
def zones_page(
    request: Request,
    db: Session = Depends(get_db),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
):
    if wants_json_response(request):
        api_key = api_key_from_headers(x_api_key, authorization)
        if not api_key:
            record_activity(
                event_type="dns.access_denied",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_label="missing",
                message="API key missing on GET /zones",
            )
            raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)
        key = get_api_key(db, api_key)
        if key is None:
            emit_activity_event(
                db,
                event_type="dns.access_denied",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_label="invalid",
                message="Invalid or revoked API key used on GET /zones",
                details={"key_fingerprint": api_key_fingerprint(api_key)},
            )
            raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)
        zone_ids = [
            link.dns_zone_config_id
            for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key.id)).all()
        ]
        zones = [zone for zone_id in zone_ids if (zone := db.get(DnsZoneConfig, zone_id)) is not None]
        actor_id = str(key.id) if key.id is not None else None
        emit_activity_event(
            db,
            event_type="dns.zones_list",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=key.label,
            message=f"Listed {len(zones)} allowed DNS zone(s)",
            details={"zone_count": len(zones)},
        )
        return [DnsZoneSummary(**dns_zone_summary_dict(z)) for z in zones]

    get_current_user(request)
    return RedirectResponse(url="/admin", status_code=HTTP_303_SEE_OTHER)


@router.get("/zones/new", response_class=HTMLResponse, include_in_schema=False)
def zone_new_form(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    provider_plugins = enabled_dns_provider_options(db)
    return templates.TemplateResponse(
        request=request,
        name="zone_form.html",
        context={
            "request": request,
            "user": user,
            "zone": None,
            "settings": {},
            "provider_plugins": provider_plugins,
            "message": None
            if provider_plugins
            else "No DNS provider plugins are enabled. Enable a plugin in Settings first.",
            "title": "Add DNS zone",
        },
    )


@router.post("/zones", response_class=HTMLResponse, include_in_schema=False)
async def zone_create(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    form = await request.form()
    zone_name = str(form.get("zone_name") or "")
    canonical = normalize_zone_name(zone_name)
    if not canonical:
        ctx = _zones_html_context(db, message="Zone name is required.", user=user)
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={"request": request, **ctx},
        )
    provider_plugins = enabled_dns_provider_options(db)
    if db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == canonical)).first():
        ctx = _zones_html_context(db, message=f"A zone named {canonical!r} already exists.", user=user)
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={"request": request, **ctx},
        )
    try:
        cfg = build_zone_config_from_form(form, provider_plugins=provider_plugins)
    except ValueError as exc:
        return templates.TemplateResponse(
            request=request,
            name="zone_form.html",
            context={
                "request": request,
                "user": user,
                "zone": None,
                "settings": {"dns_provider_type": (form.get("dns_provider_type") or "").strip().lower()},
                "provider_plugins": provider_plugins,
                "message": str(exc),
                "title": "Add DNS zone",
            },
        )
    row = DnsZoneConfig(zone_name=canonical, encrypted_config=encode_zone_config_dict(cfg))
    db.add(row)
    db.commit()
    emit_activity_event(
        db,
        event_type="dns_zone.created",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        zone_name=canonical,
        message=f"Zone {canonical!r} added",
        details={"dns_provider_type": cfg.get("dns_provider_type")},
    )
    ctx = _zones_html_context(db, message=f"Zone {canonical!r} added.", user=user)
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"request": request, **ctx},
    )


@router.post("/zones/test", include_in_schema=False)
async def zone_test(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    form = await request.form()
    zone_name_raw = str(form.get("zone_name") or "")
    test_record_name = str(form.get("test_record_name") or "").strip()
    test_record_type_raw = str(form.get("test_record_type") or "").strip()
    zone_id_raw = form.get("zone_id")

    existing: dict[str, Any] | None = None
    canonical = normalize_zone_name(zone_name_raw)

    provider_plugins = enabled_dns_provider_options(db)
    if zone_id_raw:
        try:
            zone_id = int(zone_id_raw)
        except (TypeError, ValueError):
            zone_id = None
        if zone_id is not None:
            row = db.get(DnsZoneConfig, zone_id)
            if row:
                existing = decode_zone_config(row)
                if not canonical:
                    canonical = row.zone_name

    if not canonical:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "Zone name is required.",
                "records": [],
            },
        )
    if not test_record_name:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "Test record name is required.",
                "records": [],
            },
        )

    try:
        test_record_type = normalize_lookup_record_type(test_record_type_raw or None)
        cfg = build_zone_config_from_form(form, existing=existing, provider_plugins=provider_plugins)
        records = zone_service.test_zone_record_lookup(
            cfg,
            record_name=test_record_name,
            record_type=test_record_type,
            db=db,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": str(exc),
                "records": [],
            },
        )
    except Exception as exc:
        mapped = http_exception_from_dns_error(exc)
        detail = mapped.detail if isinstance(mapped.detail, dict) else {"message": str(mapped.detail)}
        emit_activity_event(
            db,
            event_type="dns_zone.test",
            level=LOG_LEVEL_ERROR,
            status="error",
            actor_type="user",
            actor_label=user,
            zone_name=canonical,
            record_name=test_record_name,
            message=str(detail.get("message", "DNS test failed")),
            details={
                "dns_provider_type": (cfg.get("dns_provider_type") if "cfg" in locals() else None),
                "test_record_type": test_record_type_raw or None,
            },
        )
        return JSONResponse(
            status_code=mapped.status_code,
            content={
                "status": "error",
                "message": detail.get("message", "DNS test failed"),
                "records": [],
            },
        )

    record_payload = [record.model_dump() for record in records]
    if records:
        message = f"Found {len(records)} record(s) at {test_record_name!r} in zone {canonical!r}."
        status = "success"
        event_level = LOG_LEVEL_INFORMATIONAL
        event_status = "success"
    else:
        if test_record_type:
            message = (
                f"Authentication successful. No {test_record_type} record found "
                f"for {test_record_name!r} in zone {canonical!r}."
            )
        else:
            message = f"Authentication successful. No records found at {test_record_name!r} in zone {canonical!r}."
        status = "not_found"
        event_level = LOG_LEVEL_INFORMATIONAL
        event_status = "not_found"

    emit_activity_event(
        db,
        event_type="dns_zone.test",
        level=event_level,
        status=event_status,
        actor_type="user",
        actor_label=user,
        zone_name=canonical,
        record_name=test_record_name,
        message=message,
        details={
            "dns_provider_type": cfg.get("dns_provider_type"),
            "test_record_type": test_record_type_raw or None,
            "records_found": len(records),
        },
    )

    return JSONResponse(
        content={
            "status": status,
            "message": message,
            "records": record_payload,
        },
    )


@router.get("/zones/{zone_id}/edit", response_class=HTMLResponse, include_in_schema=False)
def zone_edit_form(
    request: Request,
    zone_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    row = db.get(DnsZoneConfig, zone_id)
    if not row:
        return RedirectResponse(url="/admin", status_code=HTTP_303_SEE_OTHER)
    settings = decode_zone_config(row)
    zone_view = dns_zone_public_dict(row)
    provider_plugins = enabled_dns_provider_options(db)
    title_zone = row.zone_name
    return templates.TemplateResponse(
        request=request,
        name="zone_form.html",
        context={
            "request": request,
            "user": user,
            "zone": zone_view,
            "settings": settings,
            "provider_plugins": provider_plugins,
            "message": None,
            "title": f"Edit zone {title_zone}",
        },
    )


@router.post("/zones/{zone_id}", response_class=HTMLResponse, include_in_schema=False)
async def zone_update(
    request: Request,
    zone_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    form = await request.form()
    row = db.get(DnsZoneConfig, zone_id)
    if not row:
        return RedirectResponse(url="/admin", status_code=HTTP_303_SEE_OTHER)
    existing = decode_zone_config(row)
    provider_plugins = enabled_dns_provider_options(db)
    try:
        cfg = build_zone_config_from_form(form, existing=existing, provider_plugins=provider_plugins)
    except ValueError as exc:
        return templates.TemplateResponse(
            request=request,
            name="zone_form.html",
            context={
                "request": request,
                "user": user,
                "zone": dns_zone_public_dict(row),
                "settings": existing,
                "provider_plugins": provider_plugins,
                "message": str(exc),
                "title": f"Edit zone {row.zone_name}",
            },
        )
    row.encrypted_config = encode_zone_config_dict(cfg)
    db.add(row)
    db.commit()
    db.refresh(row)
    settings = decode_zone_config(row)
    zone_view = dns_zone_public_dict(row)
    title_zone = row.zone_name
    emit_activity_event(
        db,
        event_type="dns_zone.updated",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        zone_name=row.zone_name,
        message=f"Zone {row.zone_name!r} updated",
        details={"dns_provider_type": cfg.get("dns_provider_type")},
    )
    return templates.TemplateResponse(
        request=request,
        name="zone_form.html",
        context={
            "request": request,
            "user": user,
            "zone": zone_view,
            "settings": settings,
            "provider_plugins": provider_plugins,
            "message": "Zone saved.",
            "title": f"Edit zone {title_zone}",
        },
    )


@router.post("/zones/{zone_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def zone_delete(
    request: Request,
    zone_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    row = db.get(DnsZoneConfig, zone_id)
    removed_zone_name = None
    if row:
        removed_zone_name = row.zone_name
        letsencrypt.detach_dns_zone_from_letsencrypt(db, zone_id)
        for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.dns_zone_config_id == zone_id)).all():
            db.delete(link)
        db.delete(row)
        db.commit()
    if removed_zone_name:
        emit_activity_event(
            db,
            event_type="dns_zone.deleted",
            level=LOG_LEVEL_WARNING,
            status="success",
            actor_type="user",
            actor_label=user,
            zone_name=removed_zone_name,
            message=f"Zone {removed_zone_name!r} deleted",
        )
    ctx = _zones_html_context(db, message="Zone removed.", user=user)
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"request": request, **ctx},
    )
