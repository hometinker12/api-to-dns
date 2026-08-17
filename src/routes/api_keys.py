import os
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select
from starlette.status import HTTP_303_SEE_OTHER

from ..activity_logging import (
    emit_activity_event,
)
from ..db import get_db
from ..log_constants import (
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_WARNING,
)
from ..models import (
    API_KEY_ACCESS_MODES,
    API_KEY_ACCESS_READ_ONLY,
    ApiKey,
    ApiKeyAllowedZone,
    DnsZoneConfig,
)
from ..rbac import (
    ROLE_API_KEYS_READ,
    ROLE_API_KEYS_UPDATE,
    require_role,
)
from ..security import api_key_prefix, generate_api_key, hash_api_key
from ..web import (
    render_error_response,
    templates,
)
from ..zone_service import (
    api_key_admin_dict,
    api_key_allowed_zone_names,
    api_key_public_dict,
    dns_zone_public_dict,
    list_dns_zones,
)

_OPENAPI_ON = os.getenv("OPENAPI_ENABLED", "").strip().lower() in {"1", "true", "yes"}

router = APIRouter(tags=["api-keys"], include_in_schema=False)


def _api_keys_html_context(db, *, user: str, message: str | None = None, **extra: Any) -> dict[str, Any]:
    api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda key: key.created_at, reverse=True)
    key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
    all_zones = list_dns_zones(db)
    return {
        "user": user,
        "api_keys": [api_key_admin_dict(db, k) for k in api_keys],
        "key_zones": key_zones,
        "all_zones": [dns_zone_public_dict(z) for z in all_zones],
        "message": message,
        "openapi_enabled": _OPENAPI_ON,
        **extra,
    }


def _api_key_access_mode(access_mode: str | None, *, default: str) -> str:
    selected = default if access_mode is None else access_mode.strip().lower()
    if selected not in API_KEY_ACCESS_MODES:
        raise ValueError("Access mode must be read_only or read_write.")
    return selected


@router.get("/api-keys", response_class=HTMLResponse, include_in_schema=False)
def api_keys_page(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_API_KEYS_READ)),
):
    try:
        ctx = _api_keys_html_context(db, user=user)
        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, **ctx},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@router.post("/api-keys/revoke", response_class=HTMLResponse, include_in_schema=False)
def revoke_api_key(
    request: Request,
    db: Session = Depends(get_db),
    key_id: int = Form(...),
    user: str = Depends(require_role(ROLE_API_KEYS_UPDATE)),
):
    try:
        api_key = db.get(ApiKey, key_id)
        if api_key:
            api_key.active = False
            db.add(api_key)
            db.commit()
            emit_activity_event(
                db,
                event_type="api_key.revoked",
                level=LOG_LEVEL_WARNING,
                status="success",
                actor_type="user",
                actor_label=user,
                message=f"API key {api_key.label!r} revoked",
                details={"api_key_id": api_key.id, "api_key_label": api_key.label},
            )
        ctx = _api_keys_html_context(db, user=user, message="API key revoked.")

        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, **ctx},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@router.post("/api-keys", response_class=HTMLResponse, include_in_schema=False)
def create_api_key_route(
    request: Request,
    db: Session = Depends(get_db),
    label: str = Form(...),
    zone_ids: list[int] = Form(default_factory=list),
    key_id: int | None = Form(None),
    access_mode: str | None = Form(None),
    user: str = Depends(require_role(ROLE_API_KEYS_UPDATE)),
):
    try:
        if key_id is not None:
            row = db.get(ApiKey, key_id)
            if not row:
                return RedirectResponse(url="/api-keys", status_code=HTTP_303_SEE_OTHER)
            try:
                selected_access_mode = _api_key_access_mode(access_mode, default=row.access_mode)
            except ValueError as exc:
                ctx = _api_keys_html_context(
                    db,
                    user=user,
                    edit_key_error_id=key_id,
                    edit_key_error=str(exc),
                    edit_key_label=label,
                    edit_key_access_mode=access_mode,
                    edit_key_selected_zone_ids=zone_ids,
                )
                return templates.TemplateResponse(
                    request=request,
                    name="api_keys.html",
                    context={"request": request, **ctx},
                )
            if not zone_ids:
                ctx = _api_keys_html_context(
                    db,
                    user=user,
                    edit_key_error_id=key_id,
                    edit_key_error="Select at least one DNS zone.",
                    edit_key_label=label,
                    edit_key_access_mode=access_mode,
                    edit_key_selected_zone_ids=zone_ids,
                )
                return templates.TemplateResponse(
                    request=request,
                    name="api_keys.html",
                    context={"request": request, **ctx},
                )
            row.label = label
            row.access_mode = selected_access_mode
            db.add(row)
            for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key_id)).all():
                db.delete(link)
            db.commit()
            for zid in zone_ids:
                if db.get(DnsZoneConfig, zid):
                    db.add(ApiKeyAllowedZone(api_key_id=key_id, dns_zone_config_id=zid))
            db.commit()
            emit_activity_event(
                db,
                event_type="api_key.updated",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="user",
                actor_label=user,
                message=f"API key {label!r} updated",
                details={
                    "api_key_id": key_id,
                    "api_key_label": label,
                    "access_mode": row.access_mode,
                    "allowed_zone_ids": list(zone_ids),
                },
            )
            ctx = _api_keys_html_context(db, user=user, message="API key updated.")
            return templates.TemplateResponse(
                request=request,
                name="api_keys.html",
                context={"request": request, **ctx},
            )
        try:
            selected_access_mode = _api_key_access_mode(access_mode, default=API_KEY_ACCESS_READ_ONLY)
        except ValueError as exc:
            ctx = _api_keys_html_context(
                db,
                user=user,
                create_key_error=str(exc),
                create_key_label=label,
                create_key_access_mode=access_mode,
            )
            return templates.TemplateResponse(
                request=request,
                name="api_keys.html",
                context={"request": request, **ctx},
            )
        if not zone_ids:
            ctx = _api_keys_html_context(
                db,
                user=user,
                create_key_error="Select at least one DNS zone for this API key.",
                create_key_label=label,
                create_key_access_mode=access_mode,
            )
            return templates.TemplateResponse(
                request=request,
                name="api_keys.html",
                context={"request": request, **ctx},
            )
        new_key = generate_api_key()
        api_key = ApiKey(
            label=label,
            key=hash_api_key(new_key),
            key_prefix=api_key_prefix(new_key),
            access_mode=selected_access_mode,
        )
        db.add(api_key)
        db.commit()
        db.refresh(api_key)
        for zid in zone_ids:
            if db.get(DnsZoneConfig, zid):
                db.add(ApiKeyAllowedZone(api_key_id=api_key.id, dns_zone_config_id=zid))
        db.commit()
        emit_activity_event(
            db,
            event_type="api_key.created",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"API key {label!r} created",
            details={
                "api_key_id": api_key.id,
                "api_key_label": api_key.label,
                "access_mode": api_key.access_mode,
                "allowed_zone_ids": list(zone_ids),
                "key_prefix": api_key.key_prefix,
            },
        )
        ctx = _api_keys_html_context(
            db,
            user=user,
            message=f"API key created: {new_key} (copy now; it will not be shown again)",
            created_api_key=new_key,
        )

        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, **ctx},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@router.get("/api-keys/{key_id}/edit", response_class=HTMLResponse, include_in_schema=False)
def api_key_edit_form(
    request: Request,
    key_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_API_KEYS_UPDATE)),
):
    row = db.get(ApiKey, key_id)
    if not row:
        return RedirectResponse(url="/api-keys", status_code=HTTP_303_SEE_OTHER)
    all_zones = list_dns_zones(db)
    allowed_ids = {
        link.dns_zone_config_id
        for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key_id)).all()
    }
    api_key_row = api_key_public_dict(row)
    all_zones_view = [dns_zone_public_dict(z) for z in all_zones]
    return templates.TemplateResponse(
        request=request,
        name="api_key_edit.html",
        context={
            "request": request,
            "user": user,
            "api_key_row": api_key_row,
            "all_zones": all_zones_view,
            "allowed_ids": allowed_ids,
            "message": None,
        },
    )


@router.post("/api-keys/{key_id}", response_class=HTMLResponse, include_in_schema=False)
def api_key_update(
    request: Request,
    key_id: int,
    db: Session = Depends(get_db),
    label: str = Form(...),
    zone_ids: list[int] = Form(default_factory=list),
    access_mode: str | None = Form(None),
    user: str = Depends(require_role(ROLE_API_KEYS_UPDATE)),
):
    row = db.get(ApiKey, key_id)
    if not row:
        return RedirectResponse(url="/api-keys", status_code=HTTP_303_SEE_OTHER)
    try:
        selected_access_mode = _api_key_access_mode(access_mode, default=row.access_mode)
    except ValueError as exc:
        all_zones = list_dns_zones(db)
        allowed_ids = {
            link.dns_zone_config_id
            for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key_id)).all()
        }
        return templates.TemplateResponse(
            request=request,
            name="api_key_edit.html",
            context={
                "request": request,
                "user": user,
                "api_key_row": api_key_public_dict(row),
                "all_zones": [dns_zone_public_dict(z) for z in all_zones],
                "allowed_ids": allowed_ids,
                "message": str(exc),
            },
        )
    if not zone_ids:
        all_zones = list_dns_zones(db)
        allowed_ids = {
            link.dns_zone_config_id
            for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key_id)).all()
        }
        return templates.TemplateResponse(
            request=request,
            name="api_key_edit.html",
            context={
                "request": request,
                "user": user,
                "api_key_row": api_key_public_dict(row),
                "all_zones": [dns_zone_public_dict(z) for z in all_zones],
                "allowed_ids": allowed_ids,
                "message": "Select at least one DNS zone.",
            },
        )
    row.label = label
    row.access_mode = selected_access_mode
    db.add(row)
    for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key_id)).all():
        db.delete(link)
    db.commit()
    for zid in zone_ids:
        if db.get(DnsZoneConfig, zid):
            db.add(ApiKeyAllowedZone(api_key_id=key_id, dns_zone_config_id=zid))
    db.commit()
    emit_activity_event(
        db,
        event_type="api_key.updated",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"API key {label!r} updated",
        details={
            "api_key_id": key_id,
            "api_key_label": label,
            "access_mode": row.access_mode,
            "allowed_zone_ids": list(zone_ids),
        },
    )
    all_zones = list_dns_zones(db)
    allowed_ids = {
        link.dns_zone_config_id
        for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key_id)).all()
    }
    fresh = db.get(ApiKey, key_id)
    if not fresh:
        return RedirectResponse(url="/api-keys", status_code=HTTP_303_SEE_OTHER)
    api_key_row = api_key_public_dict(fresh)
    all_zones_view = [dns_zone_public_dict(z) for z in all_zones]
    return templates.TemplateResponse(
        request=request,
        name="api_key_edit.html",
        context={
            "request": request,
            "user": user,
            "api_key_row": api_key_row,
            "all_zones": all_zones_view,
            "allowed_ids": allowed_ids,
            "message": "API key updated.",
        },
    )
