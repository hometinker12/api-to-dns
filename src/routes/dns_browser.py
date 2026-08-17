from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import Session

from ..db import get_db
from ..dns_browser_service import (
    AdminRecordDelete,
    AdminRecordMutation,
    browser_page_context,
    lookup_admin_records,
    mutate_admin_record,
)
from ..http_utils import http_exception_from_dns_error, sanitize_client_error_message
from ..rbac import ROLE_DNS_ZONES_UPDATE, require_role
from ..web import templates

router = APIRouter(tags=["dns-browser"])


@router.get("/zones/{zone_id}/records", response_class=HTMLResponse, include_in_schema=False)
def dns_browser_page(
    request: Request,
    zone_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    # Live DNS browse/search returns provider record data; require update role (not mandatory read).
    ctx = browser_page_context(db, zone_id, user=user, can_update=True)
    return templates.TemplateResponse(
        request=request,
        name="dns_browser.html",
        context={"request": request, **ctx},
    )


@router.get("/zones/{zone_id}/records/search", include_in_schema=False)
def search_records(
    zone_id: int,
    db: Session = Depends(get_db),
    record_name: str | None = Query(None),
    record_type: str | None = Query(None),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    try:
        return lookup_admin_records(
            db,
            zone_id,
            record_name=record_name,
            record_type=record_type,
            actor=user,
        )
    except Exception as exc:
        mapped = http_exception_from_dns_error(exc)
        if isinstance(mapped.detail, dict):
            return JSONResponse(
                status_code=mapped.status_code,
                content={
                    "status": "error",
                    "message": mapped.detail.get("message")
                    or sanitize_client_error_message(exc, fallback="DNS lookup failed"),
                },
            )
        raise mapped from exc


@router.post("/zones/{zone_id}/records", include_in_schema=False)
def create_record(
    zone_id: int,
    payload: AdminRecordMutation,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    return mutate_admin_record(
        db,
        zone_id,
        mode="create",
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=payload.ttl,
        values=payload.values,
        actor=user,
    )


@router.put("/zones/{zone_id}/records", include_in_schema=False)
def replace_record(
    zone_id: int,
    payload: AdminRecordMutation,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    return mutate_admin_record(
        db,
        zone_id,
        mode="replace",
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=payload.ttl,
        values=payload.values,
        actor=user,
    )


@router.delete("/zones/{zone_id}/records", include_in_schema=False)
def delete_record(
    zone_id: int,
    payload: AdminRecordDelete,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE)),
):
    return mutate_admin_record(
        db,
        zone_id,
        mode="delete",
        record_name=payload.record_name,
        record_type=payload.record_type,
        actor=user,
    )
