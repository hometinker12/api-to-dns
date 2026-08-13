from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ..auth import (
    get_current_user,
)
from ..rbac import (
    LEGACY_SETTINGS_AREA_ALIASES,
)
from ..settings_context import render_settings

router = APIRouter(tags=["settings"], include_in_schema=False)


@router.get("/settings", response_class=HTMLResponse, include_in_schema=False)
def settings_page(
    request: Request,
    area: str | None = None,
    section: str | None = None,
    event_type: str | None = None,
    level: str | None = None,
    category: str | None = None,
    log_status: str | None = None,
    zone_name: str | None = None,
    actor: str | None = None,
    text_query: str | None = None,
    start: str | None = None,
    end: str | None = None,
    offset: int = 0,
    user: str = Depends(get_current_user),
):
    normalized_area = (area or "").strip().lower()
    if normalized_area in LEGACY_SETTINGS_AREA_ALIASES:
        normalized_area = LEGACY_SETTINGS_AREA_ALIASES[normalized_area]
    log_search_params: dict[str, Any] | None = None
    if normalized_area == "log_viewing":
        log_search_params = {
            "event_type": (event_type or "").strip() or None,
            "level": (level or "").strip() or None,
            "category": (category or "").strip() or None,
            "status": (log_status or "").strip() or None,
            "zone_name": (zone_name or "").strip() or None,
            "actor": (actor or "").strip() or None,
            "text_query": (text_query or "").strip() or None,
            "start": _parse_iso_datetime(start),
            "end": _parse_iso_datetime(end),
            "offset": offset,
        }
    return render_settings(request, user, normalized_area, log_search_params=log_search_params, section=section)


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
