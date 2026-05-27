import html
import traceback
from typing import Any, Optional

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .activity_logging import LOGGER, emit_activity_event
from .db import SessionLocal
from .paths import TEMPLATES_DIR
from .rbac import ROLE_FORBIDDEN_DETAIL, ROLE_SYSTEM_UPDATE, get_user_roles
from .restart import is_restart_required, preview_restart_urls, restart_reason

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def client_ip(request: Request) -> Optional[str]:
    client = getattr(request, "client", None)
    return client.host if client else None


def record_activity(**kwargs: Any) -> None:
    try:
        with SessionLocal() as db:
            emit_activity_event(db, **kwargs)
    except Exception:  # pragma: no cover
        LOGGER.exception("emit_activity_event failed for event %s", kwargs.get("event_type"))


def render_access_denied_response() -> HTMLResponse:
    return HTMLResponse(
        content=(
            "<!DOCTYPE html><html><head><title>Access denied</title>"
            "<link rel=\"stylesheet\" href=\"/static/style.css\" /></head>"
            "<body><div class=\"page\">"
            "<h1>Access denied</h1>"
            f"<div class=\"alert error\">{html.escape(ROLE_FORBIDDEN_DETAIL)}</div>"
            "<p><a class=\"button\" href=\"/admin\">Back to dashboard</a></p>"
            "</div></body></html>"
        ),
        status_code=403,
    )


def nav_context(db, user: str, *, show_dashboard_link: bool = True) -> dict:
    roles = get_user_roles(db, user)
    can_system_update = ROLE_SYSTEM_UPDATE in roles
    restart_pending = is_restart_required(db)
    return {
        "show_dashboard_link": show_dashboard_link,
        "can_system_update": can_system_update,
        "restart_required": restart_pending,
        "restart_reason": restart_reason(db) if restart_pending else "",
        "restart_preview": preview_restart_urls(db) if restart_pending else {},
    }


def _page_nav(user: str, show_dashboard_link: bool = True) -> dict:
    with SessionLocal() as db:
        return nav_context(db, user, show_dashboard_link=show_dashboard_link)


templates.env.globals["page_nav"] = _page_nav


def render_error_response(request: Request, error: Exception, status_code: int = 500):
    traceback_text = traceback.format_exc()
    LOGGER.exception("Application error: %s", error)
    content = (
        "<html><body><h1>Application error</h1>"
        f"<p>{html.escape(str(error))}</p>"
        "<pre>"
        f"{html.escape(traceback_text)}"
        "</pre></body></html>"
    )
    return HTMLResponse(content=content, status_code=status_code)
