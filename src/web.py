import html
import traceback
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .activity_logging import LOGGER, emit_activity_event
from .db import SessionLocal
from .paths import TEMPLATES_DIR
from .rbac import ROLE_FORBIDDEN_DETAIL, ROLE_SYSTEM_UPDATE, get_user_roles
from .restart import is_restart_required, preview_restart_urls, restart_reason

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def client_ip(request: Request) -> str | None:
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
            "<script>(function(){var k='api-to-dns-theme';var s=localStorage.getItem(k);"
            "var t=(s==='light'||s==='dark')?s:(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');"
            "document.documentElement.setAttribute('data-theme',t);})();</script>"
            '<link rel="stylesheet" href="/static/style.css" /></head>'
            '<body><div class="page">'
            "<h1>Access denied</h1>"
            f'<div class="alert error">{html.escape(ROLE_FORBIDDEN_DETAIL)}</div>'
            '<p><a class="button" href="/admin">Back to dashboard</a></p>'
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
    from .security import debug_errors_enabled

    if debug_errors_enabled():
        detail = f"<p>{html.escape(str(error))}</p><pre>{html.escape(traceback_text)}</pre>"
    else:
        detail = "<p>An unexpected error occurred. Details are available in the server logs.</p>"
    content = f"<html><body><h1>Application error</h1>{detail}</body></html>"
    return HTMLResponse(content=content, status_code=status_code)
