import traceback
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .activity_logging import emit_activity_event
from .db import SessionLocal
from .operational_logging import LOGGER
from .paths import TEMPLATES_DIR
from .rbac import (
    ROLE_API_KEYS_READ,
    ROLE_API_KEYS_UPDATE,
    ROLE_FORBIDDEN_DETAIL,
    ROLE_SYSTEM_UPDATE,
    get_user_roles,
    user_has_role,
)
from .restart import is_restart_required, preview_restart_urls, restart_reason
from .version import get_app_version

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["app_version"] = get_app_version()


def client_ip(request: Request) -> str | None:
    client = getattr(request, "client", None)
    return client.host if client else None


def record_activity(**kwargs: Any) -> None:
    try:
        with SessionLocal() as db:
            emit_activity_event(db, **kwargs)
    except Exception:  # pragma: no cover
        LOGGER.exception("emit_activity_event failed for event %s", kwargs.get("event_type"))


def render_error_page(
    *,
    status_code: int,
    title: str,
    heading: str,
    message: str,
    back_href: str = "/admin",
    back_label: str = "Back to dashboard",
    debug_traceback: str | None = None,
) -> HTMLResponse:
    """Render a branded HTML error using the shared admin template and assets."""
    content = templates.get_template("error.html").render(
        {
            "title": title,
            "heading": heading,
            "message": message,
            "back_href": back_href,
            "back_label": back_label,
            "debug_traceback": debug_traceback,
        }
    )
    return HTMLResponse(content=content, status_code=status_code)


def render_access_denied_response() -> HTMLResponse:
    return render_error_page(
        status_code=403,
        title="Access denied",
        heading="Access denied",
        message=ROLE_FORBIDDEN_DETAIL,
        back_href="/admin",
        back_label="Back to dashboard",
    )


def nav_context(db, user: str, *, show_dashboard_link: bool = True) -> dict:
    roles = get_user_roles(db, user)
    can_system_update = ROLE_SYSTEM_UPDATE in roles
    can_view_api_keys = user_has_role(db, user, ROLE_API_KEYS_READ) or user_has_role(db, user, ROLE_API_KEYS_UPDATE)
    restart_pending = is_restart_required(db)
    return {
        "show_dashboard_link": show_dashboard_link,
        "can_view_api_keys": can_view_api_keys,
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
        return render_error_page(
            status_code=status_code,
            title="Application error",
            heading="Application error",
            message=str(error),
            debug_traceback=traceback_text,
        )
    return render_error_page(
        status_code=status_code,
        title="Application error",
        heading="Application error",
        message="An unexpected error occurred. Details are available in the server logs.",
    )
