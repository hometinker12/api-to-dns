import html
import traceback
from typing import Any, Optional

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .activity_logging import LOGGER, emit_activity_event
from .db import SessionLocal
from .paths import TEMPLATES_DIR
from .rbac import ROLE_FORBIDDEN_DETAIL

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
