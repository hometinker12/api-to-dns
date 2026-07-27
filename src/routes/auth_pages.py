from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import select
from starlette.status import HTTP_303_SEE_OTHER

from ..activity_logging import LOGGER, emit_activity_event
from ..auth import create_session_cookie, session_cookie_secure, session_cookie_settings
from ..db import SessionLocal
from ..models import LOG_LEVEL_INFORMATIONAL, LOG_LEVEL_WARNING, User
from ..security import verify_password
from ..web import client_ip, record_activity, render_error_response, templates

router = APIRouter(tags=["auth"], include_in_schema=False)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    try:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": None},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = client_ip(request)
    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == username)).first()
        if not user or user.disabled or not verify_password(password, user.password_hash):
            try:
                emit_activity_event(
                    db,
                    event_type="auth.login_failed",
                    level=LOG_LEVEL_WARNING,
                    status="error",
                    actor_type="user",
                    actor_label=username,
                    message=f"Failed login for {username!r}",
                    details={"reason": "disabled" if user and user.disabled else "invalid_credentials"},
                    request_ip=ip,
                )
            except Exception:  # pragma: no cover
                LOGGER.exception("could not record auth.login_failed")
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid credentials."},
            )
        try:
            emit_activity_event(
                db,
                event_type="auth.login_succeeded",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="user",
                actor_label=username,
                message=f"Successful login for {username!r}",
                request_ip=ip,
            )
        except Exception:  # pragma: no cover
            LOGGER.exception("could not record auth.login_succeeded")
    response = RedirectResponse(url="/admin", status_code=HTTP_303_SEE_OTHER)
    response.set_cookie(
        "session",
        create_session_cookie(username),
        **session_cookie_settings(secure=session_cookie_secure()),
    )
    return response


@router.get("/logout")
def logout(request: Request) -> RedirectResponse:
    session_token = request.cookies.get("session")
    actor: Optional[str] = None
    if session_token:
        try:
            from ..auth import verify_session_cookie

            actor = verify_session_cookie(session_token)
        except Exception:  # pragma: no cover - invalid sessions still log out
            actor = None
    if actor:
        record_activity(
            event_type="auth.logout",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=actor,
            message=f"Logout for {actor!r}",
            request_ip=client_ip(request),
        )
    response = RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    response.delete_cookie("session")
    return response
