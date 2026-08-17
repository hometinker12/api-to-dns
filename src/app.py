import asyncio
import os
import signal
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import select
from starlette.status import HTTP_303_SEE_OTHER

from . import letsencrypt, ssl_certs
from .activity_logging import (
    LOGGER,
    apply_remote_syslog_config,
    configure_operational_logging,
    emit_activity_event,
    get_log_level,
    run_retention_cleanup,
)
from .auth import (
    create_session_cookie,
    get_current_user,
    session_cookie_secure,
    session_cookie_settings,
)
from .csrf import csrf_origin_allowed, csrf_rejection_response
from .db import SessionLocal, init_db
from .log_constants import LOG_LEVEL_VERBOSE
from .models import User
from .paths import STATIC_DIR
from .rate_limit import rate_limit_exceeded, rate_limit_rejection_response
from .rbac import (
    ALL_ROLES,
    ROLE_FORBIDDEN_DETAIL,
    ROLE_GLOBAL_ADMIN,
    serialize_roles,
)
from .restart import (
    apply_le_renewal_restart_policy,
    clear_le_renewal_pending_restart,
    clear_restart_required,
    is_le_renewal_pending_restart,
    perform_application_restart,
    scheduled_restart_due,
)
from .routes import include_routers
from .security import hash_password
from .version import get_app_version
from .web import client_ip, render_access_denied_response
from .zone_service import migrate_legacy_dns_settings_if_needed

AUTH_REDIRECT_DETAILS = {"Authentication required", "Invalid or expired session"}
WEB_AUTH_PATH_PREFIXES = (
    "/admin",
    "/zones",
    "/api-keys",
    "/settings",
)
_REQUEST_LOG_IGNORE_PREFIXES = ("/static",)

# Process-local shutdown latch. Not shared across uvicorn workers — run a single worker.
_shutting_down = False


def _make_shutdown_handler(previous_handler):
    def handler(signum: int, frame) -> None:
        global _shutting_down
        _shutting_down = True
        if previous_handler not in (signal.SIG_DFL, signal.SIG_IGN) and callable(previous_handler):
            previous_handler(signum, frame)

    return handler


def _startup_init() -> None:
    """Shared DB/logging/admin bootstrap used by lifespan and tests."""
    init_db()
    with SessionLocal() as db:
        migrate_legacy_dns_settings_if_needed(db)
        configure_operational_logging(level=get_log_level(db))
        try:
            apply_remote_syslog_config(db)
        except Exception:
            LOGGER.exception("startup remote syslog configuration failed")
        clear_restart_required(db)
        clear_le_renewal_pending_restart(db)
        letsencrypt.clear_enrollment_progress(db)
        from . import backup_service

        try:
            backup_service.clear_stale_restore_progress(db)
        except Exception:
            LOGGER.exception("startup restore-progress cleanup failed")
        try:
            run_retention_cleanup(db, force=True)
        except Exception:
            LOGGER.exception("startup activity retention cleanup failed")
    admin_user = os.getenv("ADMIN_USER")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_user and admin_password:
        with SessionLocal() as db:
            if not db.exec(select(User).where(User.username == admin_user)).first():
                db.add(
                    User(
                        username=admin_user,
                        password_hash=hash_password(admin_password),
                        roles=serialize_roles([*ALL_ROLES, ROLE_GLOBAL_ADMIN]),
                    )
                )
                db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _startup_init()
    renewal_task = asyncio.create_task(_letsencrypt_renewal_loop())
    restart_task = asyncio.create_task(_scheduled_restart_loop())
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGTERM, _make_shutdown_handler(previous_sigterm))
    signal.signal(signal.SIGINT, _make_shutdown_handler(previous_sigint))
    try:
        yield
    finally:
        global _shutting_down
        _shutting_down = True
        for task in (renewal_task, restart_task):
            task.cancel()
        await asyncio.gather(renewal_task, restart_task, return_exceptions=True)
        try:
            from .remote_syslog import REMOTE_SYSLOG

            REMOTE_SYSLOG.stop()
        except Exception:
            LOGGER.exception("remote syslog shutdown failed")
        signal.signal(signal.SIGTERM, previous_sigterm)
        signal.signal(signal.SIGINT, previous_sigint)


async def _run_letsencrypt_renewal_once() -> None:
    await asyncio.to_thread(letsencrypt.maybe_renew_certificate_standalone)


async def _letsencrypt_renewal_loop() -> None:
    while True:
        await asyncio.sleep(12 * 60 * 60)
        try:
            await _run_letsencrypt_renewal_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("Let's Encrypt renewal loop failed")


def _apply_le_renewal_restart_policy(db, config: dict[str, Any]) -> None:
    apply_le_renewal_restart_policy(db, config)


def _maybe_scheduled_le_restart(db, *, now: datetime | None = None) -> bool:
    config = letsencrypt.get_config(db)
    if not config or not config.get("scheduled_restart_enabled") or not config.get("scheduled_restart_time"):
        return False
    if ssl_certs._read_source() != ssl_certs.SOURCE_LETSENCRYPT:  # type: ignore[attr-defined]
        return False
    if not is_le_renewal_pending_restart(db):
        return False
    if not scheduled_restart_due(db, configured_time=str(config["scheduled_restart_time"]), now=now):
        return False
    clear_le_renewal_pending_restart(db)
    perform_application_restart(scheduled=True)
    return True


async def _scheduled_restart_loop() -> None:
    while True:
        await asyncio.sleep(60)
        try:
            with SessionLocal() as db:
                _maybe_scheduled_le_restart(db)
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("Scheduled restart loop failed")


def startup_event() -> None:
    """Run startup initialization (used by tests; production uses ``lifespan``)."""
    _startup_init()


def _openapi_enabled() -> bool:
    return os.getenv("OPENAPI_ENABLED", "").strip().lower() in {"1", "true", "yes"}


_OPENAPI_ON = _openapi_enabled()
app = FastAPI(
    title="api-to-dns Service",
    description="Create or update DNS records via REST and manage API keys through a protected web UI.",
    version=get_app_version(),
    lifespan=lifespan,
    docs_url="/docs" if _OPENAPI_ON else None,
    redoc_url="/redoc" if _OPENAPI_ON else None,
    openapi_url="/openapi.json" if _OPENAPI_ON else None,
)

# Explicit CORS only. Never auto-enable "*" from insecure crypto defaults.
_cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    ),
}

# FastAPI's default Swagger/ReDoc UIs load assets from jsDelivr (and a FastAPI favicon).
# Keep the strict CSP for the admin app; only relax these paths when OpenAPI is enabled.
_DOCS_PATHS = frozenset({"/docs", "/redoc", "/docs/oauth2-redirect"})
_OPENAPI_SCHEMA_PATH = "/openapi.json"
_DOCS_CSP = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://cdn.jsdelivr.net data:; "
    "connect-src 'self' https://cdn.jsdelivr.net"
)


@app.middleware("http")
async def openapi_session_middleware(request: Request, call_next):
    """Restrict optional API documentation to authenticated dashboard sessions."""
    path = request.url.path or ""
    if _OPENAPI_ON and (path == _OPENAPI_SCHEMA_PATH or path in _DOCS_PATHS):
        try:
            get_current_user(request)
        except HTTPException:
            if path == _OPENAPI_SCHEMA_PATH:
                return JSONResponse(status_code=401, content={"detail": "Authentication required"})
            return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path or ""
    headers = dict(_SECURITY_HEADERS)
    if path in _DOCS_PATHS:
        headers["Content-Security-Policy"] = _DOCS_CSP
    for header, value in headers.items():
        response.headers[header] = value
    if session_cookie_secure(request):
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    return response


@app.middleware("http")
async def csrf_and_rate_limit_middleware(request: Request, call_next):
    if rate_limit_exceeded(request):
        return rate_limit_rejection_response(request)
    if not csrf_origin_allowed(request):
        return csrf_rejection_response(request)
    return await call_next(request)


@app.middleware("http")
async def refresh_session_cookie(request: Request, call_next):
    response = await call_next(request)
    session_user = getattr(request.state, "session_user", None)
    if session_user and request.url.path != "/logout" and response.status_code < 400:
        session_version = int(getattr(request.state, "session_version", 0) or 0)
        response.set_cookie(
            "session",
            create_session_cookie(session_user, session_version),
            **session_cookie_settings(secure=session_cookie_secure(request)),
        )
    return response


@app.middleware("http")
async def record_request_activity(request: Request, call_next):
    response = await call_next(request)
    try:
        path = request.url.path
        if path.startswith(_REQUEST_LOG_IGNORE_PREFIXES):
            return response
        with SessionLocal() as db:
            session_user = getattr(request.state, "session_user", None)
            emit_activity_event(
                db,
                event_type="http.request",
                level=LOG_LEVEL_VERBOSE,
                status="success" if response.status_code < 400 else "error",
                actor_type="user" if session_user else "anonymous",
                actor_label=session_user,
                request_method=request.method,
                request_path=path,
                request_status_code=response.status_code,
                request_ip=client_ip(request),
                evaluate_alerts=False,
            )
    except Exception:  # pragma: no cover - logging must never break a request
        LOGGER.exception("request activity logging failed")
    return response


@app.middleware("http")
async def reject_requests_during_shutdown(request: Request, call_next):
    if _shutting_down:
        return PlainTextResponse("Shutting down", status_code=503)
    return await call_next(request)


@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException):
    """Redirect unauthenticated browser pages while preserving JSON API errors."""
    if (
        exc.status_code == 401
        and exc.detail in AUTH_REDIRECT_DETAILS
        and request.url.path.startswith(WEB_AUTH_PATH_PREFIXES)
    ):
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    if (
        exc.status_code == 403
        and exc.detail == ROLE_FORBIDDEN_DETAIL
        and request.url.path.startswith(WEB_AUTH_PATH_PREFIXES)
        and "application/json" not in request.headers.get("accept", "").lower()
    ):
        return render_access_denied_response()
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


include_routers(app)
