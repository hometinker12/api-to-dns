import asyncio
import os
import signal
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import select
from starlette.status import HTTP_202_ACCEPTED, HTTP_303_SEE_OTHER, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT

from . import activity_logging
from .activity_logging import (
    LOGGER,
    configure_operational_logging,
    emit_activity_event,
    get_log_level,
    get_retention_days,
    get_smtp_config,
    is_running_in_docker,
    run_retention_cleanup,
    set_app_dns_name,
    set_log_level,
    set_retention_days,
    set_smtp_config,
)
from .auth import create_session_cookie, get_current_user, session_cookie_settings
from .db import SessionLocal, init_db
from .http_utils import (
    api_key_fingerprint,
    api_key_from_headers,
    http_exception_from_dns_error,
    sanitize_client_error_message,
    wants_json_response,
)
from .models import (
    LOG_CATEGORY_SECURITY,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
    AlertRule,
    ApiKey,
    ApiKeyAllowedZone,
    DnsRecordCreateRequest,
    DnsRecordGetResponse,
    DnsRecordInfo,
    DnsRecordPatchRequest,
    DnsRecordReplaceRequest,
    DnsRecordRequest,
    DnsRecordResponse,
    DnsZoneConfig,
    DnsZoneSummary,
    User,
)
from .plugins.utils import normalize_lookup_record_type
from .paths import STATIC_DIR
from .rbac import (
    ALL_ROLES,
    LEGACY_SETTINGS_AREA_ALIASES,
    ROLE_ACCOUNT_RESET_PASSWORD,
    ROLE_ACCOUNT_UPDATE,
    ROLE_API_KEYS_READ,
    ROLE_API_KEYS_UPDATE,
    ROLE_DNS_ZONES_READ,
    ROLE_DNS_ZONES_UPDATE,
    ROLE_FORBIDDEN_DETAIL,
    ROLE_GLOBAL_ADMIN,
    ROLE_GLOBAL_READ,
    ROLE_PLUGIN_UPDATE,
    ROLE_SYSTEM_UPDATE,
    get_user_roles,
    global_admin_guard_message,
    normalize_selected_roles,
    require_role,
    serialize_roles,
    user_has_role,
    user_is_global_admin,
    user_public_dict,
)
from .security import allow_insecure_defaults, api_key_prefix, generate_api_key, hash_api_key, hash_password, verify_password
from .csrf import csrf_origin_allowed, csrf_rejection_response
from .rate_limit import rate_limit_exceeded, rate_limit_rejection_response
from .settings_context import render_settings
from .settings_store import get_setting, set_setting
from . import ssl_certs
from . import letsencrypt
from .letsencrypt import LetsEncryptError
from .restart import (
    clear_le_renewal_pending_restart,
    clear_restart_required,
    is_le_renewal_pending_restart,
    is_restart_required,
    mark_le_renewal_pending_restart,
    mark_restart_required,
    perform_application_restart,
    scheduled_restart_due,
)
from .ssl_certs import (
    CertificateInstallError,
    OpenSSLUnavailableError,
    cert_exists,
    create_self_signed_cert,
    install_uploaded_cert,
    is_ssl_enabled,
    regenerate_self_signed_cert,
    set_ssl_enabled,
)
from .version import get_app_version
from .web import client_ip, nav_context, record_activity, render_access_denied_response, render_error_response, templates
from .zone_service import (
    api_key_admin_dict,
    api_key_allowed_zone_names,
    api_key_public_dict,
    build_zone_config_from_form,
    create_dns_client_from_settings,
    decode_zone_config,
    dns_provider_display_name,
    dns_provider_options_with_state,
    dns_zone_admin_dict,
    dns_zone_public_dict,
    dns_zone_summary_dict,
    enabled_dns_provider_options,
    encode_zone_config_dict,
    get_api_key,
    get_disabled_dns_plugins,
    get_dns_provider_options,
    get_known_dns_provider_keys,
    list_dns_zones,
    migrate_legacy_dns_settings_if_needed,
    normalize_zone_name,
    provider_dns_zone,
    set_disabled_dns_plugins,
    test_zone_record_lookup,
    zones_using_dns_provider,
    DnsProviderDisabledError,
)


def _zones_html_context(db, *, message: Optional[str] = None) -> Dict[str, Any]:
    zones = list_dns_zones(db)
    return {
        "zones": [dns_zone_admin_dict(db, z) for z in zones],
        "message": message,
    }


def _api_keys_html_context(db, *, message: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda key: key.created_at, reverse=True)
    key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
    all_zones = list_dns_zones(db)
    return {
        "api_keys": [api_key_admin_dict(db, k) for k in api_keys],
        "key_zones": key_zones,
        "all_zones": [dns_zone_public_dict(z) for z in all_zones],
        "message": message,
        **extra,
    }


def _resolve_dns_api_zone(
    db,
    *,
    api_key: str,
    zone_name: str,
    record_name: str,
    endpoint: str,
) -> tuple[ApiKey, DnsZoneConfig, Dict[str, Any], Optional[str], str, str]:
    key = get_api_key(db, api_key)
    if key is None:
        emit_activity_event(
            db,
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_label="invalid",
            message=f"Invalid or revoked API key used on {endpoint}",
            details={"key_fingerprint": api_key_fingerprint(api_key)},
        )
        raise HTTPException(status_code=401, detail="Invalid API key")

    actor_id = str(key.id) if key.id is not None else None
    actor_label = key.label

    if not zone_name or not str(zone_name).strip():
        emit_activity_event(
            db,
            event_type="dns.invalid_request",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            record_name=record_name,
            message=f"zone_name is required on {endpoint}",
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": "zone_name is required on every request."},
        )

    canonical = normalize_zone_name(zone_name)
    zone_row = db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == canonical)).first()
    if zone_row is None:
        emit_activity_event(
            db,
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            zone_name=canonical,
            record_name=record_name,
            message=f"Unknown DNS zone {canonical!r}",
        )
        raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)

    perm = db.exec(
        select(ApiKeyAllowedZone).where(
            ApiKeyAllowedZone.api_key_id == key.id,
            ApiKeyAllowedZone.dns_zone_config_id == zone_row.id,
        )
    ).first()
    if perm is None:
        emit_activity_event(
            db,
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            zone_name=canonical,
            record_name=record_name,
            message=f"API key {actor_label!r} not allowed for zone {canonical!r}",
        )
        raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)

    settings = decode_zone_config(zone_row)
    provider = (settings.get("dns_provider_type") or "azure").strip().lower()
    if provider == "azure":
        if not settings.get("azure_subscription_id"):
            emit_activity_event(
                db,
                event_type="dns.invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=canonical,
                record_name=record_name,
                message="Azure subscription ID is required on the zone configuration.",
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "message": "Azure subscription ID is required on the zone configuration.",
                },
            )
        if not settings.get("azure_resource_group"):
            emit_activity_event(
                db,
                event_type="dns.invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=canonical,
                record_name=record_name,
                message="Azure resource group is required on the zone configuration.",
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "message": "Azure resource group is required on the zone configuration.",
                },
            )

    return key, zone_row, settings, actor_id, actor_label, provider

ACCESS_DENIED_DETAIL: Dict[str, str] = {
    "error": "access_denied",
    "message": "You do not have access or an invalid key was provided.",
}

AUTH_REDIRECT_DETAILS = {"Authentication required", "Invalid or expired session"}
WEB_AUTH_PATH_PREFIXES = (
    "/admin",
    "/zones",
    "/api-keys",
    "/settings",
)
_REQUEST_LOG_IGNORE_PREFIXES = ("/static",)

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
        clear_restart_required(db)
        clear_le_renewal_pending_restart(db)
        letsencrypt.clear_enrollment_progress(db)
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
        signal.signal(signal.SIGTERM, previous_sigterm)
        signal.signal(signal.SIGINT, previous_sigint)


async def _letsencrypt_renewal_loop() -> None:
    while True:
        await asyncio.sleep(12 * 60 * 60)
        try:
            with SessionLocal() as db:
                result = letsencrypt.maybe_renew_certificate(db)
                if result:
                    _apply_le_renewal_restart_policy(db, result.get("config") or {})
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("Let's Encrypt renewal loop failed")


def _apply_le_renewal_restart_policy(db, config: Dict[str, Any]) -> None:
    if config.get("scheduled_restart_enabled") and config.get("scheduled_restart_time"):
        mark_le_renewal_pending_restart(db)
    else:
        mark_restart_required(db, reason="Let's Encrypt certificate renewed.")


def _maybe_scheduled_le_restart(db, *, now: Optional[datetime] = None) -> bool:
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


app = FastAPI(
    title="api-to-dns Service",
    description="Create or update DNS records via REST and manage API keys through a protected web UI.",
    version=get_app_version(),
    lifespan=lifespan,
)

_cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
if not _cors_origins and allow_insecure_defaults():
    # Tests / local insecure mode: keep permissive CORS for convenience.
    _cors_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _session_cookie_secure() -> bool:
    env = os.getenv("SSL_ENABLED", "").strip().lower()
    if env in {"1", "true", "yes"}:
        return True
    if env in {"0", "false", "no"}:
        return False
    try:
        with SessionLocal() as db:
            return bool(is_ssl_enabled(db))
    except Exception:
        return False


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
        response.set_cookie(
            "session",
            create_session_cookie(session_user),
            **session_cookie_settings(secure=_session_cookie_secure()),
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



# Backwards-compatible re-exports for tests and external callers.
from .rbac import parse_roles as _parse_roles, serialize_roles as _serialize_roles

get_dns_client_from_settings = create_dns_client_from_settings
get_dns_provider_label = dns_provider_display_name

@app.get("/", response_class=RedirectResponse, include_in_schema=False)
def root(request: Request) -> RedirectResponse:
    try:
        get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/admin")


@app.get(
    "/keycheck",
    responses={
        200: {
            "description": "API key is valid",
            "content": {
                "application/json": {
                    "example": {"status": "success"},
                    "schema": {
                        "type": "object",
                        "properties": {"status": {"type": "string", "example": "success"}},
                        "required": ["status"],
                    },
                }
            },
        },
        401: {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "example": {"status": "failure"},
                    "schema": {
                        "type": "object",
                        "properties": {"status": {"type": "string", "example": "failure"}},
                        "required": ["status"],
                    },
                }
            },
        }
    },
)
def keycheck(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)

    if not api_key:
        return JSONResponse(status_code=401, content={"status": "failure"})

    with SessionLocal() as db:
        key = get_api_key(db, api_key)
        if key is None:
            return JSONResponse(status_code=401, content={"status": "failure"})

    return {"status": "success"}


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_form(request: Request):
    try:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": None},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@app.post("/login", response_class=HTMLResponse, include_in_schema=False)
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
        **session_cookie_settings(secure=_session_cookie_secure()),
    )
    return response


@app.get("/logout", include_in_schema=False)
def logout(request: Request) -> RedirectResponse:
    session_token = request.cookies.get("session")
    actor: Optional[str] = None
    if session_token:
        try:
            from .auth import verify_session_cookie

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


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
def admin(request: Request, user: str = Depends(get_current_user)):
    try:
        with SessionLocal() as db:
            can_view_zones = user_has_role(db, user, ROLE_DNS_ZONES_READ) or user_has_role(db, user, ROLE_DNS_ZONES_UPDATE)
            can_view_api_keys = user_has_role(db, user, ROLE_API_KEYS_READ) or user_has_role(db, user, ROLE_API_KEYS_UPDATE)
            zones = list_dns_zones(db)
            api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda key: key.created_at, reverse=True)
            key_zones: Dict[int, List[str]] = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
            api_keys_view = [api_key_public_dict(k) for k in api_keys]
            zones_view = [dns_zone_public_dict(z) for z in zones]
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={
                "request": request,
                "user": user,
                "zones": zones_view,
                "api_keys": api_keys_view,
                "key_zones": key_zones,
                "can_view_zones": can_view_zones,
                "can_view_api_keys": can_view_api_keys,
            },
        )
    except Exception as exc:
        return render_error_response(request, exc)


@app.get(
    "/zones",
    response_model=List[DnsZoneSummary],
    responses={
        200: {
            "description": "HTML DNS zones page, or JSON zone summaries when requested with application/json.",
            "content": {
                "text/html": {"schema": {"type": "string"}},
            },
        }
    },
)
def zones_page(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    with SessionLocal() as db:
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

        user = get_current_user(request)
        if not user_has_role(db, user, ROLE_DNS_ZONES_READ):
            raise HTTPException(status_code=403, detail=ROLE_FORBIDDEN_DETAIL)
        ctx = _zones_html_context(db)
    return templates.TemplateResponse(
        request=request,
        name="zones.html",
        context={"request": request, **ctx},
    )


@app.get("/zones/new", response_class=HTMLResponse, include_in_schema=False)
def zone_new_form(request: Request, user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE))):
    with SessionLocal() as db:
        provider_plugins = enabled_dns_provider_options(db)
    return templates.TemplateResponse(
        request=request,
        name="zone_form.html",
        context={
            "request": request,
            "zone": None,
            "settings": {},
            "provider_plugins": provider_plugins,
            "message": None if provider_plugins else "No DNS provider plugins are enabled. Enable a plugin in Settings first.",
            "title": "Add DNS zone",
        },
    )


@app.post("/zones", response_class=HTMLResponse, include_in_schema=False)
async def zone_create(request: Request, user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE))):
    form = await request.form()
    zone_name = str(form.get("zone_name") or "")
    canonical = normalize_zone_name(zone_name)
    if not canonical:
        with SessionLocal() as db:
            ctx = _zones_html_context(db, message="Zone name is required.")
        return templates.TemplateResponse(
            request=request,
            name="zones.html",
            context={"request": request, **ctx},
        )
    with SessionLocal() as db:
        provider_plugins = enabled_dns_provider_options(db)
        if db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == canonical)).first():
            ctx = _zones_html_context(db, message=f"A zone named {canonical!r} already exists.")
            return templates.TemplateResponse(
                request=request,
                name="zones.html",
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
        ctx = _zones_html_context(db, message=f"Zone {canonical!r} added.")
    return templates.TemplateResponse(
        request=request,
        name="zones.html",
        context={"request": request, **ctx},
    )


@app.post("/zones/test", include_in_schema=False)
async def zone_test(request: Request, user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE))):
    form = await request.form()
    zone_name_raw = str(form.get("zone_name") or "")
    test_record_name = str(form.get("test_record_name") or "").strip()
    test_record_type_raw = str(form.get("test_record_type") or "").strip()
    zone_id_raw = form.get("zone_id")

    existing: Optional[Dict[str, Any]] = None
    canonical = normalize_zone_name(zone_name_raw)

    with SessionLocal() as db:
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
            records = test_zone_record_lookup(
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
                message = f"Authentication successful. No {test_record_type} record found for {test_record_name!r} in zone {canonical!r}."
            else:
                message = (
                    f"Authentication successful. No records found at {test_record_name!r} in zone {canonical!r}."
                )
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


@app.get("/zones/{zone_id}/edit", response_class=HTMLResponse, include_in_schema=False)
def zone_edit_form(request: Request, zone_id: int, user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE))):
    with SessionLocal() as db:
        row = db.get(DnsZoneConfig, zone_id)
        if not row:
            return RedirectResponse(url="/zones", status_code=HTTP_303_SEE_OTHER)
        settings = decode_zone_config(row)
        zone_view = dns_zone_public_dict(row)
        provider_plugins = enabled_dns_provider_options(db)
        title_zone = row.zone_name
    return templates.TemplateResponse(
        request=request,
        name="zone_form.html",
        context={
            "request": request,
            "zone": zone_view,
            "settings": settings,
            "provider_plugins": provider_plugins,
            "message": None,
            "title": f"Edit zone {title_zone}",
        },
    )


@app.post("/zones/{zone_id}", response_class=HTMLResponse, include_in_schema=False)
async def zone_update(request: Request, zone_id: int, user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE))):
    form = await request.form()
    with SessionLocal() as db:
        row = db.get(DnsZoneConfig, zone_id)
        if not row:
            return RedirectResponse(url="/zones", status_code=HTTP_303_SEE_OTHER)
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
            "zone": zone_view,
            "settings": settings,
            "provider_plugins": provider_plugins,
            "message": "Zone saved.",
            "title": f"Edit zone {title_zone}",
        },
    )


@app.post("/zones/{zone_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def zone_delete(request: Request, zone_id: int, user: str = Depends(require_role(ROLE_DNS_ZONES_UPDATE))):
    with SessionLocal() as db:
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
        ctx = _zones_html_context(db, message="Zone removed.")
    return templates.TemplateResponse(
        request=request,
        name="zones.html",
        context={"request": request, **ctx},
    )


@app.get("/api-keys", response_class=HTMLResponse, include_in_schema=False)
def api_keys_page(request: Request, user: str = Depends(require_role(ROLE_API_KEYS_READ))):
    try:
        with SessionLocal() as db:
            ctx = _api_keys_html_context(db)
        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, **ctx},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@app.post("/api-keys/revoke", response_class=HTMLResponse, include_in_schema=False)
def revoke_api_key(request: Request, key_id: int = Form(...), user: str = Depends(require_role(ROLE_API_KEYS_UPDATE))):
    try:
        with SessionLocal() as db:
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
            ctx = _api_keys_html_context(db, message="API key revoked.")

        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, **ctx},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@app.post("/api-keys", response_class=HTMLResponse, include_in_schema=False)
def create_api_key_route(
    request: Request,
    label: str = Form(...),
    zone_ids: List[int] = Form(default_factory=list),
    key_id: Optional[int] = Form(None),
    user: str = Depends(require_role(ROLE_API_KEYS_UPDATE)),
):
    try:
        if key_id is not None:
            with SessionLocal() as db:
                row = db.get(ApiKey, key_id)
                if not row:
                    return RedirectResponse(url="/api-keys", status_code=HTTP_303_SEE_OTHER)
                if not zone_ids:
                    ctx = _api_keys_html_context(
                        db,
                        edit_key_error_id=key_id,
                        edit_key_error="Select at least one DNS zone.",
                        edit_key_label=label,
                        edit_key_selected_zone_ids=zone_ids,
                    )
                    return templates.TemplateResponse(
                        request=request,
                        name="api_keys.html",
                        context={"request": request, **ctx},
                    )
                row.label = label
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
                    details={"api_key_id": key_id, "api_key_label": label, "allowed_zone_ids": list(zone_ids)},
                )
                ctx = _api_keys_html_context(db, message="API key updated.")
            return templates.TemplateResponse(
                request=request,
                name="api_keys.html",
                context={"request": request, **ctx},
            )
        if not zone_ids:
            with SessionLocal() as db:
                ctx = _api_keys_html_context(
                    db,
                    create_key_error="Select at least one DNS zone for this API key.",
                    create_key_label=label,
                )
            return templates.TemplateResponse(
                request=request,
                name="api_keys.html",
                context={"request": request, **ctx},
            )
        new_key = generate_api_key()
        with SessionLocal() as db:
            api_key = ApiKey(label=label, key=hash_api_key(new_key), key_prefix=api_key_prefix(new_key))
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
                    "allowed_zone_ids": list(zone_ids),
                    "key_prefix": api_key.key_prefix,
                },
            )
            ctx = _api_keys_html_context(
                db,
                message=(
                    f"API key created. Copy it now — it will not be shown again: {new_key}"
                ),
            )

        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, **ctx},
        )
    except Exception as exc:
        return render_error_response(request, exc)


@app.get("/api-keys/{key_id}/edit", response_class=HTMLResponse, include_in_schema=False)
def api_key_edit_form(request: Request, key_id: int, user: str = Depends(require_role(ROLE_API_KEYS_UPDATE))):
    with SessionLocal() as db:
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
            "api_key_row": api_key_row,
            "all_zones": all_zones_view,
            "allowed_ids": allowed_ids,
            "message": None,
        },
    )


@app.post("/api-keys/{key_id}", response_class=HTMLResponse, include_in_schema=False)
def api_key_update(
    request: Request,
    key_id: int,
    label: str = Form(...),
    zone_ids: List[int] = Form(default_factory=list),
    user: str = Depends(require_role(ROLE_API_KEYS_UPDATE)),
):
    with SessionLocal() as db:
        row = db.get(ApiKey, key_id)
        if not row:
            return RedirectResponse(url="/api-keys", status_code=HTTP_303_SEE_OTHER)
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
                    "api_key_row": api_key_public_dict(row),
                    "all_zones": [dns_zone_public_dict(z) for z in all_zones],
                    "allowed_ids": allowed_ids,
                    "message": "Select at least one DNS zone.",
                },
            )
        row.label = label
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
            details={"api_key_id": key_id, "api_key_label": label, "allowed_zone_ids": list(zone_ids)},
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
            "api_key_row": api_key_row,
            "all_zones": all_zones_view,
            "allowed_ids": allowed_ids,
            "message": "API key updated.",
        },
    )


@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
def settings_page(
    request: Request,
    area: Optional[str] = None,
    section: Optional[str] = None,
    event_type: Optional[str] = None,
    level: Optional[str] = None,
    category: Optional[str] = None,
    log_status: Optional[str] = None,
    zone_name: Optional[str] = None,
    actor: Optional[str] = None,
    text_query: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    offset: int = 0,
    user: str = Depends(get_current_user),
):
    normalized_area = (area or "").strip().lower()
    if normalized_area in LEGACY_SETTINGS_AREA_ALIASES:
        normalized_area = LEGACY_SETTINGS_AREA_ALIASES[normalized_area]
    log_search_params: Optional[Dict[str, Any]] = None
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
    return render_settings(
        request, user, normalized_area, log_search_params=log_search_params, section=section
    )


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


@app.post("/settings/account/password", response_class=HTMLResponse, include_in_schema=False)
def settings_self_password_change(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: str = Depends(get_current_user),
):
    if not new_password:
        return render_settings(
            request,
            user,
            "authentication",
            message="A new password is required.",
            message_kind="error",
        )
    if new_password != confirm_password:
        return render_settings(
            request,
            user,
            "authentication",
            message="New password and confirmation do not match.",
            message_kind="error",
        )
    with SessionLocal() as db:
        target = db.exec(select(User).where(User.username == user)).first()
        if target is None or not verify_password(current_password, target.password_hash):
            return render_settings(
                request,
                user,
                "authentication",
                message="Current password is incorrect.",
                message_kind="error",
            )
        target.password_hash = hash_password(new_password)
        db.add(target)
        db.commit()
        emit_activity_event(
            db,
            event_type="user.password_changed",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"User {user!r} changed their own password",
            details={"target_username": user},
        )
    return render_settings(request, user, "authentication", message="Password changed.")


@app.post("/settings/users", response_class=HTMLResponse, include_in_schema=False)
def settings_user_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    roles: List[str] = Form(default_factory=list),
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    normalized = username.strip()
    selected_roles = normalize_selected_roles(roles)
    if not normalized:
        return render_settings(
            request,
            user,
            "authentication",
            auth_form_error="Username is required.",
            auth_form_username=username,
            auth_form_selected_roles=selected_roles,
        )
    if not password:
        return render_settings(
            request,
            user,
            "authentication",
            auth_form_error="Password is required.",
            auth_form_username=normalized,
            auth_form_selected_roles=selected_roles,
        )
    with SessionLocal() as db:
        if ROLE_GLOBAL_ADMIN in selected_roles and not user_is_global_admin(db, user):
            return render_settings(
                request,
                user,
                "authentication",
                auth_form_error="Only a global admin can grant global admin.",
                auth_form_username=normalized,
                auth_form_selected_roles=[r for r in selected_roles if r != ROLE_GLOBAL_ADMIN],
            )
        if db.exec(select(User).where(User.username == normalized)).first():
            return render_settings(
                request,
                user,
                "authentication",
                auth_form_error=f"A user named {normalized!r} already exists.",
                auth_form_username=normalized,
                auth_form_selected_roles=selected_roles,
            )
        db.add(
            User(
                username=normalized,
                password_hash=hash_password(password),
                roles=serialize_roles(selected_roles),
            )
        )
        db.commit()
        emit_activity_event(
            db,
            event_type="user.created",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"User {normalized!r} created",
            details={"target_username": normalized, "roles": selected_roles},
        )
    return render_settings(
        request,
        user,
        "authentication",
        message=f"User {normalized!r} created.",
    )


@app.post("/settings/users/{user_id}/disable", response_class=HTMLResponse, include_in_schema=False)
def settings_user_disable(
    request: Request,
    user_id: int,
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            return render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if target.disabled:
            return render_settings(
                request,
                user,
                "authentication",
                message=f"User {target.username!r} is already disabled.",
                message_kind="error",
            )
        enabled_users = db.exec(select(User).where(User.disabled == False)).all()  # noqa: E712
        if len(enabled_users) <= 1:
            return render_settings(
                request,
                user,
                "authentication",
                message="At least one enabled user account must remain.",
                message_kind="error",
            )
        if target.username == user:
            return render_settings(
                request,
                user,
                "authentication",
                message="You cannot disable the user you are signed in as.",
                message_kind="error",
            )
        target.disabled = True
        db.add(target)
        db.commit()
        username = target.username
        emit_activity_event(
            db,
            event_type="user.disabled",
            level=LOG_LEVEL_WARNING,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"User {username!r} disabled",
            details={"target_username": username, "target_user_id": user_id},
        )
    return render_settings(
        request,
        user,
        "authentication",
        message=f"User {username!r} disabled.",
    )


@app.post("/settings/users/{user_id}/enable", response_class=HTMLResponse, include_in_schema=False)
def settings_user_enable(
    request: Request,
    user_id: int,
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            return render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if not target.disabled:
            return render_settings(
                request,
                user,
                "authentication",
                message=f"User {target.username!r} is already enabled.",
                message_kind="error",
            )
        target.disabled = False
        db.add(target)
        db.commit()
        username = target.username
        emit_activity_event(
            db,
            event_type="user.enabled",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"User {username!r} enabled",
            details={"target_username": username, "target_user_id": user_id},
        )
    return render_settings(
        request,
        user,
        "authentication",
        message=f"User {username!r} enabled.",
    )


@app.post("/settings/users/{user_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def settings_user_delete(
    request: Request,
    user_id: int,
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            return render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        remaining = db.exec(select(User)).all()
        if len(remaining) <= 1:
            return render_settings(
                request,
                user,
                "authentication",
                message="At least one user account must remain.",
                message_kind="error",
            )
        if target.username == user:
            return render_settings(
                request,
                user,
                "authentication",
                message="You cannot delete the user you are signed in as.",
                message_kind="error",
            )
        if not target.disabled:
            return render_settings(
                request,
                user,
                "authentication",
                message="Disable the user account before deleting it.",
                message_kind="error",
            )
        username = target.username
        db.delete(target)
        db.commit()
        emit_activity_event(
            db,
            event_type="user.deleted",
            level=LOG_LEVEL_WARNING,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"User {username!r} deleted",
            details={"target_username": username, "target_user_id": user_id},
        )
    return render_settings(
        request,
        user,
        "authentication",
        message=f"User {username!r} deleted.",
    )


@app.post("/settings/users/{user_id}/password", response_class=HTMLResponse, include_in_schema=False)
def settings_user_reset_password(
    request: Request,
    user_id: int,
    password: str = Form(...),
    confirm_password: str = Form(...),
    user: str = Depends(require_role(ROLE_ACCOUNT_RESET_PASSWORD)),
):
    if not password or not confirm_password:
        return render_settings(
            request,
            user,
            "authentication",
            message="A new password is required.",
            message_kind="error",
        )
    if password != confirm_password:
        return render_settings(
            request,
            user,
            "authentication",
            message="New password and confirmation do not match.",
            message_kind="error",
        )
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            return render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if target.disabled:
            return render_settings(
                request,
                user,
                "authentication",
                message="Enable the user account before resetting its password.",
                message_kind="error",
            )
        target.password_hash = hash_password(password)
        db.add(target)
        db.commit()
        username = target.username
        emit_activity_event(
            db,
            event_type="user.password_reset",
            level=LOG_LEVEL_WARNING,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Password reset for {username!r}",
            details={"target_username": username, "target_user_id": user_id},
        )
    return render_settings(
        request,
        user,
        "authentication",
        message=f"Password reset for {username!r}.",
    )


@app.post("/settings/users/{user_id}/roles", response_class=HTMLResponse, include_in_schema=False)
def settings_user_update_roles(
    request: Request,
    user_id: int,
    roles: List[str] = Form(default_factory=list),
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    selected = normalize_selected_roles(roles)
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            return render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if target.username == user:
            return render_settings(
                request,
                user,
                "authentication",
                message="You cannot edit roles for the user you are signed in as.",
                message_kind="error",
            )
        target_stored_roles = _parse_roles(target.roles)
        if (
            (ROLE_GLOBAL_ADMIN in selected or ROLE_GLOBAL_ADMIN in target_stored_roles)
            and not user_is_global_admin(db, user)
        ):
            return render_settings(
                request,
                user,
                "authentication",
                message="Only a global admin can change global admin role assignments.",
                message_kind="error",
            )
        if target.disabled:
            return render_settings(
                request,
                user,
                "authentication",
                message="Enable the user account before editing its roles.",
                message_kind="error",
            )
        target.roles = serialize_roles(selected)
        db.add(target)
        db.commit()
        username = target.username
        emit_activity_event(
            db,
            event_type="user.roles_updated",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Roles updated for {username!r}",
            details={"target_username": username, "roles": selected},
        )
    return render_settings(
        request,
        user,
        "authentication",
        message=f"Roles updated for {username!r}.",
    )


@app.post("/settings/plugins/{plugin_key}/disable", response_class=HTMLResponse, include_in_schema=False)
def settings_plugin_disable(
    request: Request,
    plugin_key: str,
    user: str = Depends(require_role(ROLE_PLUGIN_UPDATE)),
):
    normalized_key = plugin_key.strip().lower()
    known_keys = get_known_dns_provider_keys()
    if normalized_key not in known_keys:
        return render_settings(
            request,
            user,
            "plugins",
            message=f"Unknown DNS provider plugin: {plugin_key}.",
            message_kind="error",
        )

    with SessionLocal() as db:
        disabled = get_disabled_dns_plugins(db)
        if normalized_key in disabled:
            return render_settings(request, user, "plugins", message=f"{dns_provider_display_name(normalized_key)} is already disabled.")
        enabled_count = len([plugin for plugin in get_dns_provider_options() if plugin["key"] not in disabled])
        if enabled_count <= 1:
            return render_settings(
                request,
                user,
                "plugins",
                message="At least one DNS provider plugin must remain enabled.",
                message_kind="error",
            )
        zone_names = zones_using_dns_provider(db, normalized_key)
        if zone_names:
            zones_text = ", ".join(zone_names)
            first_zone = zone_names[0]
            return render_settings(
                request,
                user,
                "plugins",
                message=(
                    f"Cannot disable {dns_provider_display_name(normalized_key)}. "
                    f"Delete DNS zone {first_zone} first."
                    if len(zone_names) == 1
                    else f"Cannot disable {dns_provider_display_name(normalized_key)}. Delete DNS zones {zones_text} first."
                ),
                message_kind="error",
            )
        disabled.add(normalized_key)
        set_disabled_dns_plugins(db, disabled)
        emit_activity_event(
            db,
            event_type="plugin.disabled",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Plugin {normalized_key!r} disabled",
            details={"plugin_key": normalized_key},
        )

    return render_settings(request, user, "plugins", message=f"{dns_provider_display_name(normalized_key)} disabled.")


@app.post("/settings/plugins/{plugin_key}/enable", response_class=HTMLResponse, include_in_schema=False)
def settings_plugin_enable(
    request: Request,
    plugin_key: str,
    user: str = Depends(require_role(ROLE_PLUGIN_UPDATE)),
):
    normalized_key = plugin_key.strip().lower()
    known_keys = get_known_dns_provider_keys()
    if normalized_key not in known_keys:
        return render_settings(
            request,
            user,
            "plugins",
            message=f"Unknown DNS provider plugin: {plugin_key}.",
            message_kind="error",
        )

    with SessionLocal() as db:
        disabled = get_disabled_dns_plugins(db)
        was_disabled = normalized_key in disabled
        disabled.discard(normalized_key)
        set_disabled_dns_plugins(db, disabled)
        if was_disabled:
            emit_activity_event(
                db,
                event_type="plugin.enabled",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="user",
                actor_label=user,
                message=f"Plugin {normalized_key!r} enabled",
                details={"plugin_key": normalized_key},
            )

    return render_settings(request, user, "plugins", message=f"{dns_provider_display_name(normalized_key)} enabled.")


@app.post("/settings/system/app-dns-name", response_class=HTMLResponse, include_in_schema=False)
def settings_update_app_dns_name(
    request: Request,
    app_dns_name: str = Form(...),
    redirect_section: str = Form("system_identity"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    try:
        with SessionLocal() as db:
            applied = set_app_dns_name(db, app_dns_name)
            emit_activity_event(
                db,
                event_type="system.app_dns_name_changed",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="user",
                actor_label=user,
                message=f"App DNS name set to {applied}",
                details={"app_dns_name": applied},
            )
    except ValueError as exc:
        return render_settings(
            request,
            user,
            "system_settings",
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )
    return render_settings(
        request,
        user,
        "system_settings",
        message=f"App DNS name saved as {applied}.",
        section=redirect_section,
    )


@app.post("/settings/system/log-level", response_class=HTMLResponse, include_in_schema=False)
def settings_update_log_level(
    request: Request,
    log_level: str = Form(...),
    redirect_area: str = Form("system_settings"),
    redirect_section: str = Form("logging_configuration"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    target_area = (redirect_area or "system_settings").strip().lower()
    if target_area not in {"system_settings", "log_viewing"}:
        target_area = "system_settings"
    target_section = redirect_section if target_area == "system_settings" else None
    try:
        previous = None
        with SessionLocal() as db:
            previous = get_log_level(db)
            applied = set_log_level(db, log_level)
            configure_operational_logging(level=applied)
            emit_activity_event(
                db,
                event_type="system.log_level_changed",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="user",
                actor_label=user,
                message=f"Activity log level set to {applied}",
                details={"previous_level": previous, "new_level": applied},
            )
    except ValueError as exc:
        return render_settings(
            request, user, target_area, message=str(exc), message_kind="error", section=target_section
        )
    return render_settings(
        request, user, target_area, message=f"Activity log level set to {applied}.", section=target_section
    )


@app.post("/settings/system/retention", response_class=HTMLResponse, include_in_schema=False)
def settings_update_retention(
    request: Request,
    retention_days: int = Form(...),
    redirect_section: str = Form("audit_log_retention"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    if retention_days < 1:
        return render_settings(
            request,
            user,
            "system_settings",
            message="Retention must be at least 1 day.",
            message_kind="error",
            section=redirect_section,
        )
    with SessionLocal() as db:
        applied = set_retention_days(db, retention_days)
        emit_activity_event(
            db,
            event_type="system.retention_changed",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Activity log retention set to {applied} days",
            details={"retention_days": applied},
        )
    return render_settings(
        request,
        user,
        "system_settings",
        message=f"Activity log retention set to {applied} days.",
        section=redirect_section,
    )


@app.post("/settings/system/smtp", response_class=HTMLResponse, include_in_schema=False)
def settings_update_smtp(
    request: Request,
    smtp_servers: str = Form(""),
    smtp_port: int = Form(activity_logging.DEFAULT_SMTP_PORT),
    smtp_security: str = Form("none"),
    smtp_anonymous: Optional[str] = Form(None),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    smtp_timeout: int = Form(activity_logging.DEFAULT_SMTP_TIMEOUT),
    redirect_section: str = Form("smtp_delivery"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    anonymous = smtp_anonymous is not None
    with SessionLocal() as db:
        set_smtp_config(
            db,
            servers=smtp_servers,
            port=smtp_port,
            anonymous=anonymous,
            username=smtp_username,
            password=smtp_password,
            from_address=smtp_from,
            security=smtp_security,
            timeout=smtp_timeout,
        )
        emit_activity_event(
            db,
            event_type="system.smtp_updated",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message="SMTP delivery settings updated",
            details={
                "servers_count": len([s for s in (smtp_servers or "").split(",") if s.strip()]),
                "anonymous": anonymous,
                "security": smtp_security,
            },
        )
    return render_settings(
        request, user, "system_settings", message="SMTP delivery settings saved.", section=redirect_section
    )


@app.post("/settings/system/ssl", response_class=HTMLResponse, include_in_schema=False)
def settings_update_ssl(
    request: Request,
    ssl_enabled: Optional[str] = Form(None),
    redirect_section: str = Form("ssl_certificate"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    desired = ssl_enabled is not None
    with SessionLocal() as db:
        if desired and not cert_exists():
            _emit_ssl_audit(
                db,
                action="toggled",
                user=user,
                status="error",
                message="SSL enable rejected: no certificate installed",
                details={"ssl_enabled": desired},
            )
            return render_settings(
                request,
                user,
                "system_settings",
                message=(
                    "Cannot enable SSL: no certificate is installed. Upload a PEM certificate "
                    "or create a self-signed certificate first."
                ),
                message_kind="error",
                section=redirect_section,
            )
        previous = is_ssl_enabled(db)
        set_ssl_enabled(db, desired)
        if desired != previous:
            mark_restart_required(db, reason="SSL listener setting changed.")
        _emit_ssl_audit(
            db,
            action="toggled",
            user=user,
            message=f"SSL listener {'enabled' if desired else 'disabled'} (restart required)",
            details={"ssl_enabled": desired, "previous": previous, "changed": desired != previous},
        )
    return render_settings(
        request,
        user,
        "system_settings",
        message=(
            "SSL setting saved. Restart the application for the change to take effect."
        ),
        message_kind="warning",
        section=redirect_section,
    )


@app.post("/settings/system/ssl-upload", response_class=HTMLResponse, include_in_schema=False)
async def settings_upload_ssl(
    request: Request,
    ssl_key: UploadFile = File(...),
    ssl_cert: UploadFile = File(...),
    redirect_section: str = Form("ssl_certificate"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    try:
        key_bytes = await ssl_key.read()
        cert_bytes = await ssl_cert.read()
    except Exception as exc:  # noqa: BLE001 — UploadFile.read failures are surfaced verbatim
        with SessionLocal() as db:
            _emit_ssl_audit(
                db,
                action="upload_failed",
                user=user,
                status="error",
                message=f"SSL certificate upload failed: {exc}",
                details={"reason": str(exc)},
            )
        return render_settings(
            request,
            user,
            "system_settings",
            message=f"Failed to read upload: {exc}",
            message_kind="error",
            section=redirect_section,
        )

    try:
        metadata = install_uploaded_cert(key_bytes, cert_bytes)
    except CertificateInstallError as exc:
        with SessionLocal() as db:
            _emit_ssl_audit(
                db,
                action="upload_failed",
                user=user,
                status="error",
                message=f"SSL certificate upload rejected: {exc}",
                details={"reason": str(exc)},
            )
        return render_settings(
            request,
            user,
            "system_settings",
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )

    with SessionLocal() as db:
        mark_restart_required(db, reason="SSL certificate uploaded.")
        _emit_ssl_audit(
            db,
            action="uploaded",
            user=user,
            message=f"SSL certificate uploaded (CN={metadata.get('common_name') or 'unknown'})",
            details={
                "common_name": metadata.get("common_name") or "",
                "not_after": metadata.get("not_after_iso") or "",
                "fingerprint": metadata.get("fingerprint") or "",
            },
        )
    return render_settings(
        request,
        user,
        "system_settings",
        message=(
            "SSL certificate uploaded. Restart the application for the new certificate to take effect."
        ),
        message_kind="warning",
        section=redirect_section,
    )


@app.post("/settings/system/ssl-regenerate", response_class=HTMLResponse, include_in_schema=False)
def settings_regenerate_ssl(
    request: Request,
    redirect_section: str = Form("ssl_certificate"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    already_existed = cert_exists()
    user_message = ""
    try:
        with SessionLocal() as db:
            if already_existed:
                metadata = regenerate_self_signed_cert(db)
                action = "regenerated"
                user_message = "Self-signed certificate regenerated."
            else:
                metadata = create_self_signed_cert(db)
                action = "created"
                user_message = "Self-signed certificate created."
            mark_restart_required(db, reason=user_message)
            _emit_ssl_audit(
                db,
                action=action,
                user=user,
                message=f"{user_message} (CN={metadata.get('common_name') or 'unknown'})",
                details={
                    "common_name": metadata.get("common_name") or "",
                    "not_after": metadata.get("not_after_iso") or "",
                    "fingerprint": metadata.get("fingerprint") or "",
                    "source": metadata.get("source") or "",
                },
            )
    except OpenSSLUnavailableError as exc:
        with SessionLocal() as db:
            _emit_ssl_audit(
                db,
                action="regenerate_failed",
                user=user,
                status="error",
                message=f"Self-signed certificate generation failed: {exc}",
                details={"reason": str(exc)},
            )
        return render_settings(
            request,
            user,
            "system_settings",
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )
    except RuntimeError as exc:
        with SessionLocal() as db:
            _emit_ssl_audit(
                db,
                action="regenerate_failed",
                user=user,
                status="error",
                message=f"Self-signed certificate generation failed: {exc}",
                details={"reason": str(exc)},
            )
        return render_settings(
            request,
            user,
            "system_settings",
            message=f"Failed to generate self-signed certificate: {exc}",
            message_kind="error",
            section=redirect_section,
        )

    return render_settings(
        request,
        user,
        "system_settings",
        message=(
            f"{user_message} Restart the application for the new certificate to take effect."
        ),
        message_kind="warning",
        section=redirect_section,
    )


_le_enrollment_in_progress = False


def _emit_ssl_audit(
    db,
    *,
    action: str,
    user: str,
    message: str,
    status: str = "success",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    emit_activity_event(
        db,
        event_type=f"system.ssl_{action}",
        level=LOG_LEVEL_WARNING,
        category=LOG_CATEGORY_SECURITY,
        status=status,
        actor_type="user",
        actor_label=user,
        message=message,
        details=details or {},
    )


def _le_start_form_kwargs(
    *,
    email: str,
    root_dns_domain: str,
    common_name: str,
    subject_alt_names: str,
    challenge_type: str,
    zone_id: str,
    staging: Optional[str],
    renew_before_expiry_days: int,
    scheduled_restart_enabled: Optional[str],
    scheduled_restart_time: str,
) -> Dict[str, Any]:
    return {
        "email": email,
        "root_dns_domain": root_dns_domain,
        "common_name": common_name,
        "subject_alt_names": subject_alt_names,
        "challenge_type": challenge_type,
        "zone_id": int(zone_id) if str(zone_id).strip() else None,
        "staging": staging is not None,
        "renew_before_expiry_days": renew_before_expiry_days,
        "scheduled_restart_enabled": (
            True if scheduled_restart_enabled is None else scheduled_restart_enabled is not None
        ),
        "scheduled_restart_time": scheduled_restart_time,
    }


def _le_issued_message(db, config: Dict[str, Any]) -> str:
    message = "Let's Encrypt certificate installed. Restart the application to use it."
    message += letsencrypt.http_auto_renew_notice(db, config)
    return message


def _apply_le_start_result(db, result: Dict[str, Any], *, user: str) -> tuple[str, str]:
    if result.get("status") == "issued":
        mark_restart_required(db, reason="Let's Encrypt certificate installed.")
        config = result.get("config") or {}
        return (_le_issued_message(db, config), "warning")
    return (
        "Let's Encrypt enrollment started. Complete the challenge, then continue enrollment.",
        "success",
    )


def _emit_le_started(db, result: Dict[str, Any], *, user: str) -> None:
    config = result.get("config") or {}
    _emit_ssl_audit(
        db,
        action="letsencrypt_start",
        user=user,
        message="Let's Encrypt enrollment started",
        details={
            "root_dns_domain": config.get("root_dns_domain", ""),
            "common_name": config.get("common_name", ""),
            "subject_alt_names": config.get("subject_alt_names", []),
            "zone_id": config.get("zone_id"),
            "challenge_type": config.get("challenge_type", ""),
        },
    )


def _run_le_auto_enrollment_sync(kwargs: Dict[str, Any], *, user: str) -> None:
    def progress(phase: str, percent: int, message: str) -> None:
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase=phase,
                percent=percent,
                message=message,
            )

    try:
        with SessionLocal() as db:
            result = letsencrypt.start_enrollment(db, progress_cb=progress, **kwargs)
            message, _kind = _apply_le_start_result(db, result, user=user)
            _emit_le_started(db, result, user=user)
            status = result.get("status") or ""
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase="complete",
                percent=100,
                message=message,
                done=True,
                result_status=status,
            )
    except letsencrypt.LetsEncryptError as exc:
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase="error",
                percent=0,
                message=str(exc),
                done=True,
                error=str(exc),
            )
    except Exception as exc:
        LOGGER.exception("Let's Encrypt auto enrollment failed")
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase="error",
                percent=0,
                message=str(exc),
                done=True,
                error=str(exc),
            )


async def _run_le_auto_enrollment(kwargs: Dict[str, Any], *, user: str) -> None:
    global _le_enrollment_in_progress
    try:
        await asyncio.to_thread(_run_le_auto_enrollment_sync, kwargs, user=user)
    finally:
        _le_enrollment_in_progress = False


@app.get("/settings/system/ssl-letsencrypt/progress", include_in_schema=False)
def settings_letsencrypt_progress(user: str = Depends(require_role(ROLE_SYSTEM_UPDATE))):
    with SessionLocal() as db:
        payload = letsencrypt.get_enrollment_progress(db)
        if payload.get("done") and not payload.get("error"):
            payload["restart_required"] = is_restart_required(db)
        return JSONResponse(payload)


@app.post("/settings/system/ssl-letsencrypt/start-async", include_in_schema=False)
async def settings_letsencrypt_start_async(
    request: Request,
    email: str = Form(...),
    root_dns_domain: str = Form(...),
    common_name: str = Form(...),
    subject_alt_names: str = Form(""),
    challenge_type: str = Form("dns-01"),
    zone_id: str = Form(""),
    staging: Optional[str] = Form(None),
    renew_before_expiry_days: int = Form(letsencrypt.DEFAULT_RENEW_BEFORE_DAYS),
    scheduled_restart_enabled: Optional[str] = Form(None),
    scheduled_restart_time: str = Form(letsencrypt.DEFAULT_SCHEDULED_RESTART_TIME),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    global _le_enrollment_in_progress
    if challenge_type != letsencrypt.CHALLENGE_DNS or not str(zone_id).strip():
        with SessionLocal() as db:
            _emit_ssl_audit(
                db,
                action="letsencrypt_start_failed",
                user=user,
                status="error",
                message="Let's Encrypt async enrollment rejected: DNS-01 with API zone required",
                details={"challenge_type": challenge_type, "zone_id": zone_id},
            )
        return JSONResponse(
            {"detail": "Async enrollment requires DNS-01 with an API configured zone."},
            status_code=400,
        )
    if _le_enrollment_in_progress:
        with SessionLocal() as db:
            _emit_ssl_audit(
                db,
                action="letsencrypt_start_failed",
                user=user,
                status="error",
                message="Let's Encrypt async enrollment rejected: already in progress",
            )
        return JSONResponse({"detail": "Let's Encrypt enrollment is already in progress."}, status_code=HTTP_409_CONFLICT)
    kwargs = _le_start_form_kwargs(
        email=email,
        root_dns_domain=root_dns_domain,
        common_name=common_name,
        subject_alt_names=subject_alt_names,
        challenge_type=challenge_type,
        zone_id=zone_id,
        staging=staging,
        renew_before_expiry_days=renew_before_expiry_days,
        scheduled_restart_enabled=scheduled_restart_enabled,
        scheduled_restart_time=scheduled_restart_time,
    )
    with SessionLocal() as db:
        letsencrypt.clear_enrollment_progress(db)
        letsencrypt.write_enrollment_progress(
            db,
            phase="starting",
            percent=0,
            message="Starting enrollment...",
        )
    _le_enrollment_in_progress = True
    with SessionLocal() as db:
        _emit_ssl_audit(
            db,
            action="letsencrypt_start_async",
            user=user,
            message="Let's Encrypt async enrollment started",
            details={
                "root_dns_domain": kwargs.get("root_dns_domain", ""),
                "common_name": kwargs.get("common_name", ""),
                "zone_id": kwargs.get("zone_id"),
                "challenge_type": kwargs.get("challenge_type", ""),
            },
        )
    asyncio.create_task(_run_le_auto_enrollment(kwargs, user=user))
    return JSONResponse({"status": "started"}, status_code=HTTP_202_ACCEPTED)


@app.post("/settings/system/ssl-letsencrypt/start", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_start(
    request: Request,
    email: str = Form(...),
    root_dns_domain: str = Form(...),
    common_name: str = Form(...),
    subject_alt_names: str = Form(""),
    challenge_type: str = Form("dns-01"),
    zone_id: str = Form(""),
    staging: Optional[str] = Form(None),
    renew_before_expiry_days: int = Form(letsencrypt.DEFAULT_RENEW_BEFORE_DAYS),
    scheduled_restart_enabled: Optional[str] = Form(None),
    scheduled_restart_time: str = Form(letsencrypt.DEFAULT_SCHEDULED_RESTART_TIME),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    try:
        kwargs = _le_start_form_kwargs(
            email=email,
            root_dns_domain=root_dns_domain,
            common_name=common_name,
            subject_alt_names=subject_alt_names,
            challenge_type=challenge_type,
            zone_id=zone_id,
            staging=staging,
            renew_before_expiry_days=renew_before_expiry_days,
            scheduled_restart_enabled=scheduled_restart_enabled,
            scheduled_restart_time=scheduled_restart_time,
        )
        with SessionLocal() as db:
            result = letsencrypt.start_enrollment(db, **kwargs)
            message, kind = _apply_le_start_result(db, result, user=user)
            _emit_le_started(db, result, user=user)
    except LetsEncryptError as exc:
        return render_settings(request, user, "system_settings", message=str(exc), message_kind="error", section="ssl_certificate")
    return render_settings(request, user, "system_settings", message=message, message_kind=kind, section="ssl_certificate")


@app.post("/settings/system/ssl-letsencrypt/continue", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_continue(request: Request, user: str = Depends(require_role(ROLE_SYSTEM_UPDATE))):
    try:
        with SessionLocal() as db:
            result = letsencrypt.continue_enrollment(db)
            config = result.get("config") or {}
            mark_restart_required(db, reason="Let's Encrypt certificate installed.")
            _emit_ssl_audit(
                db,
                action="letsencrypt_continue",
                user=user,
                message="Let's Encrypt certificate installed",
                details={
                    "root_dns_domain": config.get("root_dns_domain", ""),
                    "common_name": config.get("common_name", ""),
                    "subject_alt_names": config.get("subject_alt_names", []),
                },
            )
    except LetsEncryptError as exc:
        return render_settings(request, user, "system_settings", message=str(exc), message_kind="error", section="ssl_certificate")
    with SessionLocal() as db:
        issued_message = _le_issued_message(db, config)
    return render_settings(
        request,
        user,
        "system_settings",
        message=issued_message,
        message_kind="warning",
        section="ssl_certificate",
    )


@app.post("/settings/system/ssl-letsencrypt/cancel", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_cancel(request: Request, user: str = Depends(require_role(ROLE_SYSTEM_UPDATE))):
    with SessionLocal() as db:
        letsencrypt.cancel_enrollment(db)
        _emit_ssl_audit(db, action="letsencrypt_cancel", user=user, message="Let's Encrypt enrollment cancelled")
    return render_settings(request, user, "system_settings", message="Let's Encrypt enrollment cancelled.", section="ssl_certificate")


@app.post("/settings/system/ssl-letsencrypt/config", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_config(
    request: Request,
    email: str = Form(""),
    root_dns_domain: str = Form(""),
    common_name: str = Form(""),
    subject_alt_names: str = Form(""),
    challenge_type: str = Form("dns-01"),
    zone_id: str = Form(""),
    staging: Optional[str] = Form(None),
    renew_before_expiry_days: int = Form(letsencrypt.DEFAULT_RENEW_BEFORE_DAYS),
    scheduled_restart_enabled: Optional[str] = Form(None),
    scheduled_restart_time: str = Form(letsencrypt.DEFAULT_SCHEDULED_RESTART_TIME),
    auto_renew_enabled: Optional[str] = Form(None),
    config_notice: str = Form(""),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    notice = (config_notice or "").strip()
    try:
        with SessionLocal() as db:
            existing = letsencrypt.get_config(db) or {}
            challenge = challenge_type or existing.get("challenge_type", letsencrypt.CHALLENGE_DNS)
            zone_id_val = int(zone_id) if str(zone_id).strip() else existing.get("zone_id")
            if challenge == letsencrypt.CHALLENGE_HTTP:
                zone_id_val = None
            if notice == "auto_renew_on" and not letsencrypt.auto_renew_supported(challenge, zone_id_val):
                raise LetsEncryptError(
                    "Automatic certificate renewal requires an automated DNS challenge zone "
                    "(not Manual DNS instructions)."
                )
            letsencrypt.save_config(
                db,
                email=email or existing.get("email", ""),
                root_dns_domain=root_dns_domain or existing.get("root_dns_domain", ""),
                common_name=common_name or existing.get("common_name", ""),
                subject_alt_names=subject_alt_names or existing.get("subject_alt_names", []),
                challenge_type=challenge_type or existing.get("challenge_type", "dns-01"),
                zone_id=int(zone_id) if str(zone_id).strip() else existing.get("zone_id"),
                staging=staging is not None,
                renew_before_expiry_days=renew_before_expiry_days,
                scheduled_restart_enabled=scheduled_restart_enabled is not None,
                scheduled_restart_time=scheduled_restart_time,
                auto_renew_enabled=auto_renew_enabled is not None,
            )
            _emit_ssl_audit(
                db,
                action="letsencrypt_config",
                user=user,
                message="Let's Encrypt settings saved",
                details={"config_notice": notice, "auto_renew_enabled": auto_renew_enabled is not None},
            )
    except LetsEncryptError as exc:
        return render_settings(request, user, "system_settings", message=str(exc), message_kind="error", section="ssl_certificate")
    if notice == "auto_renew_on":
        message = "Automatic certificate renewal was turned on."
    elif notice == "auto_renew_off":
        message = "Automatic certificate renewal was turned off."
    else:
        message = "Let's Encrypt settings saved."
    return render_settings(request, user, "system_settings", message=message, section="ssl_certificate")


@app.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse, include_in_schema=False)
def letsencrypt_http_challenge(token: str):
    with SessionLocal() as db:
        response = letsencrypt.http_challenge_response(db, token)
    if response is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Challenge token not found")
    return PlainTextResponse(response)


@app.post("/system/restart", include_in_schema=False)
def system_restart(request: Request, user: str = Depends(require_role(ROLE_SYSTEM_UPDATE))):
    with SessionLocal() as db:
        preview = nav_context(db, user).get("restart_preview", {})
        clear_restart_required(db)
        emit_activity_event(
            db,
            event_type="system.restart_requested",
            level=LOG_LEVEL_WARNING,
            status="success",
            actor_type="user",
            actor_label=user,
            message="Application restart requested",
            details=preview,
        )
    perform_application_restart(scheduled=False)
    if wants_json_response(request):
        return JSONResponse({"status": "restarting", **preview})
    return RedirectResponse(url=request.headers.get("referer") or "/admin", status_code=HTTP_303_SEE_OTHER)


@app.post("/settings/system/log-rotation", response_class=HTMLResponse, include_in_schema=False)
def settings_update_log_rotation(
    request: Request,
    log_file: str = Form(""),
    max_bytes: int = Form(1_048_576),
    backup_count: int = Form(5),
    redirect_section: str = Form("operational_log_rotation"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    if is_running_in_docker():
        return render_settings(
            request,
            user,
            "system_settings",
            message="Operational log rotation is managed by Docker in container deployments.",
            message_kind="error",
            section=redirect_section,
        )
    with SessionLocal() as db:
        set_setting(db, activity_logging.SETTING_LOG_FILE, log_file or "")
        set_setting(db, activity_logging.SETTING_LOG_MAX_BYTES, str(max(1024, int(max_bytes))))
        set_setting(db, activity_logging.SETTING_LOG_BACKUP_COUNT, str(max(0, int(backup_count))))
        configure_operational_logging(
            level=get_log_level(db),
            log_file=log_file or None,
            max_bytes=max(1024, int(max_bytes)),
            backup_count=max(0, int(backup_count)),
        )
        emit_activity_event(
            db,
            event_type="system.log_rotation_updated",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message="Operational log rotation updated",
            details={
                "log_file_configured": bool(log_file),
                "max_bytes": max(1024, int(max_bytes)),
                "backup_count": max(0, int(backup_count)),
            },
        )
    return render_settings(
        request,
        user,
        "system_settings",
        message="Operational log rotation saved.",
        section=redirect_section,
    )


@app.post("/settings/alerts", response_class=HTMLResponse, include_in_schema=False)
def settings_alerts_create(
    request: Request,
    name: str = Form(...),
    event_type: str = Form(""),
    category: str = Form(""),
    minimum_level: str = Form(LOG_LEVEL_WARNING),
    message_contains: str = Form(""),
    email_recipients: str = Form(...),
    email_subject_template: str = Form(""),
    email_body_template: str = Form(""),
    cooldown_minutes: int = Form(0),
    enabled: Optional[str] = Form("on"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    cleaned_level = (minimum_level or LOG_LEVEL_WARNING).strip().upper()
    if cleaned_level not in LOG_LEVEL_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported level: {minimum_level}", message_kind="error"
        )
    cleaned_category = (category or "").strip().lower()
    if cleaned_category and cleaned_category not in LOG_CATEGORY_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported category: {category}", message_kind="error"
        )
    if not email_recipients.strip():
        return render_settings(
            request, user, "email_alerting", message="At least one email recipient is required.", message_kind="error"
        )
    with SessionLocal() as db:
        rule = AlertRule(
            enabled=bool(enabled),
            name=name.strip(),
            event_type=event_type.strip() or None,
            category=cleaned_category or None,
            minimum_level=cleaned_level,
            message_contains=message_contains.strip() or None,
            email_recipients=email_recipients.strip(),
            email_subject_template=email_subject_template,
            email_body_template=email_body_template,
            cooldown_minutes=max(0, int(cooldown_minutes)),
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        emit_activity_event(
            db,
            event_type="alert_rule.created",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Alert rule {name!r} created",
            details={"rule_id": rule.id, "rule_name": rule.name, "category": cleaned_category, "minimum_level": cleaned_level},
        )
    return render_settings(request, user, "email_alerting", message=f"Alert rule {name!r} created.")


@app.post("/settings/alerts/{rule_id}", response_class=HTMLResponse, include_in_schema=False)
def settings_alerts_update(
    request: Request,
    rule_id: int,
    name: str = Form(...),
    event_type: str = Form(""),
    category: str = Form(""),
    minimum_level: str = Form(LOG_LEVEL_WARNING),
    message_contains: str = Form(""),
    email_recipients: str = Form(...),
    email_subject_template: str = Form(""),
    email_body_template: str = Form(""),
    cooldown_minutes: int = Form(0),
    enabled: Optional[str] = Form(None),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    cleaned_level = (minimum_level or LOG_LEVEL_WARNING).strip().upper()
    if cleaned_level not in LOG_LEVEL_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported level: {minimum_level}", message_kind="error"
        )
    cleaned_category = (category or "").strip().lower()
    if cleaned_category and cleaned_category not in LOG_CATEGORY_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported category: {category}", message_kind="error"
        )
    with SessionLocal() as db:
        rule = db.get(AlertRule, rule_id)
        if rule is None:
            return render_settings(
                request, user, "email_alerting", message="Alert rule not found.", message_kind="error"
            )
        rule.enabled = enabled is not None
        rule.name = name.strip()
        rule.event_type = event_type.strip() or None
        rule.category = cleaned_category or None
        rule.minimum_level = cleaned_level
        rule.message_contains = message_contains.strip() or None
        rule.email_recipients = email_recipients.strip()
        rule.email_subject_template = email_subject_template
        rule.email_body_template = email_body_template
        rule.cooldown_minutes = max(0, int(cooldown_minutes))
        db.add(rule)
        db.commit()
        emit_activity_event(
            db,
            event_type="alert_rule.updated",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Alert rule {name!r} updated",
            details={"rule_id": rule_id, "rule_name": rule.name, "category": cleaned_category, "minimum_level": cleaned_level},
        )
    return render_settings(request, user, "email_alerting", message=f"Alert rule {name!r} updated.")


@app.post("/settings/alerts/{rule_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def settings_alerts_delete(
    request: Request,
    rule_id: int,
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    with SessionLocal() as db:
        rule = db.get(AlertRule, rule_id)
        if rule is None:
            return render_settings(
                request, user, "email_alerting", message="Alert rule not found.", message_kind="error"
            )
        rule_name = rule.name
        db.delete(rule)
        db.commit()
        emit_activity_event(
            db,
            event_type="alert_rule.deleted",
            level=LOG_LEVEL_WARNING,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Alert rule {rule_name!r} deleted",
            details={"rule_id": rule_id, "rule_name": rule_name},
        )
    return render_settings(request, user, "email_alerting", message=f"Alert rule {rule_name!r} deleted.")


@app.get(
    "/dns-record",
    response_model=DnsRecordGetResponse,
    summary="Look up DNS records",
    description=(
        "Return records at a name in a configured zone as a ``records`` array. "
        "Each found record includes ``record_name``, ``record_type``, ``ttl``, and ``values`` when "
        "returned by the provider. Optional ``record_type`` filters which types appear in the array. "
        "Requires a valid API key with access to the zone."
    ),
    responses={
        400: {"description": "Invalid request, record type, or zone configuration."},
        401: {"description": "API key is missing or invalid."},
        403: {"description": "API key is not allowed to use this zone, or the zone is not configured."},
        502: {"description": "DNS provider reported a failure (e.g. WinRM or dynamic update)."},
        503: {"description": "A required component is not installed or misconfigured."},
    },
)
def get_dns_record(
    zone_name: str = Query(..., description="DNS zone name. Must match a configured zone allowed for this API key."),
    record_name: str = Query(..., description="Record name relative to the zone, e.g. www or @"),
    record_type: Optional[str] = Query(
        None,
        description="Optional DNS record type: A, AAAA, CNAME, or TXT. Omit to return all supported types at the name.",
    ),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)

    if not api_key:
        record_activity(
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            message="API key missing on GET /dns-record",
        )
        raise HTTPException(status_code=401, detail="API key is required")

    with SessionLocal() as db:
        _key, zone_row, settings, actor_id, actor_label, provider = _resolve_dns_api_zone(
            db,
            api_key=api_key,
            zone_name=zone_name,
            record_name=record_name,
            endpoint="GET /dns-record",
        )
        provider_domain = provider_dns_zone(settings)

        try:
            lookup_type = normalize_lookup_record_type(record_type)
            records = test_zone_record_lookup(
                settings,
                record_name=record_name,
                record_type=lookup_type,
                db=db,
            )
        except ValueError as exc:
            emit_activity_event(
                db,
                event_type="dns.invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=str(exc),
            )
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "message": str(exc)},
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            mapped = http_exception_from_dns_error(exc)
            sanitized_error = sanitize_client_error_message(exc, fallback="DNS provider error")
            emit_activity_event(
                db,
                event_type="dns.provider_failed",
                level=LOG_LEVEL_ERROR,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=sanitized_error,
                details={
                    "provider": provider,
                    "record_type": record_type,
                    "exception_type": type(exc).__name__,
                },
            )
            raise mapped from exc

        status = "success" if records else "not_found"
        message = (
            f"Found {len(records)} record(s) at {record_name!r} in zone {provider_domain!r}."
            if records
            else (
                f"No {lookup_type} record found at {record_name!r} in zone {provider_domain!r}."
                if lookup_type
                else f"No A, AAAA, CNAME, or TXT records found at {record_name!r} in zone {provider_domain!r}."
            )
        )
        emit_activity_event(
            db,
            event_type="dns.record_lookup",
            level=LOG_LEVEL_INFORMATIONAL,
            status=status,
            actor_type="api_key",
            actor_id=actor_id,
            actor_label=actor_label,
            zone_name=zone_row.zone_name,
            record_name=record_name,
            message=message,
            details={
                "provider": provider,
                "record_type": record_type,
                "records_found": len(records),
            },
        )
        return DnsRecordGetResponse(
            status=status,
            zone_name=zone_row.zone_name,
            dns_zone=provider_domain,
            record_name=record_name,
            records=records,
        )


_MUTATION_RESPONSES: Dict[int, Dict[str, Any]] = {
    400: {"description": "Invalid request, record type, or configuration."},
    401: {"description": "API key is missing or invalid."},
    403: {"description": "API key is not allowed to use this zone, or the zone is not configured."},
    502: {"description": "DNS provider reported a failure (e.g. WinRM or dynamic update)."},
    503: {"description": "A required component is not installed or misconfigured."},
}


def _record_exists_at_type(
    client,
    *,
    settings: Dict[str, Any],
    record_name: str,
    record_type: str,
) -> bool:
    """Return True if the DNS provider reports any record of *record_type* at *record_name*."""

    records = client.get_record(
        record_name=record_name,
        record_type=record_type,
        dns_server=settings.get("dns_server"),
        dns_zone=provider_dns_zone(settings),
    )
    return bool(records)


def _apply_dns_mutation(
    *,
    api_key: Optional[str],
    zone_name: Optional[str],
    record_name: str,
    record_type: str,
    ttl: Optional[int],
    values: List[str],
    mode: Literal["create", "replace", "patch", "delete"],
    endpoint: str,
    patch_ttl: Optional[int] = None,
    patch_values: Optional[List[str]] = None,
):
    """Shared pre-check + mutation flow for POST/PUT/PATCH/DELETE on ``/dns-record``."""

    if not api_key:
        record_activity(
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            message=f"API key missing on {endpoint}",
        )
        raise HTTPException(status_code=401, detail="API key is required")

    rt_upper = (record_type or "").strip().upper()

    with SessionLocal() as db:
        _key, zone_row, settings, actor_id, actor_label, provider = _resolve_dns_api_zone(
            db,
            api_key=api_key,
            zone_name=zone_name or "",
            record_name=record_name,
            endpoint=endpoint,
        )

        try:
            if provider in get_disabled_dns_plugins(db):
                raise DnsProviderDisabledError(
                    f"{dns_provider_display_name(provider)} is disabled. "
                    "Enable it in Settings before using it for DNS operations."
                )
            client = get_dns_client_from_settings(settings)
            provider_domain = provider_dns_zone(settings)

            if mode == "patch":
                records = client.get_record(
                    record_name=record_name,
                    record_type=rt_upper,
                    dns_server=settings.get("dns_server"),
                    dns_zone=provider_domain,
                )
                if not records:
                    body = DnsRecordResponse(
                        status="error",
                        action="not_found",
                        zone_name=zone_row.zone_name,
                        dns_zone=provider_domain,
                        record_name=record_name,
                        record_type=rt_upper,
                        values=list(patch_values or []),
                    )
                    emit_activity_event(
                        db,
                        event_type="dns.record_not_found",
                        level=LOG_LEVEL_WARNING,
                        status="error",
                        actor_type="api_key",
                        actor_id=actor_id,
                        actor_label=actor_label,
                        zone_name=zone_row.zone_name,
                        record_name=record_name,
                        message=f"DNS record {record_name}.{provider_domain} {rt_upper} not found",
                        details={"record_type": rt_upper, "provider": provider},
                    )
                    return JSONResponse(status_code=HTTP_404_NOT_FOUND, content=body.model_dump())

                existing = records[0]
                if existing.ttl is None or not existing.values:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "error": "dns_provider_failed",
                            "message": "Could not read existing TTL and values for PATCH merge.",
                        },
                    )
                final_ttl = patch_ttl if patch_ttl is not None else existing.ttl
                final_values = list(patch_values) if patch_values is not None else list(existing.values)
                internal = DnsRecordRequest(
                    zone_name=zone_row.zone_name,
                    record_type=rt_upper,
                    record_name=record_name,
                    ttl=final_ttl,
                    values=final_values,
                )
                client.create_or_update_record(
                    internal,
                    dns_server=settings.get("dns_server"),
                    dns_zone=provider_domain,
                )
                body = DnsRecordResponse(
                    status="success",
                    action="updated",
                    zone_name=zone_row.zone_name,
                    dns_zone=provider_domain,
                    record_name=record_name,
                    record_type=rt_upper,
                    values=final_values,
                )
                emit_activity_event(
                    db,
                    event_type="dns.record_updated",
                    level=LOG_LEVEL_INFORMATIONAL,
                    status="success",
                    actor_type="api_key",
                    actor_id=actor_id,
                    actor_label=actor_label,
                    zone_name=zone_row.zone_name,
                    record_name=record_name,
                    message=f"DNS record {record_name}.{provider_domain} updated",
                    details={
                        "record_type": rt_upper,
                        "values_count": len(final_values),
                        "provider": provider,
                    },
                )
                return body

            exists = _record_exists_at_type(
                client,
                settings=settings,
                record_name=record_name,
                record_type=rt_upper,
            )

            if mode == "create" and exists:
                body = DnsRecordResponse(
                    status="error",
                    action="record_already_exists",
                    zone_name=zone_row.zone_name,
                    dns_zone=provider_domain,
                    record_name=record_name,
                    record_type=rt_upper,
                    values=list(values),
                )
                emit_activity_event(
                    db,
                    event_type="dns.record_already_exists",
                    level=LOG_LEVEL_WARNING,
                    status="error",
                    actor_type="api_key",
                    actor_id=actor_id,
                    actor_label=actor_label,
                    zone_name=zone_row.zone_name,
                    record_name=record_name,
                    message=f"DNS record {record_name}.{provider_domain} {rt_upper} already exists",
                    details={"record_type": rt_upper, "provider": provider},
                )
                return JSONResponse(status_code=HTTP_409_CONFLICT, content=body.model_dump())

            if mode in ("replace", "delete") and not exists:
                body = DnsRecordResponse(
                    status="error",
                    action="not_found",
                    zone_name=zone_row.zone_name,
                    dns_zone=provider_domain,
                    record_name=record_name,
                    record_type=rt_upper,
                    values=[] if mode == "delete" else list(values),
                )
                emit_activity_event(
                    db,
                    event_type="dns.record_not_found",
                    level=LOG_LEVEL_WARNING,
                    status="error",
                    actor_type="api_key",
                    actor_id=actor_id,
                    actor_label=actor_label,
                    zone_name=zone_row.zone_name,
                    record_name=record_name,
                    message=f"DNS record {record_name}.{provider_domain} {rt_upper} not found",
                    details={"record_type": rt_upper, "provider": provider},
                )
                return JSONResponse(status_code=HTTP_404_NOT_FOUND, content=body.model_dump())

            if mode == "delete":
                internal = DnsRecordRequest(
                    zone_name=zone_row.zone_name,
                    record_type="DELETE",
                    record_name=record_name,
                    ttl=ttl or 300,
                    values=[rt_upper],
                )
            else:
                internal = DnsRecordRequest(
                    zone_name=zone_row.zone_name,
                    record_type=rt_upper,
                    record_name=record_name,
                    ttl=ttl if ttl is not None else 300,
                    values=list(values),
                )

            client.create_or_update_record(
                internal,
                dns_server=settings.get("dns_server"),
                dns_zone=provider_domain,
            )

            action = {
                "create": "created",
                "replace": "updated",
                "patch": "updated",
                "delete": "deleted",
            }[mode]
            response_values: List[str] = [] if mode == "delete" else list(values)
            body = DnsRecordResponse(
                status="success",
                action=action,
                zone_name=zone_row.zone_name,
                dns_zone=provider_domain,
                record_name=record_name,
                record_type=rt_upper,
                values=response_values,
            )
            emit_activity_event(
                db,
                event_type=f"dns.record_{action}",
                level=LOG_LEVEL_INFORMATIONAL,
                status="success",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=f"DNS record {record_name}.{provider_domain} {action}",
                details={
                    "record_type": rt_upper,
                    "values_count": len(values),
                    "provider": provider,
                },
            )
            return body
        except HTTPException:
            raise
        except Exception as exc:
            mapped = http_exception_from_dns_error(exc)
            sanitized_error = sanitize_client_error_message(exc, fallback="DNS provider error")
            emit_activity_event(
                db,
                event_type="dns.provider_failed",
                level=LOG_LEVEL_ERROR,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=zone_row.zone_name,
                record_name=record_name,
                message=sanitized_error,
                details={
                    "provider": provider,
                    "record_type": rt_upper,
                    "exception_type": type(exc).__name__,
                },
            )
            raise mapped from exc


@app.post(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Create a DNS record",
    description=(
        "Create a new DNS record of the given type. "
        "Pre-checks the zone with ``get_record`` and returns **409** "
        "``record_already_exists`` if a record of that type is already present at the name."
    ),
    responses={
        HTTP_409_CONFLICT: {
            "description": "A record of this type already exists at this name.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def create_dns_record(
    payload: DnsRecordCreateRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=payload.zone_name,
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=payload.ttl,
        values=payload.values,
        mode="create",
        endpoint="POST /dns-record",
    )


@app.put(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Replace a DNS record (full update)",
    description=(
        "Replace the record's type, TTL, and values. "
        "Pre-checks with ``get_record`` and returns **404** ``not_found`` if no record "
        "of the given type exists at the name."
    ),
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "No matching record exists at this name and type.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def replace_dns_record(
    payload: DnsRecordReplaceRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=payload.zone_name,
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=payload.ttl,
        values=payload.values,
        mode="replace",
        endpoint="PUT /dns-record",
    )


@app.patch(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Update a DNS record (partial update)",
    description=(
        "Update ``ttl`` and/or ``values`` on an existing record. Omitted fields are preserved "
        "from the live record (via ``get_record``). Returns **404** ``not_found`` if no record "
        "of the given type exists at the name."
    ),
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "No matching record exists at this name and type.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def patch_dns_record(
    payload: DnsRecordPatchRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=payload.zone_name,
        record_name=payload.record_name,
        record_type=payload.record_type,
        ttl=None,
        values=[],
        mode="patch",
        endpoint="PATCH /dns-record",
        patch_ttl=payload.ttl,
        patch_values=payload.values,
    )


@app.delete(
    "/dns-record",
    response_model=DnsRecordResponse,
    summary="Delete a DNS record",
    description=(
        "Delete the record of the given type at the given name. "
        "Identity is taken from query parameters (same as ``GET /dns-record``). "
        "Pre-checks with ``get_record`` and returns **404** ``not_found`` if no record "
        "of the given type exists at the name."
    ),
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "No matching record exists at this name and type.",
            "model": DnsRecordResponse,
        },
        **_MUTATION_RESPONSES,
    },
)
def delete_dns_record(
    zone_name: str = Query(..., description="DNS zone name. Must match a configured zone allowed for this API key."),
    record_name: str = Query(..., description="Record name relative to the zone, e.g. www or @"),
    record_type: str = Query(..., description="DNS record type to remove: A, AAAA, CNAME, or TXT."),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)
    try:
        from .plugins.utils import normalize_lookup_record_type as _normalize

        normalized_type = _normalize(record_type)
        if normalized_type is None:
            raise ValueError("record_type is required.")
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": str(exc)},
        ) from exc
    return _apply_dns_mutation(
        api_key=api_key,
        zone_name=zone_name,
        record_name=record_name,
        record_type=normalized_type,
        ttl=None,
        values=[],
        mode="delete",
        endpoint="DELETE /dns-record",
    )

