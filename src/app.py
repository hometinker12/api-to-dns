import html
import json
import os
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from starlette.status import HTTP_303_SEE_OTHER, HTTP_404_NOT_FOUND

from . import activity_logging
from .activity_logging import (
    DEFAULT_BODY_TEMPLATE,
    DEFAULT_SUBJECT_TEMPLATE,
    LOGGER,
    configure_operational_logging,
    emit_activity_event,
    evaluate_alert_rules,
    get_log_level,
    get_retention_days,
    get_smtp_config,
    is_running_in_docker,
    query_activity_logs,
    run_retention_cleanup,
    set_log_level,
    set_retention_days,
    set_smtp_config,
    system_identity,
)
from .auth import create_session_cookie, get_current_user, session_cookie_settings
from .db import SessionLocal, init_db
from .models import (
    LOG_CATEGORY_VALUES,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_VALUES,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
    ActivityLog,
    AlertRule,
    ApiKey,
    ApiKeyAllowedZone,
    DnsRecordRequest,
    DnsRecordResponse,
    DnsZoneConfig,
    DnsZoneSummary,
    Setting,
    User,
)
from .security import decrypt_value, encrypt_value, generate_api_key, hash_password, verify_password

ACCESS_DENIED_DETAIL: Dict[str, str] = {
    "error": "access_denied",
    "message": "You do not have access or an invalid key was provided.",
}

ROLE_GLOBAL_ADMIN = "global.admin"
ROLE_GLOBAL_READ = "global.read"
ROLE_ACCOUNT_UPDATE = "account.update"
ROLE_ACCOUNT_RESET_PASSWORD = "account.reset_password"
ROLE_API_KEYS_READ = "api_keys.read"
ROLE_API_KEYS_UPDATE = "api_keys.update"
ROLE_DNS_ZONES_READ = "dns_zones.read"
ROLE_DNS_ZONES_UPDATE = "dns_zones.update"
ROLE_PLUGIN_UPDATE = "plugin.update"
ROLE_SYSTEM_UPDATE = "system.update"

ROLE_DEPENDENCIES: Dict[str, str] = {
    ROLE_API_KEYS_UPDATE: ROLE_API_KEYS_READ,
    ROLE_DNS_ZONES_UPDATE: ROLE_DNS_ZONES_READ,
}
MANDATORY_ROLES: Set[str] = {ROLE_DNS_ZONES_READ}

ALL_ROLES: List[str] = [
    ROLE_GLOBAL_ADMIN,
    ROLE_GLOBAL_READ,
    ROLE_ACCOUNT_UPDATE,
    ROLE_ACCOUNT_RESET_PASSWORD,
    ROLE_API_KEYS_READ,
    ROLE_API_KEYS_UPDATE,
    ROLE_DNS_ZONES_READ,
    ROLE_DNS_ZONES_UPDATE,
    ROLE_PLUGIN_UPDATE,
    ROLE_SYSTEM_UPDATE,
]
LEGACY_DEFAULT_ROLES: Set[str] = set(ALL_ROLES) - {ROLE_GLOBAL_ADMIN}

ROLE_LABELS: List[Dict[str, str]] = [
    {"key": ROLE_GLOBAL_ADMIN, "label": "Global: admin"},
    {"key": ROLE_GLOBAL_READ, "label": "Global: read-only"},
    {"key": ROLE_ACCOUNT_UPDATE, "label": "Account: update"},
    {"key": ROLE_ACCOUNT_RESET_PASSWORD, "label": "Account: reset password"},
    {"key": ROLE_API_KEYS_READ, "label": "API keys: read"},
    {"key": ROLE_API_KEYS_UPDATE, "label": "API keys: update", "requires_role": ROLE_API_KEYS_READ},
    {"key": ROLE_DNS_ZONES_READ, "label": "DNS zones: read", "mandatory": True},
    {"key": ROLE_DNS_ZONES_UPDATE, "label": "DNS zones: update", "requires_role": ROLE_DNS_ZONES_READ},
    {"key": ROLE_PLUGIN_UPDATE, "label": "Plugin management"},
    {"key": ROLE_SYSTEM_UPDATE, "label": "System: update"},
]

SETTINGS_AREAS: List[Dict[str, Any]] = [
    {
        "key": "authentication",
        "label": "Authentication",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_ACCOUNT_UPDATE, ROLE_ACCOUNT_RESET_PASSWORD],
    },
    {
        "key": "plugins",
        "label": "Plugin Management",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_PLUGIN_UPDATE],
    },
    {
        "key": "system_settings",
        "label": "System Settings",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
    {
        "key": "log_viewing",
        "label": "Log Viewing / Searching",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
    {
        "key": "email_alerting",
        "label": "Email Alerting",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
    {
        "key": "backup",
        "label": "System Backup",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
]

LEGACY_SETTINGS_AREA_ALIASES: Dict[str, str] = {
    "logging": "log_viewing",
}

ROLE_FORBIDDEN_DETAIL = "You do not have permission to access this resource."
DISABLED_DNS_PLUGINS_SETTING = "disabled_dns_plugins"

LEGACY_DNS_SETTING_NAMES = [
    "dns_provider_type",
    "dns_server",
    "dns_zone",
    "dns_username",
    "dns_password",
    "dns_tsig_algorithm",
    "dns_winrm_ssl",
    "azure_tenant_id",
    "azure_client_id",
    "azure_client_secret",
    "azure_subscription_id",
    "azure_resource_group",
]

app = FastAPI(
    title="api-to-dns Service",
    description="Create or update DNS records via REST and manage API keys through a protected web UI.",
    version="0.3.4",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="src/static"), name="static")
templates = Jinja2Templates(directory="src/templates")

AUTH_REDIRECT_DETAILS = {"Authentication required", "Invalid or expired session"}
WEB_AUTH_PATH_PREFIXES = (
    "/admin",
    "/zones",
    "/api-keys",
    "/settings",
)


@app.middleware("http")
async def refresh_session_cookie(request: Request, call_next):
    response = await call_next(request)
    session_user = getattr(request.state, "session_user", None)
    if session_user and request.url.path != "/logout" and response.status_code < 400:
        response.set_cookie("session", create_session_cookie(session_user), **session_cookie_settings())
    return response


# Paths that are never useful in the activity log at VERBOSE.
_REQUEST_LOG_IGNORE_PREFIXES = ("/static",)


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
                category="http",
                status="success" if response.status_code < 400 else "error",
                actor_type="user" if session_user else "anonymous",
                actor_label=session_user,
                request_method=request.method,
                request_path=path,
                request_status_code=response.status_code,
                request_ip=_client_ip(request),
                evaluate_alerts=False,
            )
    except Exception:  # pragma: no cover - logging must never break a request
        LOGGER.exception("request activity logging failed")
    return response


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
        return _render_access_denied_response()
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


def _render_access_denied_response() -> HTMLResponse:
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


def _render_error_response(request: Request, error: Exception, status_code: int = 500):
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


def _client_ip(request: Request) -> Optional[str]:
    client = getattr(request, "client", None)
    return client.host if client else None


def _record_activity(**kwargs: Any) -> None:
    """Best-effort activity event with an isolated session."""
    try:
        with SessionLocal() as db:
            emit_activity_event(db, **kwargs)
    except Exception:  # pragma: no cover - logging must never break a request
        LOGGER.exception("emit_activity_event failed for event %s", kwargs.get("event_type"))


def get_dns_client_from_settings(settings: dict):
    """Build a DNS provider client from decrypted zone configuration."""
    from .dns_client import create_dns_client

    return create_dns_client(settings)


def get_dns_provider_options() -> List[dict]:
    from .dns_client import provider_options_for_template

    return provider_options_for_template()


def get_known_dns_provider_keys() -> Set[str]:
    return {plugin["key"] for plugin in get_dns_provider_options()}


def get_dns_provider_label(provider_key: str) -> str:
    from .dns_client import dns_provider_display_name

    return dns_provider_display_name(provider_key)


def wants_json_response(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "").lower() or "application/json" in request.headers.get(
        "content-type", ""
    ).lower()


def api_key_from_headers(x_api_key: Optional[str], authorization: Optional[str]) -> Optional[str]:
    api_key = x_api_key
    if not api_key and authorization:
        prefix = "Bearer "
        if authorization.startswith(prefix):
            api_key = authorization[len(prefix) :].strip()
    return api_key


def _http_exception_from_dns_error(exc: Exception) -> HTTPException:
    """Map provider/configuration errors to HTTP errors with structured detail."""
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, ValueError):
        return HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": str(exc) or "invalid request"},
        )
    if isinstance(exc, RuntimeError):
        return HTTPException(
            status_code=502,
            detail={"error": "dns_provider_failed", "message": str(exc)},
        )
    if isinstance(exc, ImportError):
        return HTTPException(
            status_code=503,
            detail={"error": "dependency_unavailable", "message": str(exc)},
        )
    return HTTPException(
        status_code=500,
        detail={"error": "unexpected", "message": str(exc)},
    )


def get_db():
    with SessionLocal() as db:
        yield db


def _parse_roles(raw: Optional[str]) -> Set[str]:
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def _serialize_roles(roles) -> str:
    cleaned = {r for r in roles if r in ALL_ROLES}
    if ROLE_GLOBAL_ADMIN in cleaned:
        cleaned = set(ALL_ROLES)
    cleaned.update(MANDATORY_ROLES)
    return ",".join(sorted(cleaned))


def normalize_selected_roles(roles) -> List[str]:
    selected = {r for r in roles if r in ALL_ROLES}
    if ROLE_GLOBAL_ADMIN in selected:
        return sorted(ALL_ROLES)
    selected.update(MANDATORY_ROLES)
    for role, required_role in ROLE_DEPENDENCIES.items():
        if role in selected:
            selected.add(required_role)
    return sorted(selected)


def effective_roles(stored_roles: Set[str]) -> Set[str]:
    if ROLE_GLOBAL_ADMIN in stored_roles:
        return set(ALL_ROLES)
    return stored_roles | MANDATORY_ROLES


def get_user_roles(db, username: str) -> Set[str]:
    """Return the role set for `username`."""
    user_row = db.exec(select(User).where(User.username == username)).first()
    if user_row is None:
        return set()
    return effective_roles(_parse_roles(user_row.roles))


def user_has_role(db, username: str, role: str) -> bool:
    roles = get_user_roles(db, username)
    return ROLE_GLOBAL_ADMIN in roles or role in roles or (
        ROLE_GLOBAL_READ in roles and role in {ROLE_API_KEYS_READ, ROLE_DNS_ZONES_READ}
    )


def user_has_any_role(db, username: str, roles) -> bool:
    return any(user_has_role(db, username, role) for role in roles)


def user_is_global_admin(db, username: str) -> bool:
    return ROLE_GLOBAL_ADMIN in get_user_roles(db, username)


def target_is_global_admin(target: User) -> bool:
    return ROLE_GLOBAL_ADMIN in effective_roles(_parse_roles(target.roles))


def global_admin_guard_message(db, actor: str, target: User) -> Optional[str]:
    if target_is_global_admin(target) and not user_is_global_admin(db, actor):
        return "Only a global admin can manage another global admin account."
    return None


def require_role(role: str):
    """FastAPI dependency factory that returns the username when the user has `role`."""

    def _dependency(user: str = Depends(get_current_user)) -> str:
        with SessionLocal() as db:
            if not user_has_role(db, user, role):
                raise HTTPException(status_code=403, detail=ROLE_FORBIDDEN_DETAIL)
        return user

    return _dependency


def user_public_dict(u: User) -> Dict[str, Any]:
    stored_roles = _parse_roles(u.roles)
    display_roles = stored_roles or LEGACY_DEFAULT_ROLES
    effective_display_roles = effective_roles(display_roles)
    return {
        "id": u.id,
        "username": u.username,
        "disabled": u.disabled,
        "roles": sorted(effective_display_roles),
        "stored_roles": sorted(display_roles | MANDATORY_ROLES),
        "is_global_admin": ROLE_GLOBAL_ADMIN in effective_display_roles,
        "has_default_roles": not stored_roles,
    }


def accessible_settings_areas(user_roles: Set[str]) -> List[Dict[str, str]]:
    return [
        area
        for area in SETTINGS_AREAS
        if area["key"] == "authentication" or any(role in user_roles for role in area["required_roles"])
    ]


def normalize_zone_name(zone: str) -> str:
    return zone.strip().rstrip(".").lower()


def get_setting(db, name: str) -> Optional[str]:
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    return decrypt_value(record.value) if record else None


def set_setting(db, name: str, value: str) -> None:
    encrypted = encrypt_value(value)
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    if record:
        record.value = encrypted
    else:
        db.add(Setting(name=name, value=encrypted))
    db.commit()


def delete_setting(db, name: str) -> None:
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    if record:
        db.delete(record)
    db.commit()


def get_disabled_dns_plugins(db) -> Set[str]:
    raw = get_setting(db, DISABLED_DNS_PLUGINS_SETTING)
    if not raw:
        return set()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return set()
    if not isinstance(parsed, list):
        return set()
    known_keys = get_known_dns_provider_keys()
    return {str(key).strip().lower() for key in parsed if str(key).strip().lower() in known_keys}


def set_disabled_dns_plugins(db, plugin_keys) -> None:
    known_keys = get_known_dns_provider_keys()
    cleaned = sorted({str(key).strip().lower() for key in plugin_keys if str(key).strip().lower() in known_keys})
    if cleaned:
        set_setting(db, DISABLED_DNS_PLUGINS_SETTING, json.dumps(cleaned))
    else:
        delete_setting(db, DISABLED_DNS_PLUGINS_SETTING)


def dns_provider_options_with_state(db) -> List[dict]:
    disabled = get_disabled_dns_plugins(db)
    options: List[dict] = []
    for plugin in get_dns_provider_options():
        row = dict(plugin)
        row["enabled"] = row["key"] not in disabled
        row["disabled"] = not row["enabled"]
        options.append(row)
    return options


def enabled_dns_provider_options(db) -> List[dict]:
    return [plugin for plugin in dns_provider_options_with_state(db) if plugin["enabled"]]


def zones_using_dns_provider(db, provider_key: str) -> List[str]:
    matches: List[str] = []
    for zone in list_dns_zones(db):
        settings = decode_zone_config(zone)
        provider = (settings.get("dns_provider_type") or "azure").strip().lower()
        if provider == provider_key:
            matches.append(zone.zone_name)
    return matches


def decode_zone_config(row: DnsZoneConfig) -> Dict[str, Any]:
    raw = decrypt_value(row.encrypted_config)
    return json.loads(raw)


def encode_zone_config_dict(cfg: Dict[str, Any]) -> str:
    return encrypt_value(json.dumps(cfg))


def migrate_legacy_dns_settings_if_needed(db) -> None:
    if db.exec(select(DnsZoneConfig)).first():
        return
    zone_raw = get_setting(db, "dns_zone")
    if not zone_raw or not str(zone_raw).strip():
        return
    canonical = normalize_zone_name(zone_raw)
    cfg = {
        "dns_provider_type": get_setting(db, "dns_provider_type") or "azure",
        "dns_server": get_setting(db, "dns_server") or "",
        "dns_username": get_setting(db, "dns_username") or "",
        "dns_password": get_setting(db, "dns_password") or "",
        "dns_tsig_algorithm": get_setting(db, "dns_tsig_algorithm") or "",
        "dns_winrm_ssl": get_setting(db, "dns_winrm_ssl") or "",
        "azure_tenant_id": get_setting(db, "azure_tenant_id") or "",
        "azure_client_id": get_setting(db, "azure_client_id") or "",
        "azure_client_secret": get_setting(db, "azure_client_secret") or "",
        "azure_subscription_id": get_setting(db, "azure_subscription_id") or "",
        "azure_resource_group": get_setting(db, "azure_resource_group") or "",
    }
    row = DnsZoneConfig(zone_name=canonical, encrypted_config=encode_zone_config_dict(cfg))
    db.add(row)
    db.commit()
    db.refresh(row)
    for key in db.exec(select(ApiKey).where(ApiKey.active == True)).all():
        db.add(ApiKeyAllowedZone(api_key_id=key.id, dns_zone_config_id=row.id))
    db.commit()
    for name in LEGACY_DNS_SETTING_NAMES:
        delete_setting(db, name)


def list_dns_zones(db) -> List[DnsZoneConfig]:
    return sorted(db.exec(select(DnsZoneConfig)).all(), key=lambda z: z.zone_name)


def api_key_allowed_zone_names(db, api_key_id: int) -> List[str]:
    links = db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == api_key_id)).all()
    names: List[str] = []
    for link in links:
        z = db.get(DnsZoneConfig, link.dns_zone_config_id)
        if z:
            names.append(z.zone_name)
    return sorted(names)


def dns_zone_public_dict(z: DnsZoneConfig) -> Dict[str, Any]:
    """Safe to use after the Session closes (plain dict)."""
    cfg = decode_zone_config(z)
    provider_key = cfg.get("dns_provider_type", "") or "azure"
    return {
        "id": z.id,
        "zone_name": z.zone_name,
        "dns_provider_type": provider_key,
        "dns_provider_label": get_dns_provider_label(provider_key),
        "dns_server": cfg.get("dns_server", "") or "",
    }


def dns_zone_summary_dict(z: DnsZoneConfig) -> Dict[str, Any]:
    return {"id": z.id, "zone_name": z.zone_name}


def api_key_public_dict(k: ApiKey) -> Dict[str, Any]:
    """Safe to use after the Session closes (plain dict)."""
    return {"id": k.id, "label": k.label, "key": k.key, "active": k.active}


def get_api_key(db, api_key: str):
    return db.exec(select(ApiKey).where(ApiKey.key == api_key, ApiKey.active == True)).first()


def _blank_preserve_secret(new_val: str, old_val: str) -> str:
    return old_val if not (new_val or "").strip() else new_val


def build_zone_config_from_form(
    form,
    existing: Optional[Dict[str, Any]] = None,
    provider_plugins: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    ex = existing or {}
    provider = (form.get("dns_provider_type") or ex.get("dns_provider_type") or "azure").strip().lower()
    plugins = provider_plugins if provider_plugins is not None else get_dns_provider_options()
    plugin = next((p for p in plugins if p["key"] == provider), None)
    if plugin is None:
        if provider in get_known_dns_provider_keys():
            raise ValueError(
                f"{get_dns_provider_label(provider)} is disabled. Enable it in Settings before using it for a DNS zone."
            )
        available = ", ".join(p["key"] for p in plugins) or "none"
        raise ValueError(f"Unknown DNS provider type: {provider}. Available providers: {available}.")

    cfg: Dict[str, Any] = {"dns_provider_type": provider}
    for field in plugin["fields"]:
        name = field["name"]
        if field["type"] == "checkbox":
            value = "true" if name in form else ""
        else:
            value = (form.get(name) or "").strip()
        if field["preserve_on_blank"]:
            value = _blank_preserve_secret(value, ex.get(name, ""))
        elif not value and field["default"] and not ex.get(name):
            value = field["default"]
        cfg[name] = value
    return cfg


@app.on_event("startup")
def startup_event():
    init_db()
    with SessionLocal() as db:
        migrate_legacy_dns_settings_if_needed(db)
        configure_operational_logging(level=get_log_level(db))
        try:
            run_retention_cleanup(db, force=True)
        except Exception:  # pragma: no cover - never block startup
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
                        roles=_serialize_roles([*ALL_ROLES, ROLE_GLOBAL_ADMIN]),
                    )
                )
                db.commit()


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
        return _render_error_response(request, exc)


@app.post("/login", response_class=HTMLResponse, include_in_schema=False)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = _client_ip(request)
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
    response.set_cookie("session", create_session_cookie(username), **session_cookie_settings())
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
        _record_activity(
            event_type="auth.logout",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=actor,
            message=f"Logout for {actor!r}",
            request_ip=_client_ip(request),
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
        return _render_error_response(request, exc)


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
                raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)
            key = get_api_key(db, api_key)
            if key is None:
                raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)
            zone_ids = [
                link.dns_zone_config_id
                for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key.id)).all()
            ]
            zones = [zone for zone_id in zone_ids if (zone := db.get(DnsZoneConfig, zone_id)) is not None]
            return [DnsZoneSummary(**dns_zone_summary_dict(z)) for z in zones]

        user = get_current_user(request)
        if not user_has_role(db, user, ROLE_DNS_ZONES_READ):
            raise HTTPException(status_code=403, detail=ROLE_FORBIDDEN_DETAIL)
        zones = list_dns_zones(db)
        zones_view = [dns_zone_public_dict(z) for z in zones]
    return templates.TemplateResponse(
        request=request,
        name="zones.html",
        context={"request": request, "zones": zones_view, "message": None},
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
            zones = list_dns_zones(db)
            zones_view = [dns_zone_public_dict(z) for z in zones]
        return templates.TemplateResponse(
            request=request,
            name="zones.html",
            context={"request": request, "zones": zones_view, "message": "Zone name is required."},
        )
    with SessionLocal() as db:
        provider_plugins = enabled_dns_provider_options(db)
        if db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == canonical)).first():
            zones = list_dns_zones(db)
            zones_view = [dns_zone_public_dict(z) for z in zones]
            return templates.TemplateResponse(
                request=request,
                name="zones.html",
                context={"request": request, "zones": zones_view, "message": f"A zone named {canonical!r} already exists."},
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
        zones = list_dns_zones(db)
        zones_view = [dns_zone_public_dict(z) for z in zones]
    return templates.TemplateResponse(
        request=request,
        name="zones.html",
        context={"request": request, "zones": zones_view, "message": f"Zone {canonical!r} added."},
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
        zones = list_dns_zones(db)
        zones_view = [dns_zone_public_dict(z) for z in zones]
    return templates.TemplateResponse(
        request=request,
        name="zones.html",
        context={"request": request, "zones": zones_view, "message": "Zone removed."},
    )


@app.get("/api-keys", response_class=HTMLResponse, include_in_schema=False)
def api_keys_page(request: Request, user: str = Depends(require_role(ROLE_API_KEYS_READ))):
    try:
        with SessionLocal() as db:
            api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda key: key.created_at, reverse=True)
            key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
            all_zones = list_dns_zones(db)
            api_keys_view = [api_key_public_dict(k) for k in api_keys]
            all_zones_view = [dns_zone_public_dict(z) for z in all_zones]
        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={
                "request": request,
                "api_keys": api_keys_view,
                "key_zones": key_zones,
                "all_zones": all_zones_view,
                "message": None,
            },
        )
    except Exception as exc:
        return _render_error_response(request, exc)


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
            api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda k: k.created_at, reverse=True)
            key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
            all_zones = list_dns_zones(db)
            api_keys_view = [api_key_public_dict(k) for k in api_keys]
            all_zones_view = [dns_zone_public_dict(z) for z in all_zones]

        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={
                "request": request,
                "api_keys": api_keys_view,
                "key_zones": key_zones,
                "all_zones": all_zones_view,
                "message": "API key revoked.",
            },
        )
    except Exception as exc:
        return _render_error_response(request, exc)


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
                    api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda k: k.created_at, reverse=True)
                    key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
                    all_zones = list_dns_zones(db)
                    api_keys_view = [api_key_public_dict(k) for k in api_keys]
                    all_zones_view = [dns_zone_public_dict(z) for z in all_zones]
                    return templates.TemplateResponse(
                        request=request,
                        name="api_keys.html",
                        context={
                            "request": request,
                            "api_keys": api_keys_view,
                            "key_zones": key_zones,
                            "all_zones": all_zones_view,
                            "message": None,
                            "edit_key_error_id": key_id,
                            "edit_key_error": "Select at least one DNS zone.",
                            "edit_key_label": label,
                            "edit_key_selected_zone_ids": zone_ids,
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
                api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda k: k.created_at, reverse=True)
                key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
                all_zones = list_dns_zones(db)
                api_keys_view = [api_key_public_dict(k) for k in api_keys]
                all_zones_view = [dns_zone_public_dict(z) for z in all_zones]
            return templates.TemplateResponse(
                request=request,
                name="api_keys.html",
                context={
                    "request": request,
                    "api_keys": api_keys_view,
                    "key_zones": key_zones,
                    "all_zones": all_zones_view,
                    "message": "API key updated.",
                },
            )
        if not zone_ids:
            with SessionLocal() as db:
                api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda k: k.created_at, reverse=True)
                key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
                all_zones = list_dns_zones(db)
                api_keys_view = [api_key_public_dict(k) for k in api_keys]
                all_zones_view = [dns_zone_public_dict(z) for z in all_zones]
            return templates.TemplateResponse(
                request=request,
                name="api_keys.html",
                context={
                    "request": request,
                    "api_keys": api_keys_view,
                    "key_zones": key_zones,
                    "all_zones": all_zones_view,
                    "message": None,
                    "create_key_error": "Select at least one DNS zone for this API key.",
                    "create_key_label": label,
                },
            )
        new_key = generate_api_key()
        with SessionLocal() as db:
            api_key = ApiKey(label=label, key=new_key)
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
                },
            )
            api_keys = sorted(db.exec(select(ApiKey)).all(), key=lambda k: k.created_at, reverse=True)
            key_zones = {k.id: api_key_allowed_zone_names(db, k.id) for k in api_keys}
            all_zones = list_dns_zones(db)
            api_keys_view = [api_key_public_dict(k) for k in api_keys]
            all_zones_view = [dns_zone_public_dict(z) for z in all_zones]

        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={
                "request": request,
                "api_keys": api_keys_view,
                "key_zones": key_zones,
                "all_zones": all_zones_view,
                "message": f"API key created: {new_key}",
            },
        )
    except Exception as exc:
        return _render_error_response(request, exc)


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


LOG_SEARCH_PAGE_SIZE = 25
ALERT_TEMPLATE_VARIABLES: List[Dict[str, str]] = [
    {"name": "{event_type}", "description": "Activity event identifier (e.g. dns.record_created)"},
    {"name": "{level}", "description": "Event severity: VERBOSE, INFORMATIONAL, WARNING, or ERROR"},
    {"name": "{category}", "description": "Event category, such as security, http, dns, alert, system, or user"},
    {"name": "{timestamp}", "description": "Event timestamp in UTC ISO 8601"},
    {"name": "{message}", "description": "Short human-readable summary"},
    {"name": "{status}", "description": "success or error"},
    {"name": "{actor_type}", "description": "user, api_key, system, or anonymous"},
    {"name": "{actor_label}", "description": "Username or API key label"},
    {"name": "{zone_name}", "description": "DNS zone associated with the event (if any)"},
    {"name": "{record_name}", "description": "DNS record name (if any)"},
    {"name": "{details}", "description": "JSON-encoded sanitized event detail payload"},
    {"name": "{system_dns_name}", "description": "Detected system DNS name (or Docker Container)"},
    {"name": "{system_ip_address}", "description": "Detected system IP address (or Docker Container)"},
]


def _settings_context(
    request: Request,
    user: str,
    area: Optional[str],
    message: Optional[str] = None,
    message_kind: str = "success",
    auth_form_error: Optional[str] = None,
    auth_form_username: Optional[str] = None,
    auth_form_selected_roles: Optional[List[str]] = None,
    log_search_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    with SessionLocal() as db:
        user_roles = get_user_roles(db, user)
        can_view_accounts = bool(
            {ROLE_GLOBAL_READ, ROLE_ACCOUNT_UPDATE, ROLE_ACCOUNT_RESET_PASSWORD}.intersection(user_roles)
        )
        users_view = (
            [user_public_dict(u) for u in sorted(db.exec(select(User)).all(), key=lambda u: u.username.lower())]
            if can_view_accounts
            else []
        )
        plugin_options = (
            dns_provider_options_with_state(db)
            if ROLE_GLOBAL_READ in user_roles or ROLE_PLUGIN_UPDATE in user_roles
            else []
        )
        accessible = accessible_settings_areas(user_roles)
        accessible_keys = {a["key"] for a in accessible}
        requested_area = (area or "").strip().lower() or (accessible[0]["key"] if accessible else "")
        if requested_area not in accessible_keys:
            requested_area = accessible[0]["key"] if accessible else ""

        system_settings_view: Optional[Dict[str, Any]] = None
        log_view: Optional[Dict[str, Any]] = None
        alert_view: Optional[Dict[str, Any]] = None

        if requested_area in {"system_settings", "log_viewing", "email_alerting"} and (
            ROLE_GLOBAL_READ in user_roles or ROLE_SYSTEM_UPDATE in user_roles
        ):
            identity = system_identity()
            smtp = get_smtp_config(db)
            current_level = get_log_level(db)
            retention_days = get_retention_days(db)
            shared_system = {
                "identity": identity,
                "is_docker": is_running_in_docker(),
                "log_level": current_level,
                "log_levels": list(LOG_LEVEL_VALUES),
                "log_categories": list(LOG_CATEGORY_VALUES),
                "retention_days": retention_days,
                "retention_options": [
                    {"value": 1, "label": "24 hours"},
                    {"value": 7, "label": "1 week"},
                    {"value": 30, "label": "30 days"},
                    {"value": 60, "label": "60 days"},
                    {"value": 90, "label": "90 days"},
                    {"value": 180, "label": "180 days"},
                    {"value": 365, "label": "365 days"},
                ],
                "smtp": {**smtp, "password_set": bool(smtp.get("password"))},
                "operational_log": {
                    "log_file": activity_logging._get_setting(db, activity_logging.SETTING_LOG_FILE) or "",
                    "max_bytes": int(
                        activity_logging._get_setting(db, activity_logging.SETTING_LOG_MAX_BYTES) or 1_048_576
                    ),
                    "backup_count": int(
                        activity_logging._get_setting(db, activity_logging.SETTING_LOG_BACKUP_COUNT) or 5
                    ),
                },
            }

            if requested_area == "system_settings":
                system_settings_view = shared_system

            if requested_area == "log_viewing":
                params = log_search_params or {}
                rows, total = query_activity_logs(
                    db,
                    event_type=params.get("event_type") or None,
                    level=params.get("level") or None,
                    category=params.get("category") or None,
                    status=params.get("status") or None,
                    zone_name=params.get("zone_name") or None,
                    actor=params.get("actor") or None,
                    text_query=params.get("text_query") or None,
                    start=params.get("start"),
                    end=params.get("end"),
                    limit=LOG_SEARCH_PAGE_SIZE,
                    offset=max(0, int(params.get("offset") or 0)),
                )
                current_offset = max(0, int(params.get("offset") or 0))
                previous_offset = max(0, current_offset - LOG_SEARCH_PAGE_SIZE)
                next_offset = current_offset + LOG_SEARCH_PAGE_SIZE
                log_view = {
                    "shared": shared_system,
                    "params": params,
                    "rows": [
                        {
                            "id": row.id,
                            "timestamp": row.timestamp.isoformat() if row.timestamp else "",
                            "level": row.level,
                            "category": row.category or "",
                            "event_type": row.event_type,
                            "status": row.status or "",
                            "actor_type": row.actor_type or "",
                            "actor_label": row.actor_label or "",
                            "zone_name": row.zone_name or "",
                            "record_name": row.record_name or "",
                            "message": row.message or "",
                            "details_json": row.details_json or "",
                            "request_method": row.request_method or "",
                            "request_path": row.request_path or "",
                            "request_status_code": row.request_status_code,
                            "request_ip": row.request_ip or "",
                        }
                        for row in rows
                    ],
                    "total": total,
                    "page_size": LOG_SEARCH_PAGE_SIZE,
                    "offset": current_offset,
                    "previous_offset": previous_offset,
                    "next_offset": next_offset,
                    "has_previous": current_offset > 0,
                    "has_next": next_offset < total,
                }

            if requested_area == "email_alerting":
                rules = list(db.exec(select(AlertRule)).all())
                alert_view = {
                    "shared": shared_system,
                    "rules": [
                        {
                            "id": rule.id,
                            "enabled": rule.enabled,
                            "name": rule.name or "",
                            "event_type": rule.event_type or "",
                            "category": rule.category or "",
                            "minimum_level": rule.minimum_level,
                            "message_contains": rule.message_contains or "",
                            "email_recipients": rule.email_recipients or "",
                            "email_subject_template": rule.email_subject_template or "",
                            "email_body_template": rule.email_body_template or "",
                            "cooldown_minutes": rule.cooldown_minutes,
                            "last_triggered_at": rule.last_triggered_at.isoformat() if rule.last_triggered_at else "",
                        }
                        for rule in sorted(rules, key=lambda r: (r.name or "", r.id or 0))
                    ],
                    "template_variables": ALERT_TEMPLATE_VARIABLES,
                    "default_subject": DEFAULT_SUBJECT_TEMPLATE,
                    "default_body": DEFAULT_BODY_TEMPLATE,
                }

    return {
        "request": request,
        "user": user,
        "user_roles": sorted(user_roles),
        "accessible_areas": accessible,
        "selected_area": requested_area,
        "users": users_view,
        "role_catalog": ROLE_LABELS,
        "plugins": plugin_options,
        "message": message,
        "message_kind": message_kind,
        "auth_form_error": auth_form_error,
        "auth_form_username": auth_form_username or "",
        "auth_form_selected_roles": [] if auth_form_selected_roles is None else auth_form_selected_roles,
        "can_view_accounts": can_view_accounts,
        "can_account_update": ROLE_ACCOUNT_UPDATE in user_roles,
        "can_account_reset_password": ROLE_ACCOUNT_RESET_PASSWORD in user_roles,
        "can_global_admin": ROLE_GLOBAL_ADMIN in user_roles,
        "can_plugin_update": ROLE_PLUGIN_UPDATE in user_roles,
        "can_system_update": ROLE_SYSTEM_UPDATE in user_roles,
        "system_settings_view": system_settings_view,
        "log_view": log_view,
        "alert_view": alert_view,
    }


def _render_settings(
    request: Request,
    user: str,
    area: Optional[str],
    **kwargs: Any,
):
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=_settings_context(request, user, area, **kwargs),
    )


@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
def settings_page(
    request: Request,
    area: Optional[str] = None,
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
    return _render_settings(request, user, normalized_area, log_search_params=log_search_params)


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
        return _render_settings(
            request,
            user,
            "authentication",
            message="A new password is required.",
            message_kind="error",
        )
    if new_password != confirm_password:
        return _render_settings(
            request,
            user,
            "authentication",
            message="New password and confirmation do not match.",
            message_kind="error",
        )
    with SessionLocal() as db:
        target = db.exec(select(User).where(User.username == user)).first()
        if target is None or not verify_password(current_password, target.password_hash):
            return _render_settings(
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
    return _render_settings(request, user, "authentication", message="Password changed.")


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
        return _render_settings(
            request,
            user,
            "authentication",
            auth_form_error="Username is required.",
            auth_form_username=username,
            auth_form_selected_roles=selected_roles,
        )
    if not password:
        return _render_settings(
            request,
            user,
            "authentication",
            auth_form_error="Password is required.",
            auth_form_username=normalized,
            auth_form_selected_roles=selected_roles,
        )
    with SessionLocal() as db:
        if ROLE_GLOBAL_ADMIN in selected_roles and not user_is_global_admin(db, user):
            return _render_settings(
                request,
                user,
                "authentication",
                auth_form_error="Only a global admin can grant global admin.",
                auth_form_username=normalized,
                auth_form_selected_roles=[r for r in selected_roles if r != ROLE_GLOBAL_ADMIN],
            )
        if db.exec(select(User).where(User.username == normalized)).first():
            return _render_settings(
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
                roles=_serialize_roles(selected_roles),
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
    return _render_settings(
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
            return _render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return _render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if target.disabled:
            return _render_settings(
                request,
                user,
                "authentication",
                message=f"User {target.username!r} is already disabled.",
                message_kind="error",
            )
        enabled_users = db.exec(select(User).where(User.disabled == False)).all()  # noqa: E712
        if len(enabled_users) <= 1:
            return _render_settings(
                request,
                user,
                "authentication",
                message="At least one enabled user account must remain.",
                message_kind="error",
            )
        if target.username == user:
            return _render_settings(
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
    return _render_settings(
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
            return _render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return _render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if not target.disabled:
            return _render_settings(
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
    return _render_settings(
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
            return _render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return _render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        remaining = db.exec(select(User)).all()
        if len(remaining) <= 1:
            return _render_settings(
                request,
                user,
                "authentication",
                message="At least one user account must remain.",
                message_kind="error",
            )
        if target.username == user:
            return _render_settings(
                request,
                user,
                "authentication",
                message="You cannot delete the user you are signed in as.",
                message_kind="error",
            )
        if not target.disabled:
            return _render_settings(
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
    return _render_settings(
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
        return _render_settings(
            request,
            user,
            "authentication",
            message="A new password is required.",
            message_kind="error",
        )
    if password != confirm_password:
        return _render_settings(
            request,
            user,
            "authentication",
            message="New password and confirmation do not match.",
            message_kind="error",
        )
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            return _render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return _render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if target.disabled:
            return _render_settings(
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
    return _render_settings(
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
            return _render_settings(
                request,
                user,
                "authentication",
                message="User not found.",
                message_kind="error",
            )
        if guard_message := global_admin_guard_message(db, user, target):
            return _render_settings(
                request,
                user,
                "authentication",
                message=guard_message,
                message_kind="error",
            )
        if target.username == user:
            return _render_settings(
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
            return _render_settings(
                request,
                user,
                "authentication",
                message="Only a global admin can change global admin role assignments.",
                message_kind="error",
            )
        if target.disabled:
            return _render_settings(
                request,
                user,
                "authentication",
                message="Enable the user account before editing its roles.",
                message_kind="error",
            )
        target.roles = _serialize_roles(selected)
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
    return _render_settings(
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
        return _render_settings(
            request,
            user,
            "plugins",
            message=f"Unknown DNS provider plugin: {plugin_key}.",
            message_kind="error",
        )

    with SessionLocal() as db:
        disabled = get_disabled_dns_plugins(db)
        if normalized_key in disabled:
            return _render_settings(request, user, "plugins", message=f"{get_dns_provider_label(normalized_key)} is already disabled.")
        enabled_count = len([plugin for plugin in get_dns_provider_options() if plugin["key"] not in disabled])
        if enabled_count <= 1:
            return _render_settings(
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
            return _render_settings(
                request,
                user,
                "plugins",
                message=(
                    f"Cannot disable {get_dns_provider_label(normalized_key)}. "
                    f"Delete DNS zone {first_zone} first."
                    if len(zone_names) == 1
                    else f"Cannot disable {get_dns_provider_label(normalized_key)}. Delete DNS zones {zones_text} first."
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

    return _render_settings(request, user, "plugins", message=f"{get_dns_provider_label(normalized_key)} disabled.")


@app.post("/settings/plugins/{plugin_key}/enable", response_class=HTMLResponse, include_in_schema=False)
def settings_plugin_enable(
    request: Request,
    plugin_key: str,
    user: str = Depends(require_role(ROLE_PLUGIN_UPDATE)),
):
    normalized_key = plugin_key.strip().lower()
    known_keys = get_known_dns_provider_keys()
    if normalized_key not in known_keys:
        return _render_settings(
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

    return _render_settings(request, user, "plugins", message=f"{get_dns_provider_label(normalized_key)} enabled.")


@app.post("/settings/system/log-level", response_class=HTMLResponse, include_in_schema=False)
def settings_update_log_level(
    request: Request,
    log_level: str = Form(...),
    redirect_area: str = Form("system_settings"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    target_area = (redirect_area or "system_settings").strip().lower()
    if target_area not in {"system_settings", "log_viewing"}:
        target_area = "system_settings"
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
        return _render_settings(request, user, target_area, message=str(exc), message_kind="error")
    return _render_settings(request, user, target_area, message=f"Activity log level set to {applied}.")


@app.post("/settings/system/retention", response_class=HTMLResponse, include_in_schema=False)
def settings_update_retention(
    request: Request,
    retention_days: int = Form(...),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    if retention_days < 1:
        return _render_settings(
            request, user, "system_settings", message="Retention must be at least 1 day.", message_kind="error"
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
    return _render_settings(
        request, user, "system_settings", message=f"Activity log retention set to {applied} days."
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
    return _render_settings(request, user, "system_settings", message="SMTP delivery settings saved.")


@app.post("/settings/system/log-rotation", response_class=HTMLResponse, include_in_schema=False)
def settings_update_log_rotation(
    request: Request,
    log_file: str = Form(""),
    max_bytes: int = Form(1_048_576),
    backup_count: int = Form(5),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    with SessionLocal() as db:
        activity_logging._set_setting(db, activity_logging.SETTING_LOG_FILE, log_file or "")
        activity_logging._set_setting(db, activity_logging.SETTING_LOG_MAX_BYTES, str(max(1024, int(max_bytes))))
        activity_logging._set_setting(db, activity_logging.SETTING_LOG_BACKUP_COUNT, str(max(0, int(backup_count))))
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
    return _render_settings(request, user, "system_settings", message="Operational log rotation saved.")


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
        return _render_settings(
            request, user, "email_alerting", message=f"Unsupported level: {minimum_level}", message_kind="error"
        )
    cleaned_category = (category or "").strip().lower()
    if cleaned_category and cleaned_category not in LOG_CATEGORY_VALUES:
        return _render_settings(
            request, user, "email_alerting", message=f"Unsupported category: {category}", message_kind="error"
        )
    if not email_recipients.strip():
        return _render_settings(
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
    return _render_settings(request, user, "email_alerting", message=f"Alert rule {name!r} created.")


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
        return _render_settings(
            request, user, "email_alerting", message=f"Unsupported level: {minimum_level}", message_kind="error"
        )
    cleaned_category = (category or "").strip().lower()
    if cleaned_category and cleaned_category not in LOG_CATEGORY_VALUES:
        return _render_settings(
            request, user, "email_alerting", message=f"Unsupported category: {category}", message_kind="error"
        )
    with SessionLocal() as db:
        rule = db.get(AlertRule, rule_id)
        if rule is None:
            return _render_settings(
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
    return _render_settings(request, user, "email_alerting", message=f"Alert rule {name!r} updated.")


@app.post("/settings/alerts/{rule_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def settings_alerts_delete(
    request: Request,
    rule_id: int,
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    with SessionLocal() as db:
        rule = db.get(AlertRule, rule_id)
        if rule is None:
            return _render_settings(
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
    return _render_settings(request, user, "email_alerting", message=f"Alert rule {rule_name!r} deleted.")


@app.post(
    "/dns-record",
    response_model=DnsRecordResponse,
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "DELETE: no matching record in the zone.",
            "model": DnsRecordResponse,
        },
        400: {"description": "Invalid request or configuration."},
        403: {"description": "API key is not allowed to use this zone, or the zone is not configured."},
        502: {"description": "DNS provider reported a failure (e.g. WinRM or dynamic update)."},
        503: {"description": "A required component is not installed or misconfigured."},
    },
)
def upsert_dns_record(
    payload: DnsRecordRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = api_key_from_headers(x_api_key, authorization)

    if not api_key:
        _record_activity(
            event_type="dns.access_denied",
            level=LOG_LEVEL_WARNING,
            status="error",
            actor_type="api_key",
            message="API key missing on /dns-record",
        )
        raise HTTPException(status_code=401, detail="API key is required")

    with SessionLocal() as db:
        key = db.exec(select(ApiKey).where(ApiKey.key == api_key, ApiKey.active == True)).first()
        if key is None:
            emit_activity_event(
                db,
                event_type="dns.access_denied",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_label="invalid",
                message="Invalid or revoked API key used on /dns-record",
                details={"key_fingerprint": _api_key_fingerprint(api_key)},
            )
            raise HTTPException(status_code=401, detail="Invalid API key")

        actor_id = str(key.id) if key.id is not None else None
        actor_label = key.label

        if not payload.zone_name or not str(payload.zone_name).strip():
            emit_activity_event(
                db,
                event_type="dns.invalid_request",
                level=LOG_LEVEL_WARNING,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                record_name=payload.record_name,
                message="zone_name is required on /dns-record",
            )
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "message": "zone_name is required on every request."},
            )
        canonical = normalize_zone_name(payload.zone_name)
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
                record_name=payload.record_name,
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
                record_name=payload.record_name,
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
                    record_name=payload.record_name,
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
                    record_name=payload.record_name,
                    message="Azure resource group is required on the zone configuration.",
                )
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_request",
                        "message": "Azure resource group is required on the zone configuration.",
                    },
                )

        payload = payload.model_copy(update={"zone_name": zone_row.zone_name})

        try:
            client = get_dns_client_from_settings(settings)
            existed = client.create_or_update_record(
                payload,
                dns_server=settings.get("dns_server"),
                dns_zone=zone_row.zone_name,
            )
            op = payload.record_type.strip().upper()
            if op == "DELETE":
                action = "deleted" if existed else "not_found"
                status = "success" if existed else "error"
            else:
                action = "updated" if existed else "created"
                status = "success"
            body = DnsRecordResponse(
                status=status,
                action=action,
                zone_name=payload.zone_name,
                record_name=payload.record_name,
                record_type=payload.record_type,
                values=payload.values,
            )
            event_type = "dns.record_" + action
            event_level = LOG_LEVEL_INFORMATIONAL if status == "success" else LOG_LEVEL_WARNING
            emit_activity_event(
                db,
                event_type=event_type,
                level=event_level,
                status=status,
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=payload.zone_name,
                record_name=payload.record_name,
                message=f"DNS record {payload.record_name}.{payload.zone_name} {action}",
                details={
                    "record_type": payload.record_type,
                    "values_count": len(payload.values),
                    "provider": provider,
                },
            )
            if op == "DELETE" and not existed:
                return JSONResponse(status_code=HTTP_404_NOT_FOUND, content=body.model_dump())
            return body
        except HTTPException:
            raise
        except Exception as exc:
            mapped = _http_exception_from_dns_error(exc)
            sanitized_error = (str(exc) or "DNS provider error").splitlines()[0][:512]
            emit_activity_event(
                db,
                event_type="dns.provider_failed",
                level=LOG_LEVEL_ERROR,
                status="error",
                actor_type="api_key",
                actor_id=actor_id,
                actor_label=actor_label,
                zone_name=payload.zone_name,
                record_name=payload.record_name,
                message=sanitized_error,
                details={
                    "provider": provider,
                    "record_type": payload.record_type,
                    "exception_type": type(exc).__name__,
                },
            )
            raise mapped from exc


def _api_key_fingerprint(api_key: str) -> str:
    """Return a short, log-safe fingerprint for an API key string.

    Never logs the key itself: the prefix is short and combined with a SHA-256
    digest so the full key cannot be recovered from logs.
    """
    import hashlib

    if not api_key:
        return ""
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"
