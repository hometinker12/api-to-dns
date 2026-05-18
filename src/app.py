import html
import json
import os
import traceback
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from starlette.status import HTTP_303_SEE_OTHER, HTTP_404_NOT_FOUND

from .auth import create_session_cookie, get_current_user
from .db import SessionLocal, init_db
from .models import (
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

ALL_ROLES: List[str] = [
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

ROLE_LABELS: List[Dict[str, str]] = [
    {"key": ROLE_GLOBAL_READ, "label": "Global: read-only"},
    {"key": ROLE_ACCOUNT_UPDATE, "label": "Account: update"},
    {"key": ROLE_ACCOUNT_RESET_PASSWORD, "label": "Account: reset password"},
    {"key": ROLE_API_KEYS_READ, "label": "API keys: read"},
    {"key": ROLE_API_KEYS_UPDATE, "label": "API keys: update", "requires_role": ROLE_API_KEYS_READ},
    {"key": ROLE_DNS_ZONES_READ, "label": "DNS zones: read"},
    {"key": ROLE_DNS_ZONES_UPDATE, "label": "DNS zones: update", "requires_role": ROLE_DNS_ZONES_READ},
    {"key": ROLE_PLUGIN_UPDATE, "label": "Plugin management"},
    {"key": ROLE_SYSTEM_UPDATE, "label": "System: update"},
]

SETTINGS_AREAS: List[Dict[str, str]] = [
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
        "key": "logging",
        "label": "Activity Logging",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
    {
        "key": "backup",
        "label": "System Backup",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
]

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
    version="0.3.1",
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
    print("Application error:", error)
    print(traceback_text)
    content = (
        "<html><body><h1>Application error</h1>"
        f"<p>{html.escape(str(error))}</p>"
        "<pre>"
        f"{html.escape(traceback_text)}"
        "</pre></body></html>"
    )
    return HTMLResponse(content=content, status_code=status_code)


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
    return ",".join(sorted(cleaned))


def normalize_selected_roles(roles) -> List[str]:
    selected = {r for r in roles if r in ALL_ROLES}
    for role, required_role in ROLE_DEPENDENCIES.items():
        if role in selected:
            selected.add(required_role)
    return sorted(selected)


def get_user_roles(db, username: str) -> Set[str]:
    """Return the role set for `username`."""
    user_row = db.exec(select(User).where(User.username == username)).first()
    if user_row is None:
        return set(ALL_ROLES)
    return _parse_roles(user_row.roles)


def user_has_role(db, username: str, role: str) -> bool:
    roles = get_user_roles(db, username)
    return role in roles or (
        ROLE_GLOBAL_READ in roles and role in {ROLE_API_KEYS_READ, ROLE_DNS_ZONES_READ}
    )


def user_has_any_role(db, username: str, roles) -> bool:
    return any(user_has_role(db, username, role) for role in roles)


def require_role(role: str):
    """FastAPI dependency factory that returns the username when the user has `role`."""

    def _dependency(user: str = Depends(get_current_user)) -> str:
        with SessionLocal() as db:
            if not user_has_role(db, user, role):
                raise HTTPException(status_code=403, detail=ROLE_FORBIDDEN_DETAIL)
        return user

    return _dependency


def user_public_dict(u: User) -> Dict[str, Any]:
    return {
        "id": u.id,
        "username": u.username,
        "roles": sorted(_parse_roles(u.roles) or set(ALL_ROLES)),
        "has_default_roles": not _parse_roles(u.roles),
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
    admin_user = os.getenv("ADMIN_USER")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_user and admin_password:
        with SessionLocal() as db:
            if not db.exec(select(User).where(User.username == admin_user)).first():
                db.add(
                    User(
                        username=admin_user,
                        password_hash=hash_password(admin_password),
                        roles=_serialize_roles(ALL_ROLES),
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
    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == username)).first()
        if not user or not verify_password(password, user.password_hash):
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid credentials."},
            )
    response = RedirectResponse(url="/admin", status_code=HTTP_303_SEE_OTHER)
    response.set_cookie("session", create_session_cookie(username), httponly=True)
    return response


@app.get("/logout", include_in_schema=False)
def logout() -> RedirectResponse:
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
        if row:
            for link in db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.dns_zone_config_id == zone_id)).all():
                db.delete(link)
            db.delete(row)
            db.commit()
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


def _settings_context(
    request: Request,
    user: str,
    area: Optional[str],
    message: Optional[str] = None,
    message_kind: str = "success",
    auth_form_error: Optional[str] = None,
    auth_form_username: Optional[str] = None,
    auth_form_selected_roles: Optional[List[str]] = None,
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
        "can_plugin_update": ROLE_PLUGIN_UPDATE in user_roles,
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
    user: str = Depends(get_current_user),
):
    return _render_settings(request, user, area)


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
    return _render_settings(
        request,
        user,
        "authentication",
        message=f"User {normalized!r} created.",
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
        if target.username == user:
            return _render_settings(
                request,
                user,
                "authentication",
                message="You cannot delete the user you are signed in as.",
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
        username = target.username
        db.delete(target)
        db.commit()
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
    user: str = Depends(require_role(ROLE_ACCOUNT_RESET_PASSWORD)),
):
    if not password:
        return _render_settings(
            request,
            user,
            "authentication",
            message="A new password is required.",
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
        target.password_hash = hash_password(password)
        db.add(target)
        db.commit()
        username = target.username
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
        target.roles = _serialize_roles(selected)
        db.add(target)
        db.commit()
        username = target.username
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
        disabled.discard(normalized_key)
        set_disabled_dns_plugins(db, disabled)

    return _render_settings(request, user, "plugins", message=f"{get_dns_provider_label(normalized_key)} enabled.")


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
        raise HTTPException(status_code=401, detail="API key is required")

    with SessionLocal() as db:
        key = db.exec(select(ApiKey).where(ApiKey.key == api_key, ApiKey.active == True)).first()
        if key is None:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not payload.zone_name or not str(payload.zone_name).strip():
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "message": "zone_name is required on every request."},
            )
        canonical = normalize_zone_name(payload.zone_name)
        zone_row = db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == canonical)).first()
        if zone_row is None:
            raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)
        perm = db.exec(
            select(ApiKeyAllowedZone).where(
                ApiKeyAllowedZone.api_key_id == key.id,
                ApiKeyAllowedZone.dns_zone_config_id == zone_row.id,
            )
        ).first()
        if perm is None:
            raise HTTPException(status_code=403, detail=ACCESS_DENIED_DETAIL)

        settings = decode_zone_config(zone_row)
        provider = (settings.get("dns_provider_type") or "azure").strip().lower()
        if provider == "azure":
            if not settings.get("azure_subscription_id"):
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_request",
                        "message": "Azure subscription ID is required on the zone configuration.",
                    },
                )
            if not settings.get("azure_resource_group"):
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
            if op == "DELETE" and not existed:
                return JSONResponse(status_code=HTTP_404_NOT_FOUND, content=body.model_dump())
            return body
        except HTTPException:
            raise
        except Exception as exc:
            raise _http_exception_from_dns_error(exc) from exc
