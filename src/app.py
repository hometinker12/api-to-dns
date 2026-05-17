import html
import json
import os
import traceback
from typing import Any, Dict, List, Optional

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
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


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


def build_zone_config_from_form(form, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ex = existing or {}
    provider = (form.get("dns_provider_type") or ex.get("dns_provider_type") or "azure").strip().lower()
    plugins = get_dns_provider_options()
    plugin = next((p for p in plugins if p["key"] == provider), None)
    if plugin is None:
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
                db.add(User(username=admin_user, password_hash=hash_password(admin_password)))
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

        get_current_user(request)
        zones = list_dns_zones(db)
        zones_view = [dns_zone_public_dict(z) for z in zones]
    return templates.TemplateResponse(
        request=request,
        name="zones.html",
        context={"request": request, "zones": zones_view, "message": None},
    )


@app.get("/zones/new", response_class=HTMLResponse, include_in_schema=False)
def zone_new_form(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse(
        request=request,
        name="zone_form.html",
        context={
            "request": request,
            "zone": None,
            "settings": {},
            "provider_plugins": get_dns_provider_options(),
            "message": None,
            "title": "Add DNS zone",
        },
    )


@app.post("/zones", response_class=HTMLResponse, include_in_schema=False)
async def zone_create(request: Request, user: str = Depends(get_current_user)):
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
        if db.exec(select(DnsZoneConfig).where(DnsZoneConfig.zone_name == canonical)).first():
            zones = list_dns_zones(db)
            zones_view = [dns_zone_public_dict(z) for z in zones]
            return templates.TemplateResponse(
                request=request,
                name="zones.html",
                context={"request": request, "zones": zones_view, "message": f"A zone named {canonical!r} already exists."},
            )
        cfg = build_zone_config_from_form(form)
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
def zone_edit_form(request: Request, zone_id: int, user: str = Depends(get_current_user)):
    with SessionLocal() as db:
        row = db.get(DnsZoneConfig, zone_id)
        if not row:
            return RedirectResponse(url="/zones", status_code=HTTP_303_SEE_OTHER)
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
            "provider_plugins": get_dns_provider_options(),
            "message": None,
            "title": f"Edit zone {title_zone}",
        },
    )


@app.post("/zones/{zone_id}", response_class=HTMLResponse, include_in_schema=False)
async def zone_update(request: Request, zone_id: int, user: str = Depends(get_current_user)):
    form = await request.form()
    with SessionLocal() as db:
        row = db.get(DnsZoneConfig, zone_id)
        if not row:
            return RedirectResponse(url="/zones", status_code=HTTP_303_SEE_OTHER)
        existing = decode_zone_config(row)
        cfg = build_zone_config_from_form(form, existing=existing)
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
            "provider_plugins": get_dns_provider_options(),
            "message": "Zone saved.",
            "title": f"Edit zone {title_zone}",
        },
    )


@app.post("/zones/{zone_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def zone_delete(request: Request, zone_id: int, user: str = Depends(get_current_user)):
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
def api_keys_page(request: Request, user: str = Depends(get_current_user)):
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
def revoke_api_key(request: Request, key_id: int = Form(...), user: str = Depends(get_current_user)):
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
    user: str = Depends(get_current_user),
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
def api_key_edit_form(request: Request, key_id: int, user: str = Depends(get_current_user)):
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
    user: str = Depends(get_current_user),
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
