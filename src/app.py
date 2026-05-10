import html
import os
import traceback
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Form, Header, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.status import HTTP_303_SEE_OTHER, HTTP_404_NOT_FOUND
from sqlmodel import select

from .auth import create_session_cookie, get_current_user
from .db import SessionLocal, init_db
from .models import ApiKey, DnsRecordRequest, DnsRecordResponse, Setting, User
from .security import decrypt_value, encrypt_value, generate_api_key, hash_password, verify_password

app = FastAPI(
    title="Microsoft DNS Record Service",
    description="Create or update Microsoft DNS records via REST and manage API keys through a protected web UI.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="src/static"), name="static")
templates = Jinja2Templates(directory="src/templates")


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
    """Build a DNS provider client from encrypted application settings."""
    from .dns_client import create_dns_client

    return create_dns_client(settings)


def _http_exception_from_dns_error(exc: Exception) -> HTTPException:
    """Map provider/configuration errors to HTTP errors with structured detail."""
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, ValueError):
        return HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": str(exc)},
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


def get_api_key(db, api_key: str):
    return db.exec(
        select(ApiKey).where(ApiKey.key == api_key, ApiKey.active == True)
    ).first()


def load_settings(db):
    return {
        "dns_provider_type": get_setting(db, "dns_provider_type"),
        "dns_server": get_setting(db, "dns_server"),
        "dns_zone": get_setting(db, "dns_zone"),
        "dns_username": get_setting(db, "dns_username"),
        "dns_password": get_setting(db, "dns_password"),
        "dns_tsig_algorithm": get_setting(db, "dns_tsig_algorithm"),
        "dns_winrm_ssl": get_setting(db, "dns_winrm_ssl"),
        "azure_tenant_id": get_setting(db, "azure_tenant_id"),
        "azure_client_id": get_setting(db, "azure_client_id"),
        "azure_client_secret": get_setting(db, "azure_client_secret"),
        "azure_subscription_id": get_setting(db, "azure_subscription_id"),
        "azure_resource_group": get_setting(db, "azure_resource_group"),
    }


@app.on_event("startup")
def startup_event():
    init_db()
    admin_user = os.getenv("ADMIN_USER")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_user and admin_password:
        with SessionLocal() as db:
            if not db.exec(select(User).where(User.username == admin_user)).first():
                db.add(User(username=admin_user, password_hash=hash_password(admin_password)))
                db.commit()


@app.get("/", response_class=RedirectResponse)
def root() -> RedirectResponse:
    return RedirectResponse(url="/admin")


@app.get("/keycheck")
def keycheck(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = x_api_key
    if not api_key and authorization:
        prefix = "Bearer "
        if authorization.startswith(prefix):
            api_key = authorization[len(prefix) :].strip()

    if not api_key:
        return JSONResponse(status_code=401, content={"status": "failure"})

    with SessionLocal() as db:
        key = get_api_key(db, api_key)
        if key is None:
            return JSONResponse(status_code=401, content={"status": "failure"})

    return {"status": "success"}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    try:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": None}
        )
    except Exception as exc:
        return _render_error_response(request, exc)


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == username)).first()
        if not user or not verify_password(password, user.password_hash):
            return templates.TemplateResponse(
                request=request, 
                name="login.html", 
                context={"error": "Invalid credentials."})
    response = RedirectResponse(url="/admin", status_code=HTTP_303_SEE_OTHER)
    response.set_cookie("session", create_session_cookie(username), httponly=True)
    return response


@app.get("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    response.delete_cookie("session")
    return response


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, user: str = Depends(get_current_user)):
    try:
        with SessionLocal() as db:
            settings = load_settings(db)
            api_keys = db.exec(select(ApiKey)).all()
            api_keys = sorted(api_keys, key=lambda key: key.created_at, reverse=True)
        return templates.TemplateResponse(request=request, name="admin.html", 
            context={"request": request, "user": user, "settings": settings, "api_keys": api_keys})

    except Exception as exc:
        return _render_error_response(request, exc)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = Depends(get_current_user)):
    with SessionLocal() as db:
        settings = load_settings(db)
    return templates.TemplateResponse(request=request, name="settings.html",
        context={"request": request, "settings": settings, "message": None},
    )


@app.post("/settings", response_class=HTMLResponse)
def save_settings(
    request: Request,
    dns_provider_type: str = Form("azure"),
    dns_server: str = Form(""),
    dns_zone: str = Form(""),
    dns_username: str = Form(""),
    dns_password: str = Form(""),
    dns_tsig_algorithm: str = Form(""),
    dns_winrm_ssl: str = Form(""),
    azure_tenant_id: str = Form(""),
    azure_client_id: str = Form(""),
    azure_client_secret: str = Form(""),
    azure_subscription_id: str = Form(""),
    azure_resource_group: str = Form(""),
    user: str = Depends(get_current_user),
):
    with SessionLocal() as db:
        set_setting(db, "dns_provider_type", dns_provider_type)
        set_setting(db, "dns_server", dns_server)
        set_setting(db, "dns_zone", dns_zone)
        set_setting(db, "dns_username", dns_username)
        set_setting(db, "dns_password", dns_password)
        set_setting(db, "dns_tsig_algorithm", dns_tsig_algorithm)
        set_setting(db, "dns_winrm_ssl", dns_winrm_ssl)
        set_setting(db, "azure_tenant_id", azure_tenant_id)
        set_setting(db, "azure_client_id", azure_client_id)
        set_setting(db, "azure_client_secret", azure_client_secret)
        set_setting(db, "azure_subscription_id", azure_subscription_id)
        set_setting(db, "azure_resource_group", azure_resource_group)
        settings = load_settings(db)

    return templates.TemplateResponse(request=request, name="settings.html",
        context={"request": request, "settings": settings, "message": "Settings saved successfully."},
    )


@app.get("/api-keys", response_class=HTMLResponse)
def api_keys_page(request: Request, user: str = Depends(get_current_user)):
    try:
        with SessionLocal() as db:
            api_keys = db.exec(select(ApiKey)).all()
            api_keys = sorted(api_keys, key=lambda key: key.created_at, reverse=True)
        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, "api_keys": api_keys, "message": None},
        )
    except Exception as exc:
        return _render_error_response(request, exc)


@app.post("/api-keys", response_class=HTMLResponse)
def create_api_key_route(request: Request, label: str = Form(...), user: str = Depends(get_current_user)):
    try:
        new_key = generate_api_key()
        with SessionLocal() as db:
            api_key = ApiKey(label=label, key=new_key)
            db.add(api_key)
            db.commit()
            api_keys = db.exec(select(ApiKey)).all()
            api_keys = sorted(api_keys, key=lambda key: key.created_at, reverse=True)

        return templates.TemplateResponse(request=request, name="api_keys.html",
            context={"request": request, "api_keys": api_keys, "message": f"API key created: {new_key}"},
        )
    except Exception as exc:
        return _render_error_response(request, exc)


@app.post("/api-keys/revoke", response_class=HTMLResponse)
def revoke_api_key(request: Request, key_id: int = Form(...), user: str = Depends(get_current_user)):
    try:
        with SessionLocal() as db:
            api_key = db.get(ApiKey, key_id)
            if api_key:
                api_key.active = False
                db.add(api_key)
                db.commit()
            api_keys = db.exec(select(ApiKey)).all()
            api_keys = sorted(api_keys, key=lambda key: key.created_at, reverse=True)

        return templates.TemplateResponse(
            request=request,
            name="api_keys.html",
            context={"request": request, "api_keys": api_keys, "message": "API key revoked."},
        )
    except Exception as exc:
        return _render_error_response(request, exc)


@app.post(
    "/dns-record",
    response_model=DnsRecordResponse,
    responses={
        HTTP_404_NOT_FOUND: {
            "description": "DELETE: no matching record in the zone.",
            "model": DnsRecordResponse,
        },
        400: {"description": "Invalid request or configuration."},
        502: {"description": "DNS provider reported a failure (e.g. WinRM or dynamic update)."},
        503: {"description": "A required component is not installed or misconfigured."},
    },
)
def upsert_dns_record(
    payload: DnsRecordRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    api_key = x_api_key
    if not api_key and authorization:
        prefix = "Bearer "
        if authorization.startswith(prefix):
            api_key = authorization[len(prefix) :].strip()

    if not api_key:
        raise HTTPException(status_code=401, detail="API key is required")

    with SessionLocal() as db:
        key = db.exec(select(ApiKey).where(ApiKey.key == api_key, ApiKey.active == True)).first()
        if key is None:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not payload.zone_name:
            payload.zone_name = get_setting(db, "dns_zone")
        if not payload.zone_name:
            raise HTTPException(status_code=400, detail="Zone name is required")

        settings = load_settings(db)
        provider = (settings.get("dns_provider_type") or "azure").strip().lower()
        if provider == "azure":
            updates = {}
            if not payload.subscription_id and settings.get("azure_subscription_id"):
                updates["subscription_id"] = settings["azure_subscription_id"]
            if not payload.resource_group and settings.get("azure_resource_group"):
                updates["resource_group"] = settings["azure_resource_group"]
            if updates:
                payload = payload.model_copy(update=updates)
            if not payload.subscription_id:
                raise HTTPException(
                    status_code=400,
                    detail="subscription_id is required for Azure DNS (save a default in settings or include it in the request).",
                )
            if not payload.resource_group:
                raise HTTPException(
                    status_code=400,
                    detail="resource_group is required for Azure DNS (save a default in settings or include it in the request).",
                )

        try:
            client = get_dns_client_from_settings(settings)
            existed = client.create_or_update_record(
                payload,
                dns_server=settings.get("dns_server"),
                dns_zone=settings.get("dns_zone"),
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
