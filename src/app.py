import os
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Form, Header, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.status import HTTP_303_SEE_OTHER
from sqlmodel import select

from .auth import create_session_cookie, get_current_user
from .db import SessionLocal, init_db
from .dns_client import AzureDnsClient
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
client = AzureDnsClient()


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
        "dns_server": get_setting(db, "dns_server"),
        "dns_zone": get_setting(db, "dns_zone"),
        "dns_username": get_setting(db, "dns_username"),
        "dns_password": get_setting(db, "dns_password"),
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
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == username)).first()
        if not user or not verify_password(password, user.password_hash):
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Invalid credentials."},
            )

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
    with SessionLocal() as db:
        settings = load_settings(db)
        api_keys = db.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "user": user, "settings": settings, "api_keys": api_keys},
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = Depends(get_current_user)):
    with SessionLocal() as db:
        settings = load_settings(db)
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "settings": settings, "message": None},
    )


@app.post("/settings", response_class=HTMLResponse)
def save_settings(
    request: Request,
    dns_server: str = Form(""),
    dns_zone: str = Form(""),
    dns_username: str = Form(""),
    dns_password: str = Form(""),
    user: str = Depends(get_current_user),
):
    with SessionLocal() as db:
        set_setting(db, "dns_server", dns_server)
        set_setting(db, "dns_zone", dns_zone)
        set_setting(db, "dns_username", dns_username)
        set_setting(db, "dns_password", dns_password)
        settings = load_settings(db)

    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "settings": settings, "message": "Settings saved successfully."},
    )


@app.get("/api-keys", response_class=HTMLResponse)
def api_keys_page(request: Request, user: str = Depends(get_current_user)):
    with SessionLocal() as db:
        api_keys = db.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
    return templates.TemplateResponse(
        "api_keys.html",
        {"request": request, "api_keys": api_keys, "message": None},
    )


@app.post("/api-keys", response_class=HTMLResponse)
def create_api_key_route(request: Request, label: str = Form(...), user: str = Depends(get_current_user)):
    new_key = generate_api_key()
    with SessionLocal() as db:
        api_key = ApiKey(label=label, key=new_key)
        db.add(api_key)
        db.commit()
        api_keys = db.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()

    return templates.TemplateResponse(
        "api_keys.html",
        {"request": request, "api_keys": api_keys, "message": f"API key created: {new_key}"},
    )


@app.post("/api-keys/revoke", response_class=HTMLResponse)
def revoke_api_key(request: Request, key_id: int = Form(...), user: str = Depends(get_current_user)):
    with SessionLocal() as db:
        api_key = db.get(ApiKey, key_id)
        if api_key:
            api_key.active = False
            db.add(api_key)
            db.commit()
        api_keys = db.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()

    return templates.TemplateResponse(
        "api_keys.html",
        {"request": request, "api_keys": api_keys, "message": "API key revoked."},
    )


@app.post("/dns-record", response_model=DnsRecordResponse)
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

        try:
            existed = client.create_or_update_record(payload)
            action = "updated" if existed else "created"
            return DnsRecordResponse(
                status="success",
                action=action,
                zone_name=payload.zone_name,
                record_name=payload.record_name,
                record_type=payload.record_type,
                values=payload.values,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))
