import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import HTTPException, Request
from sqlmodel import select

SECRET_KEY = os.getenv("SECRET_KEY", "please-change-this-secret")
SESSION_IDLE_TIMEOUT_SECONDS = 300
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session-cookie")


def session_cookie_settings() -> dict:
    return {
        "httponly": True,
        "max_age": SESSION_IDLE_TIMEOUT_SECONDS,
        "samesite": "lax",
    }


def create_session_cookie(username: str) -> str:
    return serializer.dumps(username)


def verify_session_cookie(token: str) -> str:
    return serializer.loads(token, max_age=SESSION_IDLE_TIMEOUT_SECONDS)


def get_current_user(request: Request) -> str:
    session_token = request.cookies.get("session")
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        username = verify_session_cookie(session_token)
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    from .db import SessionLocal
    from .models import User

    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == username)).first()
        if user is None or user.disabled:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
    request.state.session_user = username
    return username
