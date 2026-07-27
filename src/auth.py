import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import HTTPException, Request
from sqlmodel import select

from .security import allow_insecure_defaults

_INSECURE_SECRET_DEFAULTS = frozenset(
    {
        "",
        "please-change-this-secret",
        "change-me-before-production",
    }
)


def _require_secret_key() -> str:
    raw = os.getenv("SECRET_KEY")
    candidate = (raw or "").strip()
    if candidate in _INSECURE_SECRET_DEFAULTS:
        if allow_insecure_defaults():
            return "test-secret-key-for-pytest-only"
        raise RuntimeError(
            "SECRET_KEY must be set to a non-default random value before starting the application. "
            "Do not use placeholder values such as 'change-me-before-production'."
        )
    return candidate


SECRET_KEY = _require_secret_key()
SESSION_IDLE_TIMEOUT_SECONDS = 900
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session-cookie")


def session_cookie_secure() -> bool:
    env = os.getenv("SSL_ENABLED", "").strip().lower()
    if env in {"1", "true", "yes"}:
        return True
    if env in {"0", "false", "no"}:
        return False
    try:
        from .db import SessionLocal
        from .ssl_certs import is_ssl_enabled

        with SessionLocal() as db:
            return bool(is_ssl_enabled(db))
    except Exception:
        return False


def session_cookie_settings(*, secure: bool = False) -> dict:
    return {
        "httponly": True,
        "max_age": SESSION_IDLE_TIMEOUT_SECONDS,
        "samesite": "lax",
        "secure": secure,
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
