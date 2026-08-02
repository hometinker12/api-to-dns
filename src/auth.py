import os

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
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


def _env_flag(name: str) -> bool | None:
    raw = os.getenv(name, "").strip().lower()
    if raw in {"1", "true", "yes"}:
        return True
    if raw in {"0", "false", "no"}:
        return False
    return None


def trust_proxy_headers() -> bool:
    return bool(_env_flag("TRUST_PROXY_HEADERS"))


def session_cookie_secure(request: Request | None = None) -> bool:
    """Return whether the session cookie should set the Secure attribute.

    Resolution order:
    1. ``SESSION_COOKIE_SECURE`` force flag
    2. Trusted request/proxy HTTPS when ``TRUST_PROXY_HEADERS=1``
    3. In-app SSL toggle (``SSL_ENABLED`` env or DB ``ssl_enabled``)
    """
    forced = _env_flag("SESSION_COOKIE_SECURE")
    if forced is not None:
        return forced

    if request is not None:
        if request.url.scheme == "https":
            return True
        if trust_proxy_headers():
            forwarded = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
            if forwarded == "https":
                return True

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
        "path": "/",
        "httponly": True,
        "max_age": SESSION_IDLE_TIMEOUT_SECONDS,
        "samesite": "lax",
        "secure": secure,
    }


def create_session_cookie(username: str, session_version: int = 0) -> str:
    return serializer.dumps({"u": username, "v": int(session_version)})


def verify_session_cookie(token: str) -> tuple[str, int]:
    """Return ``(username, session_version)`` from a signed session cookie."""
    data: str | dict = serializer.loads(token, max_age=SESSION_IDLE_TIMEOUT_SECONDS)
    if isinstance(data, str):
        # Legacy username-only cookies are treated as session_version 0.
        return data, 0
    if isinstance(data, dict):
        username = str(data.get("u") or "").strip()
        if not username:
            raise BadSignature("session cookie missing username")
        try:
            version = int(data.get("v") or 0)
        except (TypeError, ValueError) as exc:
            raise BadSignature("session cookie has invalid version") from exc
        return username, version
    raise BadSignature("session cookie has unexpected payload")


def bump_session_version(db, user) -> int:
    """Increment and persist ``user.session_version``; return the new value."""
    current = int(getattr(user, "session_version", 0) or 0)
    user.session_version = current + 1
    db.add(user)
    db.commit()
    db.refresh(user)
    return int(user.session_version or 0)


def get_current_user(request: Request) -> str:
    session_token = request.cookies.get("session")
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        username, cookie_version = verify_session_cookie(session_token)
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    from .db import SessionLocal
    from .models import User

    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == username)).first()
        if user is None or user.disabled:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        db_version = int(getattr(user, "session_version", 0) or 0)
        if cookie_version != db_version:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
    request.state.session_user = username
    request.state.session_version = cookie_version
    return username
