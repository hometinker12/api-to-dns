import os
import secrets
import sys
from passlib.context import CryptContext
from cryptography.fernet import Fernet

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

_INSECURE_ENCRYPTION_PLACEHOLDERS = frozenset(
    {
        "",
        "change-me-before-production",
    }
)


def allow_insecure_defaults() -> bool:
    """Return True when missing/placeholder crypto secrets may be auto-filled.

    Enabled under pytest, or when ``API_TO_DNS_ALLOW_INSECURE_DEFAULTS=1``.
    Explicitly setting that env var to ``0``/``false`` forces production fail-fast
    even under pytest (used by security unit tests).
    Production deployments must set real ``ENCRYPTION_KEY`` / ``SECRET_KEY`` values.
    """
    forced = os.getenv("API_TO_DNS_ALLOW_INSECURE_DEFAULTS", "").strip().lower()
    if forced in {"0", "false", "no"}:
        return False
    if forced in {"1", "true", "yes"}:
        return True
    if os.getenv("PYTEST_CURRENT_TEST") or "pytest" in sys.modules:
        return True
    return False


def _require_encryption_key() -> str:
    raw = os.getenv("ENCRYPTION_KEY")
    candidate = (raw or "").strip()
    if candidate in _INSECURE_ENCRYPTION_PLACEHOLDERS:
        if allow_insecure_defaults():
            return Fernet.generate_key().decode()
        raise RuntimeError(
            "ENCRYPTION_KEY must be set to a valid Fernet key before starting the application. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    try:
        Fernet(candidate.encode())
    except (ValueError, TypeError, Exception) as exc:
        if allow_insecure_defaults():
            return Fernet.generate_key().decode()
        raise RuntimeError(
            "ENCRYPTION_KEY is not a valid Fernet key. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        ) from exc
    return candidate


ENCRYPTION_KEY = _require_encryption_key()
fernet = Fernet(ENCRYPTION_KEY.encode())


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def encrypt_value(value: str) -> str:
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    return fernet.decrypt(value.encode()).decode()
