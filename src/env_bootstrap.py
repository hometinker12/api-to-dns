"""Load persisted application secrets before crypto/session modules initialize.

Restore writes ``SECRET_KEY`` / ``ENCRYPTION_KEY`` to a durable file under the
data directory. This module applies those values into ``os.environ`` early so a
process restart picks them up even when Compose ``env_file`` or a read-only
root filesystem would otherwise keep stale host ``.env`` values.
"""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

APP_SECRETS_FILENAME = "app_secrets.env"
_SECRET_KEYS = ("SECRET_KEY", "ENCRYPTION_KEY")


def data_dir() -> Path:
    """Return the writable data directory (sibling of the SQLite DB when possible)."""
    raw = (os.getenv("DATABASE_URL") or "").strip()
    if raw.startswith("sqlite:///"):
        db_path = raw[len("sqlite:///") :]
        # Absolute paths may be sqlite:////app/data/app.db (four slashes).
        if db_path.startswith("/") and not db_path.startswith("//"):
            path = Path(db_path)
        elif db_path.startswith("/") or (len(db_path) > 2 and db_path[1] == ":"):
            path = Path(db_path)
        else:
            path = Path(db_path).resolve()
        parent = path.parent
        if str(parent) not in {"", "."}:
            return parent
    if os.path.exists("/.dockerenv") or Path("/app/data").is_dir():
        return Path("/app/data")
    return Path("data")


def app_secrets_path() -> Path:
    return data_dir() / APP_SECRETS_FILENAME


def project_env_path() -> Path:
    """Best-effort path to the project ``.env`` (local / Compose host)."""
    return Path(__file__).resolve().parents[1] / ".env"


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key in _SECRET_KEYS:
            values[key] = value.strip().strip('"').strip("'")
    return values


def apply_persisted_secrets() -> None:
    """Overlay ``SECRET_KEY`` / ``ENCRYPTION_KEY`` from the durable secrets file."""
    path = app_secrets_path()
    for key, value in parse_env_file(path).items():
        if not value:
            continue
        try:
            os.environ[key] = _validate_persisted_secret(key, value)
        except ValueError:
            # Fail closed for the overlay: leave existing process env unchanged
            # rather than applying a corrupt/hostile durable file.
            continue


def shell_export_persisted_secrets() -> str:
    """Return ``export KEY=...`` lines for the entrypoint (shell-safe quoting).

    Parses only known keys via :func:`parse_env_file` — never sources the file.
    """
    path = app_secrets_path()
    lines: list[str] = []
    for key, value in parse_env_file(path).items():
        if not value:
            continue
        try:
            cleaned = _validate_persisted_secret(key, value)
        except ValueError:
            continue
        lines.append(f"export {key}={shlex.quote(cleaned)}")
    return "\n".join(lines)


def _validate_persisted_secret(name: str, value: str) -> str:
    """Reject empty or shell-unsafe secret values before durable write."""
    cleaned = (value or "").strip()
    if not cleaned:
        raise ValueError(f"{name} is empty.")
    # Reject control chars / newlines so a KEY=value line cannot smuggle keys.
    # Values may contain '=' (Fernet padding); shell export uses shlex.quote.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        raise ValueError(f"{name} contains control characters.")
    if name == "ENCRYPTION_KEY":
        try:
            from cryptography.fernet import Fernet

            Fernet(cleaned.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001 — normalize Fernet errors
            raise ValueError("ENCRYPTION_KEY is not a valid Fernet key.") from exc
    return cleaned


def write_application_secrets(*, secret_key: str, encryption_key: str) -> list[str]:
    """Persist secrets for the next process start. Returns paths written."""
    secret_key = _validate_persisted_secret("SECRET_KEY", secret_key)
    encryption_key = _validate_persisted_secret("ENCRYPTION_KEY", encryption_key)
    written: list[str] = []
    body = f"SECRET_KEY={secret_key}\nENCRYPTION_KEY={encryption_key}\n"
    durable = app_secrets_path()
    durable.parent.mkdir(parents=True, exist_ok=True)
    durable.write_text(body, encoding="utf-8")
    try:
        os.chmod(durable, 0o600)
    except OSError:
        pass
    written.append(str(durable))
    os.environ["SECRET_KEY"] = secret_key
    os.environ["ENCRYPTION_KEY"] = encryption_key

    # Never rewrite the project ``.env`` under pytest — that file is often the
    # live Compose secrets source for a local Docker volume.
    if not os.getenv("PYTEST_CURRENT_TEST") and "pytest" not in sys.modules:
        env_path = project_env_path()
        try:
            if env_path.is_file() and os.access(env_path, os.W_OK):
                existing = env_path.read_text(encoding="utf-8").splitlines()
                updated: list[str] = []
                seen: set[str] = set()
                replacements = {
                    "SECRET_KEY": secret_key.strip(),
                    "ENCRYPTION_KEY": encryption_key.strip(),
                }
                for line in existing:
                    stripped = line.strip()
                    if stripped.startswith("#") or "=" not in line:
                        updated.append(line)
                        continue
                    key = line.split("=", 1)[0].strip()
                    if key in replacements:
                        updated.append(f"{key}={replacements[key]}")
                        seen.add(key)
                    else:
                        updated.append(line)
                for key, value in replacements.items():
                    if key not in seen:
                        updated.append(f"{key}={value}")
                env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
                written.append(str(env_path))
        except OSError:
            pass
    return written


# Apply as soon as this module is imported.
apply_persisted_secrets()
