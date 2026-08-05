"""Load persisted application secrets before crypto/session modules initialize.

Restore writes ``SECRET_KEY`` / ``ENCRYPTION_KEY`` to a durable file under the
data directory. This module applies those values into ``os.environ`` early so a
process restart picks them up even when Compose ``env_file`` or a read-only
root filesystem would otherwise keep stale host ``.env`` values.
"""

from __future__ import annotations

import os
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
        if value:
            os.environ[key] = value


def write_application_secrets(*, secret_key: str, encryption_key: str) -> list[str]:
    """Persist secrets for the next process start. Returns paths written."""
    written: list[str] = []
    body = f"SECRET_KEY={secret_key.strip()}\nENCRYPTION_KEY={encryption_key.strip()}\n"
    durable = app_secrets_path()
    durable.parent.mkdir(parents=True, exist_ok=True)
    durable.write_text(body, encoding="utf-8")
    try:
        os.chmod(durable, 0o600)
    except OSError:
        pass
    written.append(str(durable))
    os.environ["SECRET_KEY"] = secret_key.strip()
    os.environ["ENCRYPTION_KEY"] = encryption_key.strip()

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
