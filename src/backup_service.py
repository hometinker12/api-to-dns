"""Configuration backup export/import (ciphertext as-is + outer password envelope)."""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlmodel import select

from . import env_bootstrap
from .backup_crypto import (
    BACKUP_FORMAT,
    BACKUP_VERSION,
    decrypt_envelope,
    encrypt_payload,
)
from .letsencrypt import ACME_ACCOUNT_KEY_FILENAME
from .models import (
    API_KEY_ACCESS_MODES,
    API_KEY_ACCESS_READ_WRITE,
    ActivityLog,
    AlertRule,
    ApiKey,
    ApiKeyAllowedZone,
    DnsZoneConfig,
    Setting,
    User,
)
from .rbac import ROLE_GLOBAL_ADMIN, effective_roles, parse_roles, serialize_roles
from .security import pwd_context
from .settings_store import begin_immediate, delete_setting, get_typed_setting_by_key, set_typed_setting_by_key
from .ssl_certs import CERT_FILENAME, KEY_FILENAME, SOURCE_FILENAME, cert_dir
from .time_utils import utc_now
from .version import get_app_version

# Soft limit for uploaded backup archives (JSON envelope in memory).
MAX_BACKUP_UPLOAD_BYTES = 32 * 1024 * 1024
MANIFEST_ENVELOPE_ENCRYPTED = "envelope_encrypted"
# Bound imported passlib PBKDF2 work factors (default hash uses 29000).
MIN_PASSWORD_HASH_ROUNDS = 10_000
MAX_PASSWORD_HASH_ROUNDS = 600_000

LOGGER = logging.getLogger("api_to_dns")

SETTING_BACKUP_PROGRESS = "backup_restore_progress"

CATEGORY_SETTINGS = "settings"
CATEGORY_USERS = "users"
CATEGORY_ZONES = "zones"
CATEGORY_API_KEYS = "api_keys"
CATEGORY_ALERT_RULES = "alert_rules"
CATEGORY_SSL_FILES = "ssl_files"
CATEGORY_APPLICATION_SECRETS = "application_secrets"
CATEGORY_ACTIVITY_LOGS = "activity_logs"

ALL_CATEGORIES: list[str] = [
    CATEGORY_SETTINGS,
    CATEGORY_USERS,
    CATEGORY_ZONES,
    CATEGORY_API_KEYS,
    CATEGORY_ALERT_RULES,
    CATEGORY_SSL_FILES,
    CATEGORY_APPLICATION_SECRETS,
    CATEGORY_ACTIVITY_LOGS,
]

DEFAULT_EXPORT_CATEGORIES: list[str] = [
    CATEGORY_SETTINGS,
    CATEGORY_USERS,
    CATEGORY_ZONES,
    CATEGORY_API_KEYS,
    CATEGORY_ALERT_RULES,
    CATEGORY_SSL_FILES,
    CATEGORY_APPLICATION_SECRETS,
]

FERNET_BACKED_CATEGORIES = frozenset(
    {
        CATEGORY_SETTINGS,
        CATEGORY_ZONES,
        CATEGORY_SSL_FILES,
    }
)
ENCRYPTION_REQUIRED_EXPORT_CATEGORIES = frozenset(
    {
        CATEGORY_SETTINGS,
        CATEGORY_USERS,
        CATEGORY_ZONES,
        CATEGORY_API_KEYS,
        CATEGORY_SSL_FILES,
        CATEGORY_APPLICATION_SECRETS,
    }
)

# Ephemeral / in-progress settings that should not round-trip in backups.
_EXCLUDED_SETTING_NAMES = frozenset(
    {
        SETTING_BACKUP_PROGRESS,
        "restart_required",
        "restart_reason",
        "last_scheduled_restart_date",
        "letsencrypt_renewal_pending_restart",
        "letsencrypt_enrollment",
        "letsencrypt_enrollment_progress",
        "last_activity_retention_cleanup",
    }
)

SSL_FILE_NAMES = (KEY_FILENAME, CERT_FILENAME, SOURCE_FILENAME, ACME_ACCOUNT_KEY_FILENAME)

ProgressCallback = Callable[[str, int, str], None]


class BackupError(RuntimeError):
    """Raised when backup export or import cannot proceed."""


def write_restore_progress(
    db,
    *,
    phase: str,
    percent: int,
    message: str,
    done: bool = False,
    error: str | None = None,
    result_status: str | None = None,
    restarting: bool = False,
) -> None:
    payload = {
        "phase": phase,
        "percent": max(0, min(100, int(percent))),
        "message": message,
        "done": bool(done),
        "error": error,
        "result_status": result_status,
        "restarting": bool(restarting),
    }
    set_typed_setting_by_key(db, SETTING_BACKUP_PROGRESS, payload)
    db.commit()


def get_restore_progress(db) -> dict[str, Any]:
    try:
        data = get_typed_setting_by_key(db, SETTING_BACKUP_PROGRESS)
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {
        "phase": data.get("phase") or "idle",
        "percent": max(0, min(100, int(data.get("percent") or 0))),
        "message": data.get("message") or "",
        "done": bool(data.get("done")),
        "error": data.get("error"),
        "result_status": data.get("result_status"),
        "restarting": bool(data.get("restarting")),
    }


def _restore_is_running(progress: dict[str, Any]) -> bool:
    if bool(progress.get("done")):
        return False
    phase = str(progress.get("phase") or "idle").strip().lower()
    return phase not in {"", "idle"}


def is_restore_in_progress(db) -> bool:
    return _restore_is_running(get_restore_progress(db))


def try_begin_restore(db, *, message: str = "Starting restore…") -> bool:
    """Atomically mark restore as starting. Returns False if already running."""
    begin_immediate(db)
    if is_restore_in_progress(db):
        db.rollback()
        return False
    write_restore_progress(db, phase="starting", percent=0, message=message)
    return True


def mark_restore_worker_finished(db) -> None:
    if is_restore_in_progress(db):
        write_restore_progress(
            db,
            phase="error",
            percent=100,
            message="Restore worker ended unexpectedly.",
            done=True,
            error="Restore worker ended unexpectedly.",
            result_status="error",
        )


def clear_stale_restore_progress(db) -> None:
    if is_restore_in_progress(db):
        clear_restore_progress(db)


def import_in_progress() -> bool:
    from .db import SessionLocal

    with SessionLocal() as db:
        return is_restore_in_progress(db)


def set_import_in_progress(value: bool) -> None:
    """Compatibility helper: map the old process flag onto DB-backed restore progress."""
    from .db import SessionLocal

    with SessionLocal() as db:
        if value:
            write_restore_progress(db, phase="starting", percent=0, message="Starting restore…")
        elif is_restore_in_progress(db):
            clear_restore_progress(db)


def clear_restore_progress(db) -> None:
    delete_setting(db, SETTING_BACKUP_PROGRESS)
    db.commit()


def normalize_categories(selected: list[str] | set[str] | None, *, default_on: bool = True) -> list[str]:
    if selected is None:
        return list(DEFAULT_EXPORT_CATEGORIES if default_on else [])
    chosen = [c for c in ALL_CATEGORIES if c in set(selected)]
    return chosen


def validate_import_categories(categories: list[str], payload: dict[str, Any]) -> None:
    manifest = payload.get("manifest") or {}
    included = set(manifest.get("categories") or [])
    for cat in categories:
        present = cat in included or cat in payload
        if not present:
            label = "audit logs" if cat == CATEGORY_ACTIVITY_LOGS else cat
            raise BackupError(f"Backup does not include {label}.")
    needs_secrets = bool(FERNET_BACKED_CATEGORIES.intersection(categories))
    if needs_secrets and CATEGORY_APPLICATION_SECRETS not in categories:
        raise BackupError(
            "Restoring settings, DNS zones, or SSL files requires Application secrets "
            "(ENCRYPTION_KEY) so Fernet ciphertext remains readable after restart."
        )


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def build_payload(db, categories: list[str]) -> dict[str, Any]:
    cats = normalize_categories(categories)
    payload: dict[str, Any] = {
        "manifest": {
            "format": BACKUP_FORMAT,
            "schema_version": BACKUP_VERSION,
            "app_version": get_app_version(),
            "categories": cats,
            "created_at": utc_now().isoformat(),
        }
    }

    if CATEGORY_SETTINGS in cats:
        rows = list(db.exec(select(Setting)).all())
        payload[CATEGORY_SETTINGS] = [
            {"name": row.name, "value": row.value}
            for row in rows
            if row.name and row.name not in _EXCLUDED_SETTING_NAMES
        ]

    if CATEGORY_USERS in cats:
        users = list(db.exec(select(User)).all())
        payload[CATEGORY_USERS] = [
            {
                "username": u.username,
                "password_hash": u.password_hash,
                "roles": u.roles or "",
                "disabled": bool(u.disabled),
                "session_version": int(u.session_version or 0),
            }
            for u in users
        ]

    if CATEGORY_ZONES in cats:
        zones = list(db.exec(select(DnsZoneConfig)).all())
        payload[CATEGORY_ZONES] = [{"zone_name": z.zone_name, "encrypted_config": z.encrypted_config} for z in zones]

    if CATEGORY_API_KEYS in cats:
        keys = list(db.exec(select(ApiKey)).all())
        zone_by_id = {z.id: z.zone_name for z in db.exec(select(DnsZoneConfig)).all()}
        key_payload = []
        for key in keys:
            links = list(db.exec(select(ApiKeyAllowedZone).where(ApiKeyAllowedZone.api_key_id == key.id)).all())
            allowed = [zone_by_id[link.dns_zone_config_id] for link in links if link.dns_zone_config_id in zone_by_id]
            key_payload.append(
                {
                    "label": key.label,
                    "key": key.key,
                    "key_prefix": key.key_prefix or "",
                    "access_mode": key.access_mode,
                    "active": bool(key.active),
                    "created_at": _iso(key.created_at),
                    "allowed_zones": allowed,
                }
            )
        payload[CATEGORY_API_KEYS] = key_payload

    if CATEGORY_ALERT_RULES in cats:
        rules = list(db.exec(select(AlertRule)).all())
        payload[CATEGORY_ALERT_RULES] = [
            {
                "enabled": bool(r.enabled),
                "name": r.name or "",
                "event_type": r.event_type,
                "category": r.category,
                "minimum_level": r.minimum_level,
                "message_contains": r.message_contains,
                "email_recipients": r.email_recipients or "",
                "email_subject_template": r.email_subject_template or "",
                "email_body_template": r.email_body_template or "",
                "cooldown_minutes": int(r.cooldown_minutes or 0),
                "last_triggered_at": _iso(r.last_triggered_at),
            }
            for r in rules
        ]

    if CATEGORY_SSL_FILES in cats:
        directory = cert_dir()
        files: dict[str, str] = {}
        for name in SSL_FILE_NAMES:
            path = directory / name
            if path.is_file():
                files[name] = base64.b64encode(path.read_bytes()).decode("ascii")
        payload[CATEGORY_SSL_FILES] = files

    if CATEGORY_APPLICATION_SECRETS in cats:
        payload[CATEGORY_APPLICATION_SECRETS] = {
            "SECRET_KEY": os.environ.get("SECRET_KEY") or "",
            "ENCRYPTION_KEY": os.environ.get("ENCRYPTION_KEY") or "",
        }

    if CATEGORY_ACTIVITY_LOGS in cats:
        logs: list[dict[str, Any]] = []
        batch_size = 500
        offset = 0
        while True:
            batch = list(db.exec(select(ActivityLog).order_by(ActivityLog.id).offset(offset).limit(batch_size)).all())
            if not batch:
                break
            for row in batch:
                logs.append(
                    {
                        "timestamp": _iso(row.timestamp),
                        "level": row.level,
                        "category": row.category,
                        "event_type": row.event_type,
                        "status": row.status,
                        "actor_type": row.actor_type,
                        "actor_id": row.actor_id,
                        "actor_label": row.actor_label,
                        "zone_name": row.zone_name,
                        "record_name": row.record_name,
                        "message": row.message,
                        "details_json": row.details_json,
                        "request_method": row.request_method,
                        "request_path": row.request_path,
                        "request_status_code": row.request_status_code,
                        "request_ip": row.request_ip,
                    }
                )
            offset += batch_size
        payload[CATEGORY_ACTIVITY_LOGS] = logs

    return payload


def serialize_backup(
    payload: dict[str, Any],
    *,
    encrypt: bool,
    password: str | None,
) -> bytes:
    created = (payload.get("manifest") or {}).get("created_at") or utc_now().isoformat()
    sensitive_categories = sorted(set(payload) & ENCRYPTION_REQUIRED_EXPORT_CATEGORIES)
    if sensitive_categories and not encrypt:
        labels = ", ".join(sensitive_categories)
        raise BackupError(f"Selected backup categories require a password-encrypted backup: {labels}.")
    if encrypt:
        if not password:
            raise BackupError("Password is required when encryption is enabled.")
        if len(password) < 8:
            raise BackupError("Backup password must be at least 8 characters.")
        envelope = encrypt_payload(json.dumps(payload, separators=(",", ":")).encode("utf-8"), password)
        envelope["created_at"] = created
        return json.dumps(envelope, indent=2).encode("utf-8")

    envelope = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "created_at": created,
        "encrypted": False,
        "payload": payload,
    }
    return json.dumps(envelope, indent=2).encode("utf-8")


def load_backup_bytes(raw: bytes, password: str | None) -> dict[str, Any]:
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("Backup file is not valid JSON.") from exc
    if envelope.get("format") != BACKUP_FORMAT:
        raise BackupError("Unrecognized backup format.")
    encrypted = bool(envelope.get("encrypted"))
    if encrypted:
        if not password:
            raise BackupError("Password is required to decrypt this backup.")
        try:
            payload_bytes = decrypt_envelope(envelope, password)
        except ValueError as exc:
            raise BackupError(str(exc)) from exc
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise BackupError("Decrypted backup payload is corrupt.") from exc
    else:
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise BackupError("Unencrypted backup is missing payload.")
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise BackupError("Backup payload is missing manifest.")
    # Record envelope integrity so restore can refuse secrets from plaintext archives.
    manifest[MANIFEST_ENVELOPE_ENCRYPTED] = encrypted
    return payload


def backup_filename() -> str:
    stamp = utc_now().strftime("%Y%m%d-%H%M%S")
    return f"api-to-dns-backup-{stamp}.atdb"


def _delete_all(db, model, *, commit: bool = True) -> None:
    for row in list(db.exec(select(model)).all()):
        db.delete(row)
    if commit:
        db.commit()


def _progress(cb: ProgressCallback | None, phase: str, percent: int, message: str) -> None:
    if cb:
        cb(phase, percent, message)


def _require_mapping(item: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise BackupError(f"{label} entry must be an object.")
    return item


def _fresh_session_version() -> int:
    """Return an unpredictable session_version that cannot collide via +1 arithmetic."""
    return secrets.randbits(31) or 1


def _validate_password_hash(password_hash: str, *, username: str) -> None:
    if pwd_context.identify(password_hash) is None:
        raise BackupError(f"User '{username}' has an unrecognized password_hash format.")
    # passlib: $pbkdf2-sha256$<rounds>$<salt>$<digest>
    parts = password_hash.split("$")
    if len(parts) >= 3 and parts[1].startswith("pbkdf2"):
        try:
            rounds = int(parts[2])
        except ValueError as exc:
            raise BackupError(f"User '{username}' has an invalid password_hash rounds value.") from exc
        if rounds < MIN_PASSWORD_HASH_ROUNDS or rounds > MAX_PASSWORD_HASH_ROUNDS:
            raise BackupError(
                f"User '{username}' password_hash rounds must be between "
                f"{MIN_PASSWORD_HASH_ROUNDS} and {MAX_PASSWORD_HASH_ROUNDS}."
            )


def validate_restore_records(categories: list[str], payload: dict[str, Any]) -> None:
    """Validate every selected category before any destructive wipe/commit."""
    cats = normalize_categories(categories, default_on=False)
    validate_import_categories(cats, payload)

    if CATEGORY_SETTINGS in cats:
        settings = payload.get(CATEGORY_SETTINGS) or []
        if not isinstance(settings, list):
            raise BackupError("Backup settings category must be a list.")
        for item in settings:
            row = _require_mapping(item, label="Settings")
            name = (row.get("name") or "").strip()
            if name and name not in _EXCLUDED_SETTING_NAMES and row.get("value") is not None:
                if not isinstance(row.get("value"), str):
                    raise BackupError(f"Setting '{name}' value must be a string.")

    if CATEGORY_USERS in cats:
        users = payload.get(CATEGORY_USERS) or []
        if not isinstance(users, list) or not users:
            raise BackupError("Backup users category is empty; refusing to leave the system with no accounts.")
        seen: set[str] = set()
        enabled_global_admin = False
        for item in users:
            row = _require_mapping(item, label="User")
            username = (row.get("username") or "").strip()
            password_hash = row.get("password_hash")
            if not username:
                raise BackupError("User entry missing username.")
            if not isinstance(password_hash, str) or not password_hash.strip():
                raise BackupError(f"User '{username}' is missing password_hash.")
            _validate_password_hash(password_hash, username=username)
            if username in seen:
                raise BackupError(f"Duplicate user '{username}' in backup.")
            seen.add(username)
            try:
                int(row.get("session_version") or 0)
            except (TypeError, ValueError) as exc:
                raise BackupError(f"User '{username}' has invalid session_version.") from exc
            if not bool(row.get("disabled")):
                roles = effective_roles(parse_roles(row.get("roles") or ""))
                if ROLE_GLOBAL_ADMIN in roles:
                    enabled_global_admin = True
        if not enabled_global_admin:
            raise BackupError("Backup users must include at least one enabled global administrator.")

    if CATEGORY_ZONES in cats:
        zones = payload.get(CATEGORY_ZONES) or []
        if not isinstance(zones, list):
            raise BackupError("Backup zones category must be a list.")
        seen_zones: set[str] = set()
        for item in zones:
            row = _require_mapping(item, label="Zone")
            zone_name = (row.get("zone_name") or "").strip()
            if not zone_name:
                raise BackupError("Zone entry missing zone_name.")
            if zone_name in seen_zones:
                raise BackupError(f"Duplicate zone '{zone_name}' in backup.")
            seen_zones.add(zone_name)
            if not isinstance(row.get("encrypted_config"), str) or not row.get("encrypted_config"):
                raise BackupError(f"Zone '{zone_name}' is missing encrypted_config.")

    if CATEGORY_API_KEYS in cats:
        keys = payload.get(CATEGORY_API_KEYS) or []
        if not isinstance(keys, list):
            raise BackupError("Backup API keys category must be a list.")
        seen_keys: set[str] = set()
        for item in keys:
            row = _require_mapping(item, label="API key")
            digest = row.get("key")
            if not isinstance(digest, str) or not digest:
                raise BackupError("API key entry missing key digest.")
            if digest in seen_keys:
                raise BackupError("Duplicate API key digest in backup.")
            seen_keys.add(digest)
            access_mode = row.get("access_mode", API_KEY_ACCESS_READ_WRITE)
            if not isinstance(access_mode, str) or access_mode not in API_KEY_ACCESS_MODES:
                raise BackupError("API key access_mode must be read_only or read_write.")
            allowed = row.get("allowed_zones") or []
            if allowed is not None and not isinstance(allowed, list):
                raise BackupError("API key allowed_zones must be a list.")

    if CATEGORY_ALERT_RULES in cats:
        rules = payload.get(CATEGORY_ALERT_RULES) or []
        if not isinstance(rules, list):
            raise BackupError("Backup alert rules category must be a list.")
        for item in rules:
            row = _require_mapping(item, label="Alert rule")
            try:
                int(row.get("cooldown_minutes") or 0)
            except (TypeError, ValueError) as exc:
                raise BackupError("Alert rule has invalid cooldown_minutes.") from exc

    if CATEGORY_SSL_FILES in cats:
        files = payload.get(CATEGORY_SSL_FILES) or {}
        if not isinstance(files, dict):
            raise BackupError("Backup SSL files category must be an object.")
        for name, b64 in files.items():
            if name not in SSL_FILE_NAMES:
                continue
            if not isinstance(b64, str) or not b64.strip():
                raise BackupError(f"SSL file '{name}' is empty.")
            try:
                base64.b64decode(b64, validate=True)
            except Exception as exc:  # noqa: BLE001
                raise BackupError(f"SSL file '{name}' is not valid base64.") from exc

    if CATEGORY_ACTIVITY_LOGS in cats:
        logs = payload.get(CATEGORY_ACTIVITY_LOGS) or []
        if not isinstance(logs, list):
            raise BackupError("Backup activity logs category must be a list.")
        for item in logs:
            _require_mapping(item, label="Activity log")

    if CATEGORY_APPLICATION_SECRETS in cats:
        manifest = payload.get("manifest") or {}
        if not isinstance(manifest, dict) or not manifest.get(MANIFEST_ENVELOPE_ENCRYPTED):
            raise BackupError("Application secrets can only be restored from a password-encrypted backup.")
        secrets = payload.get(CATEGORY_APPLICATION_SECRETS) or {}
        if not isinstance(secrets, dict):
            raise BackupError("Backup application secrets must be an object.")
        secret_key = (secrets.get("SECRET_KEY") or "").strip()
        encryption_key = (secrets.get("ENCRYPTION_KEY") or "").strip()
        if not secret_key or not encryption_key:
            raise BackupError("Backup application secrets are incomplete.")
        try:
            env_bootstrap._validate_persisted_secret("SECRET_KEY", secret_key)
            env_bootstrap._validate_persisted_secret("ENCRYPTION_KEY", encryption_key)
        except ValueError as exc:
            raise BackupError(str(exc)) from exc


def restore_payload(
    db,
    payload: dict[str, Any],
    categories: list[str],
    *,
    progress_cb: ProgressCallback | None = None,
) -> dict[str, Any]:
    cats = normalize_categories(categories, default_on=False)
    if not cats:
        raise BackupError("Select at least one category to restore.")

    summary: dict[str, int] = {}
    _progress(progress_cb, "validate", 5, "Validating backup archive…")
    # Full structural validation before any wipe so a bad archive cannot lock out admins.
    validate_restore_records(cats, payload)

    db_categories = {
        CATEGORY_SETTINGS,
        CATEGORY_USERS,
        CATEGORY_ZONES,
        CATEGORY_API_KEYS,
        CATEGORY_ALERT_RULES,
        CATEGORY_ACTIVITY_LOGS,
    }
    touches_db = bool(db_categories.intersection(cats))

    # Progress updates open a separate SQLite session; only call them outside
    # the restore write transaction to avoid "database is locked".
    if touches_db:
        _progress(progress_cb, "database", 15, "Restoring database categories…")

    try:
        # Wipe + restore DB rows in one transaction so failures roll back the wipe.
        if CATEGORY_API_KEYS in cats or CATEGORY_ZONES in cats:
            _delete_all(db, ApiKeyAllowedZone, commit=False)
        if CATEGORY_API_KEYS in cats:
            _delete_all(db, ApiKey, commit=False)
        if CATEGORY_ZONES in cats:
            _delete_all(db, DnsZoneConfig, commit=False)
        if CATEGORY_USERS in cats:
            _delete_all(db, User, commit=False)
        if CATEGORY_ALERT_RULES in cats:
            _delete_all(db, AlertRule, commit=False)
        if CATEGORY_ACTIVITY_LOGS in cats:
            _delete_all(db, ActivityLog, commit=False)
        if CATEGORY_SETTINGS in cats:
            for row in list(db.exec(select(Setting)).all()):
                if row.name != SETTING_BACKUP_PROGRESS:
                    db.delete(row)
        # Apply deletes before inserts so unique constraints (username, zone_name, …) succeed.
        if touches_db:
            db.flush()

        if CATEGORY_SETTINGS in cats:
            for item in payload.get(CATEGORY_SETTINGS) or []:
                name = (item.get("name") or "").strip()
                if not name or name in _EXCLUDED_SETTING_NAMES:
                    continue
                db.add(Setting(name=name, value=item.get("value") or ""))
            summary[CATEGORY_SETTINGS] = len(payload.get(CATEGORY_SETTINGS) or [])

        if CATEGORY_USERS in cats:
            users = payload.get(CATEGORY_USERS) or []
            for item in users:
                # Assign a fresh unpredictable session_version so source cookies
                # cannot replay against the restored target (same SECRET_KEY).
                db.add(
                    User(
                        username=str(item["username"]).strip(),
                        password_hash=item["password_hash"],
                        roles=serialize_roles(parse_roles(item.get("roles") or "")),
                        disabled=bool(item.get("disabled")),
                        session_version=_fresh_session_version(),
                    )
                )
            summary[CATEGORY_USERS] = len(users)

        zone_id_by_name: dict[str, int] = {}
        if CATEGORY_ZONES in cats:
            zones = payload.get(CATEGORY_ZONES) or []
            for item in zones:
                row = DnsZoneConfig(
                    zone_name=item["zone_name"],
                    encrypted_config=item["encrypted_config"],
                )
                db.add(row)
                db.flush()
                db.refresh(row)
                zone_id_by_name[row.zone_name] = int(row.id)
            summary[CATEGORY_ZONES] = len(zones)
        else:
            zone_id_by_name = {z.zone_name: int(z.id) for z in db.exec(select(DnsZoneConfig)).all() if z.id is not None}

        if CATEGORY_API_KEYS in cats:
            keys = payload.get(CATEGORY_API_KEYS) or []
            for item in keys:
                row = ApiKey(
                    label=item.get("label") or "",
                    key=item["key"],
                    key_prefix=item.get("key_prefix") or "",
                    access_mode=item.get("access_mode", API_KEY_ACCESS_READ_WRITE),
                    active=bool(item.get("active", True)),
                    created_at=_parse_dt(item.get("created_at")) or utc_now(),
                )
                db.add(row)
                db.flush()
                db.refresh(row)
                for zname in item.get("allowed_zones") or []:
                    zid = zone_id_by_name.get(zname)
                    if zid is None:
                        continue
                    db.add(ApiKeyAllowedZone(api_key_id=row.id, dns_zone_config_id=zid))
            summary[CATEGORY_API_KEYS] = len(keys)

        if CATEGORY_ALERT_RULES in cats:
            rules = payload.get(CATEGORY_ALERT_RULES) or []
            for item in rules:
                db.add(
                    AlertRule(
                        enabled=bool(item.get("enabled", True)),
                        name=item.get("name") or "",
                        event_type=item.get("event_type"),
                        category=item.get("category"),
                        minimum_level=item.get("minimum_level") or "WARNING",
                        message_contains=item.get("message_contains"),
                        email_recipients=item.get("email_recipients") or "",
                        email_subject_template=item.get("email_subject_template") or "",
                        email_body_template=item.get("email_body_template") or "",
                        cooldown_minutes=int(item.get("cooldown_minutes") or 0),
                        last_triggered_at=_parse_dt(item.get("last_triggered_at")),
                    )
                )
            summary[CATEGORY_ALERT_RULES] = len(rules)

        if CATEGORY_ACTIVITY_LOGS in cats:
            logs = payload.get(CATEGORY_ACTIVITY_LOGS) or []
            batch: list[ActivityLog] = []
            for item in logs:
                batch.append(
                    ActivityLog(
                        timestamp=_parse_dt(item.get("timestamp")) or utc_now(),
                        level=item.get("level") or "INFORMATIONAL",
                        category=item.get("category"),
                        event_type=item.get("event_type") or "",
                        status=item.get("status"),
                        actor_type=item.get("actor_type"),
                        actor_id=item.get("actor_id"),
                        actor_label=item.get("actor_label"),
                        zone_name=item.get("zone_name"),
                        record_name=item.get("record_name"),
                        message=item.get("message"),
                        details_json=item.get("details_json"),
                        request_method=item.get("request_method"),
                        request_path=item.get("request_path"),
                        request_status_code=item.get("request_status_code"),
                        request_ip=item.get("request_ip"),
                    )
                )
                if len(batch) >= 200:
                    db.add_all(batch)
                    db.flush()
                    batch = []
            if batch:
                db.add_all(batch)
                db.flush()
            summary[CATEGORY_ACTIVITY_LOGS] = len(logs)

        if touches_db:
            db.commit()
            _progress(progress_cb, "database", 70, "Database categories restored…")
    except Exception:
        db.rollback()
        raise

    # Filesystem categories after DB commit so a failed DB restore cannot orphan SSL/secrets.
    if CATEGORY_SSL_FILES in cats:
        _progress(progress_cb, "ssl_files", 85, "Restoring SSL certificate files…")
        directory = cert_dir()
        for name in SSL_FILE_NAMES:
            path = directory / name
            if path.is_file():
                try:
                    path.unlink()
                except OSError as exc:
                    LOGGER.warning("Failed to remove SSL file %s: %s", path, exc)
        files = payload.get(CATEGORY_SSL_FILES) or {}
        directory.mkdir(parents=True, exist_ok=True)
        count = 0
        for name, b64 in files.items():
            if name not in SSL_FILE_NAMES:
                continue
            path = directory / name
            path.write_bytes(base64.b64decode(b64))
            try:
                os.chmod(path, 0o600 if name.endswith(".key") else 0o644)
            except OSError:
                pass
            count += 1
        summary[CATEGORY_SSL_FILES] = count

    restarting = False
    if CATEGORY_APPLICATION_SECRETS in cats:
        _progress(progress_cb, "application_secrets", 95, "Writing application secrets…")
        secrets = payload.get(CATEGORY_APPLICATION_SECRETS) or {}
        secret_key = (secrets.get("SECRET_KEY") or "").strip()
        encryption_key = (secrets.get("ENCRYPTION_KEY") or "").strip()
        if not secret_key or not encryption_key:
            raise BackupError("Backup application secrets are incomplete.")
        # Secrets-only restore keeps existing users; assign fresh session versions
        # so source cookies signed with the restored SECRET_KEY cannot be replayed.
        if CATEGORY_USERS not in cats:
            for user_row in list(db.exec(select(User)).all()):
                user_row.session_version = _fresh_session_version()
                db.add(user_row)
            db.commit()
        env_bootstrap.write_application_secrets(secret_key=secret_key, encryption_key=encryption_key)
        summary[CATEGORY_APPLICATION_SECRETS] = 2
        restarting = True

    return {"summary": summary, "restarting": restarting, "categories": cats}
