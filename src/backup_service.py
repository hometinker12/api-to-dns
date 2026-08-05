"""Configuration backup export/import (ciphertext as-is + outer password envelope)."""

from __future__ import annotations

import base64
import json
import logging
import os
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
    ActivityLog,
    AlertRule,
    ApiKey,
    ApiKeyAllowedZone,
    DnsZoneConfig,
    Setting,
    User,
)
from .settings_store import delete_setting, get_setting, set_setting
from .ssl_certs import CERT_FILENAME, KEY_FILENAME, SOURCE_FILENAME, cert_dir
from .time_utils import utc_now
from .version import get_app_version

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

_IMPORT_IN_PROGRESS = False


class BackupError(RuntimeError):
    """Raised when backup export or import cannot proceed."""


def import_in_progress() -> bool:
    return _IMPORT_IN_PROGRESS


def set_import_in_progress(value: bool) -> None:
    global _IMPORT_IN_PROGRESS
    _IMPORT_IN_PROGRESS = bool(value)


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
    set_setting(db, SETTING_BACKUP_PROGRESS, json.dumps(payload))
    db.commit()


def get_restore_progress(db) -> dict[str, Any]:
    raw = get_setting(db, SETTING_BACKUP_PROGRESS)
    if not raw:
        return {
            "phase": "idle",
            "percent": 0,
            "message": "Idle",
            "done": False,
            "error": None,
            "result_status": None,
            "restarting": False,
        }
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
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
    if envelope.get("encrypted"):
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
    if not isinstance(payload.get("manifest"), dict):
        raise BackupError("Backup payload is missing manifest.")
    return payload


def backup_filename() -> str:
    stamp = utc_now().strftime("%Y%m%d-%H%M%S")
    return f"api-to-dns-backup-{stamp}.atdb"


def _delete_all(db, model) -> None:
    for row in list(db.exec(select(model)).all()):
        db.delete(row)
    db.commit()


def _progress(cb: ProgressCallback | None, phase: str, percent: int, message: str) -> None:
    if cb:
        cb(phase, percent, message)


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
    validate_import_categories(cats, payload)

    summary: dict[str, int] = {}
    _progress(progress_cb, "validate", 5, "Validating backup archive…")

    # Wipe phase
    _progress(progress_cb, "wipe", 10, "Removing selected data on this installation…")
    if CATEGORY_API_KEYS in cats or CATEGORY_ZONES in cats:
        # ACLs first when either side is replaced
        _delete_all(db, ApiKeyAllowedZone)
    if CATEGORY_API_KEYS in cats:
        _delete_all(db, ApiKey)
    if CATEGORY_ZONES in cats:
        _delete_all(db, DnsZoneConfig)
    if CATEGORY_USERS in cats:
        _delete_all(db, User)
    if CATEGORY_ALERT_RULES in cats:
        _delete_all(db, AlertRule)
    if CATEGORY_ACTIVITY_LOGS in cats:
        _delete_all(db, ActivityLog)
    if CATEGORY_SETTINGS in cats:
        for row in list(db.exec(select(Setting)).all()):
            if row.name != SETTING_BACKUP_PROGRESS:
                db.delete(row)
        db.commit()
    if CATEGORY_SSL_FILES in cats:
        directory = cert_dir()
        for name in SSL_FILE_NAMES:
            path = directory / name
            if path.is_file():
                try:
                    path.unlink()
                except OSError as exc:
                    LOGGER.warning("Failed to remove SSL file %s: %s", path, exc)

    step = 0
    total_steps = max(1, len(cats))

    def _step_percent(base: int = 20) -> int:
        nonlocal step
        step += 1
        return min(95, base + int(70 * step / total_steps))

    if CATEGORY_SETTINGS in cats:
        _progress(progress_cb, "settings", _step_percent(), "Restoring system settings…")
        for item in payload.get(CATEGORY_SETTINGS) or []:
            name = (item.get("name") or "").strip()
            if not name or name in _EXCLUDED_SETTING_NAMES:
                continue
            db.add(Setting(name=name, value=item.get("value") or ""))
        db.commit()
        summary[CATEGORY_SETTINGS] = len(payload.get(CATEGORY_SETTINGS) or [])

    if CATEGORY_USERS in cats:
        _progress(progress_cb, "users", _step_percent(), "Restoring users…")
        users = payload.get(CATEGORY_USERS) or []
        if not users:
            raise BackupError("Backup users category is empty; refusing to leave the system with no accounts.")
        for item in users:
            db.add(
                User(
                    username=item["username"],
                    password_hash=item["password_hash"],
                    roles=item.get("roles") or "",
                    disabled=bool(item.get("disabled")),
                    session_version=int(item.get("session_version") or 0),
                )
            )
        db.commit()
        summary[CATEGORY_USERS] = len(users)

    zone_id_by_name: dict[str, int] = {}
    if CATEGORY_ZONES in cats:
        _progress(progress_cb, "zones", _step_percent(), "Restoring DNS zones…")
        zones = payload.get(CATEGORY_ZONES) or []
        for item in zones:
            row = DnsZoneConfig(
                zone_name=item["zone_name"],
                encrypted_config=item["encrypted_config"],
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            zone_id_by_name[row.zone_name] = int(row.id)
        summary[CATEGORY_ZONES] = len(zones)
    else:
        zone_id_by_name = {z.zone_name: int(z.id) for z in db.exec(select(DnsZoneConfig)).all() if z.id is not None}

    if CATEGORY_API_KEYS in cats:
        _progress(progress_cb, "api_keys", _step_percent(), "Restoring API keys…")
        keys = payload.get(CATEGORY_API_KEYS) or []
        for item in keys:
            row = ApiKey(
                label=item.get("label") or "",
                key=item["key"],
                key_prefix=item.get("key_prefix") or "",
                active=bool(item.get("active", True)),
                created_at=_parse_dt(item.get("created_at")) or utc_now(),
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            for zname in item.get("allowed_zones") or []:
                zid = zone_id_by_name.get(zname)
                if zid is None:
                    continue
                db.add(ApiKeyAllowedZone(api_key_id=row.id, dns_zone_config_id=zid))
            db.commit()
        summary[CATEGORY_API_KEYS] = len(keys)

    if CATEGORY_ALERT_RULES in cats:
        _progress(progress_cb, "alert_rules", _step_percent(), "Restoring email alert rules…")
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
        db.commit()
        summary[CATEGORY_ALERT_RULES] = len(rules)

    if CATEGORY_SSL_FILES in cats:
        _progress(progress_cb, "ssl_files", _step_percent(), "Restoring SSL certificate files…")
        files = payload.get(CATEGORY_SSL_FILES) or {}
        directory = cert_dir()
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

    if CATEGORY_ACTIVITY_LOGS in cats:
        _progress(progress_cb, "activity_logs", _step_percent(), "Restoring audit logs…")
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
                db.commit()
                batch = []
        if batch:
            db.add_all(batch)
            db.commit()
        summary[CATEGORY_ACTIVITY_LOGS] = len(logs)

    restarting = False
    if CATEGORY_APPLICATION_SECRETS in cats:
        _progress(progress_cb, "application_secrets", _step_percent(), "Writing application secrets…")
        secrets = payload.get(CATEGORY_APPLICATION_SECRETS) or {}
        secret_key = (secrets.get("SECRET_KEY") or "").strip()
        encryption_key = (secrets.get("ENCRYPTION_KEY") or "").strip()
        if not secret_key or not encryption_key:
            raise BackupError("Backup application secrets are incomplete.")
        env_bootstrap.write_application_secrets(secret_key=secret_key, encryption_key=encryption_key)
        summary[CATEGORY_APPLICATION_SECRETS] = 2
        restarting = True

    return {"summary": summary, "restarting": restarting, "categories": cats}
