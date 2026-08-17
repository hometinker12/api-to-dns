"""Activity/audit logging and retention.

This module owns the database-backed activity log surface used by the admin UI.
Operational logging, system identity, SMTP alerting, and remote syslog
persistence live in owner modules; this module re-exports them for one-release
compatibility.

- ``emit_activity_event`` writes a normalized event row, applies redaction,
  and opportunistically triggers retention and alert evaluation.
- ``query_activity_logs`` powers the search UI.
- ``evaluate_alert_rules`` matches an event against configured alert rules and
  sends email via the configured SMTP server list with failover.
- ``redact_details`` keeps secrets out of the database and out of email.
- ``should_store_event`` applies the configured global level (verbose /
  informational / warning / error) as the storage threshold while always
  storing security-category events.
- ``run_retention_cleanup`` deletes rows older than the configured retention
  window, throttled to no more than once per day per process.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from sqlmodel import select

from .alerting import (
    DEFAULT_BODY_TEMPLATE,
    DEFAULT_SMTP_PORT,
    DEFAULT_SMTP_SECURITY,
    DEFAULT_SMTP_TIMEOUT,
    DEFAULT_SUBJECT_TEMPLATE,
    SETTING_SMTP_ALLOW_INSECURE_AUTH,
    SETTING_SMTP_ANONYMOUS,
    SETTING_SMTP_FROM,
    SETTING_SMTP_PASSWORD,
    SETTING_SMTP_PORT,
    SETTING_SMTP_SECURITY,
    SETTING_SMTP_SERVERS,
    SETTING_SMTP_TIMEOUT,
    SETTING_SMTP_USERNAME,
    evaluate_alert_rules,
    get_smtp_config,
    render_alert_template,
    send_alert_email,
    set_smtp_config,
    validate_smtp_transport_security,
)
from .log_constants import (
    LOG_CATEGORY_SECURITY,
    LOG_CATEGORY_VALUES,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_ORDER,
    LOG_LEVEL_VALUES,
    SECURITY_EVENT_PREFIXES,
)
from .models import (
    ActivityLog,
)
from .operational_logging import (
    LOGGER,
    SETTING_LOG_BACKUP_COUNT,
    SETTING_LOG_FILE,
    SETTING_LOG_MAX_BYTES,
    configure_operational_logging,
)
from .remote_syslog import (
    SETTING_SYSLOG_ALLOW_INSECURE,
    SETTING_SYSLOG_ENABLED,
    SETTING_SYSLOG_FACILITY,
    SETTING_SYSLOG_HOST,
    SETTING_SYSLOG_MINIMUM_LEVEL,
    SETTING_SYSLOG_PORT,
    SETTING_SYSLOG_PROTOCOL,
    SETTING_SYSLOG_QUEUE_SIZE,
    SETTING_SYSLOG_TIMEOUT,
    apply_remote_syslog_config,
    get_remote_syslog_config,
    set_remote_syslog_config,
)
from .settings_store import get_typed_setting_by_key, set_typed_setting_by_key
from .system_identity import (
    SETTING_APP_DNS_NAME,
    default_app_dns_name,
    detect_system_dns_name,
    detect_system_ip_address,
    get_app_dns_name,
    is_running_in_docker,
    set_app_dns_name,
    system_identity,
)
from .time_utils import utc_now

DETAILS_BYTE_CAP = 4096

# Setting names persisted in the encrypted Setting table.
SETTING_LOG_LEVEL = "log_level"
SETTING_RETENTION_DAYS = "activity_retention_days"
SETTING_LAST_RETENTION = "last_activity_retention_cleanup"

DEFAULT_LOG_LEVEL = LOG_LEVEL_INFORMATIONAL
DEFAULT_RETENTION_DAYS = 90

_SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "client_secret",
    "tsig",
    "encryption_key",
)

_REDACTED = "***redacted***"

_retention_state: dict[str, datetime] = {}


def _typed_bool(db, key: str) -> bool:
    try:
        return bool(get_typed_setting_by_key(db, key))
    except ValueError:
        return False


def _typed_int(db, key: str, fallback: int) -> int:
    try:
        return int(get_typed_setting_by_key(db, key))
    except (TypeError, ValueError):
        return fallback


def _typed_str(db, key: str) -> str:
    try:
        value = get_typed_setting_by_key(db, key)
    except ValueError:
        return ""
    return "" if value is None else str(value)


def get_log_level(db) -> str:
    raw = _typed_str(db, SETTING_LOG_LEVEL).strip().upper()
    if raw not in LOG_LEVEL_VALUES:
        return DEFAULT_LOG_LEVEL
    return raw


def set_log_level(db, value: str) -> str:
    cleaned = (value or "").strip().upper()
    if cleaned not in LOG_LEVEL_VALUES:
        raise ValueError(f"Unsupported log level: {value!r}")
    set_typed_setting_by_key(db, SETTING_LOG_LEVEL, cleaned)
    return cleaned


def get_retention_days(db) -> int:
    try:
        value = int(get_typed_setting_by_key(db, SETTING_RETENTION_DAYS))
    except (TypeError, ValueError):
        return DEFAULT_RETENTION_DAYS
    return max(1, value)


def set_retention_days(db, value: int) -> int:
    days = max(1, int(value))
    set_typed_setting_by_key(db, SETTING_RETENTION_DAYS, days)
    return days


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def _key_is_sensitive(key: str) -> bool:
    lowered = (key or "").lower()
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def redact_details(details: Any) -> Any:
    """Return a structure safe to log: secret-looking keys are redacted.

    The walk is depth-limited implicitly by the JSON-friendly shape of inputs.
    Strings longer than DETAILS_BYTE_CAP are truncated with a marker so the
    serialized JSON stays bounded.
    """
    if isinstance(details, dict):
        return {key: (_REDACTED if _key_is_sensitive(key) else redact_details(value)) for key, value in details.items()}
    if isinstance(details, (list, tuple)):
        return [redact_details(item) for item in details]
    if isinstance(details, str) and len(details) > DETAILS_BYTE_CAP:
        return details[:DETAILS_BYTE_CAP] + "...[truncated]"
    return details


def _details_to_json(details: dict[str, Any] | None) -> str | None:
    if details is None:
        return None
    safe = redact_details(details)
    try:
        encoded = json.dumps(safe, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        encoded = json.dumps({"unserializable": str(safe)})
    if len(encoded.encode("utf-8")) > DETAILS_BYTE_CAP:
        truncated = encoded.encode("utf-8")[:DETAILS_BYTE_CAP].decode("utf-8", errors="ignore")
        return truncated + "...[truncated]"
    return encoded


# ---------------------------------------------------------------------------
# Level threshold
# ---------------------------------------------------------------------------


def _normalize_level(level: str) -> str:
    cleaned = (level or "").strip().upper()
    if cleaned not in LOG_LEVEL_VALUES:
        return LOG_LEVEL_INFORMATIONAL
    return cleaned


def normalize_category(category: str | None) -> str | None:
    cleaned = (category or "").strip().lower()
    if not cleaned:
        return None
    return cleaned if cleaned in LOG_CATEGORY_VALUES else cleaned


def infer_event_category(event_type: str) -> str | None:
    """Infer category from the event type namespace.

    By default the segment before the first dot is the category (``plugin.disabled`` →
    ``plugin``, ``http.request`` → ``http``). Types listed in ``SECURITY_EVENT_PREFIXES``
    always map to the security category instead.
    """
    normalized = (event_type or "").strip().lower()
    if not normalized:
        return None
    for prefix in SECURITY_EVENT_PREFIXES:
        if normalized.startswith(prefix):
            return LOG_CATEGORY_SECURITY
    if "." in normalized:
        return normalized.split(".", 1)[0]
    return normalized


def should_store_event(event_level: str, configured_level: str, category: str | None = None) -> bool:
    """Return True if an event at ``event_level`` should be persisted given the configured threshold."""
    if normalize_category(category) == LOG_CATEGORY_SECURITY:
        return True
    event_rank = LOG_LEVEL_ORDER.get(_normalize_level(event_level), LOG_LEVEL_ORDER[LOG_LEVEL_INFORMATIONAL])
    threshold = LOG_LEVEL_ORDER.get(_normalize_level(configured_level), LOG_LEVEL_ORDER[LOG_LEVEL_INFORMATIONAL])
    return event_rank >= threshold


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


def emit_activity_event(
    db,
    *,
    event_type: str,
    level: str = LOG_LEVEL_INFORMATIONAL,
    category: str | None = None,
    status: str | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    actor_label: str | None = None,
    zone_name: str | None = None,
    record_name: str | None = None,
    message: str | None = None,
    details: dict[str, Any] | None = None,
    request_method: str | None = None,
    request_path: str | None = None,
    request_status_code: int | None = None,
    request_ip: str | None = None,
    evaluate_alerts: bool = True,
) -> ActivityLog | None:
    """Persist an audit/activity event if the configured threshold allows it."""
    normalized_level = _normalize_level(level)
    normalized_category = normalize_category(category) or infer_event_category(event_type)
    configured = get_log_level(db)
    if not should_store_event(normalized_level, configured, normalized_category):
        return None

    row = ActivityLog(
        timestamp=utc_now(),
        level=normalized_level,
        category=normalized_category,
        event_type=event_type,
        status=status,
        actor_type=actor_type,
        actor_id=str(actor_id) if actor_id is not None else None,
        actor_label=actor_label,
        zone_name=zone_name,
        record_name=record_name,
        message=message,
        details_json=_details_to_json(details),
        request_method=request_method,
        request_path=request_path,
        request_status_code=request_status_code,
        request_ip=request_ip,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    try:
        from .remote_syslog import REMOTE_SYSLOG, ActivityLogSnapshot

        REMOTE_SYSLOG.enqueue(ActivityLogSnapshot.from_row(row))
    except Exception:  # pragma: no cover - forwarding must never block events
        LOGGER.exception("could not enqueue audit event for remote syslog")

    try:
        run_retention_cleanup(db)
    except Exception:  # pragma: no cover - retention failures must never block events
        LOGGER.exception("activity retention cleanup failed")

    if evaluate_alerts and event_type != "alert.email_failed":
        try:
            from .alerting import evaluate_alert_rules as _evaluate_alert_rules

            _evaluate_alert_rules(db, row)
        except Exception:  # pragma: no cover - alerting failures must never block events
            LOGGER.exception("alert rule evaluation failed for event %s", event_type)

    return row


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------


def query_activity_logs(
    db,
    *,
    event_type: str | None = None,
    level: str | None = None,
    category: str | None = None,
    status: str | None = None,
    zone_name: str | None = None,
    actor: str | None = None,
    text_query: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[ActivityLog], int]:
    statement = select(ActivityLog)
    filters = []
    if event_type:
        filters.append(ActivityLog.event_type == event_type)
    if level:
        cleaned = _normalize_level(level)
        filters.append(ActivityLog.level == cleaned)
    if category:
        filters.append(ActivityLog.category == normalize_category(category))
    if status:
        filters.append(ActivityLog.status == status)
    if zone_name:
        filters.append(ActivityLog.zone_name == zone_name)
    if actor:
        like = f"%{actor}%"
        filters.append(
            (ActivityLog.actor_label.ilike(like))  # type: ignore[union-attr]
            | (ActivityLog.actor_id.ilike(like))  # type: ignore[union-attr]
        )
    if text_query:
        like = f"%{text_query}%"
        filters.append(
            (ActivityLog.message.ilike(like))  # type: ignore[union-attr]
            | (ActivityLog.details_json.ilike(like))  # type: ignore[union-attr]
            | (ActivityLog.event_type.ilike(like))  # type: ignore[union-attr]
            | (ActivityLog.category.ilike(like))  # type: ignore[union-attr]
            | (ActivityLog.zone_name.ilike(like))  # type: ignore[union-attr]
            | (ActivityLog.actor_label.ilike(like))  # type: ignore[union-attr]
        )
    if start is not None:
        filters.append(ActivityLog.timestamp >= start)
    if end is not None:
        filters.append(ActivityLog.timestamp <= end)
    for clause in filters:
        statement = statement.where(clause)

    all_rows = list(db.exec(statement.order_by(ActivityLog.timestamp.desc())).all())  # type: ignore[arg-type]
    total = len(all_rows)
    sliced = all_rows[offset : offset + limit]
    return sliced, total


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def run_retention_cleanup(db, *, force: bool = False) -> int:
    """Delete activity rows older than the configured retention window.

    Throttled to at most once per day per process unless ``force`` is set.
    Returns the number of rows removed.
    """
    if not force:
        last_local = _retention_state.get("last")
        if last_local is not None and (utc_now() - last_local) < timedelta(hours=24):
            return 0
        stored = _typed_str(db, SETTING_LAST_RETENTION)
        if stored:
            try:
                last_db = datetime.fromisoformat(stored)
            except ValueError:
                last_db = None
            if last_db is not None and (utc_now() - last_db) < timedelta(hours=24):
                _retention_state["last"] = last_db
                return 0

    days = get_retention_days(db)
    cutoff = utc_now() - timedelta(days=days)
    rows = db.exec(select(ActivityLog).where(ActivityLog.timestamp < cutoff)).all()
    removed = 0
    for row in rows:
        db.delete(row)
        removed += 1
    if removed:
        db.commit()
    now = utc_now()
    set_typed_setting_by_key(db, SETTING_LAST_RETENTION, now.isoformat())
    _retention_state["last"] = now
    return removed


__all__ = [
    "DEFAULT_BODY_TEMPLATE",
    "DEFAULT_RETENTION_DAYS",
    "DEFAULT_SMTP_PORT",
    "DEFAULT_SMTP_SECURITY",
    "DEFAULT_SMTP_TIMEOUT",
    "DEFAULT_SUBJECT_TEMPLATE",
    "LOGGER",
    "SETTING_LOG_BACKUP_COUNT",
    "SETTING_LOG_FILE",
    "SETTING_LOG_LEVEL",
    "SETTING_LOG_MAX_BYTES",
    "SETTING_RETENTION_DAYS",
    "SETTING_SMTP_ALLOW_INSECURE_AUTH",
    "SETTING_SMTP_ANONYMOUS",
    "SETTING_SMTP_FROM",
    "SETTING_SMTP_PASSWORD",
    "SETTING_SMTP_PORT",
    "SETTING_SMTP_SECURITY",
    "SETTING_SMTP_SERVERS",
    "SETTING_SMTP_TIMEOUT",
    "SETTING_SMTP_USERNAME",
    "SETTING_SYSLOG_ENABLED",
    "SETTING_SYSLOG_HOST",
    "SETTING_SYSLOG_PORT",
    "SETTING_SYSLOG_PROTOCOL",
    "SETTING_SYSLOG_FACILITY",
    "SETTING_SYSLOG_MINIMUM_LEVEL",
    "SETTING_SYSLOG_TIMEOUT",
    "SETTING_SYSLOG_QUEUE_SIZE",
    "SETTING_SYSLOG_ALLOW_INSECURE",
    "apply_remote_syslog_config",
    "configure_operational_logging",
    "default_app_dns_name",
    "detect_system_dns_name",
    "detect_system_ip_address",
    "get_app_dns_name",
    "emit_activity_event",
    "evaluate_alert_rules",
    "get_log_level",
    "get_remote_syslog_config",
    "get_retention_days",
    "get_smtp_config",
    "infer_event_category",
    "is_running_in_docker",
    "normalize_category",
    "query_activity_logs",
    "redact_details",
    "render_alert_template",
    "run_retention_cleanup",
    "send_alert_email",
    "set_app_dns_name",
    "set_log_level",
    "set_remote_syslog_config",
    "set_retention_days",
    "set_smtp_config",
    "validate_smtp_transport_security",
    "SETTING_APP_DNS_NAME",
    "should_store_event",
    "system_identity",
]
