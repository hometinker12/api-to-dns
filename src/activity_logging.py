"""Activity/audit logging, SMTP alerting, retention, and system identity helpers.

This module owns the database-backed activity log surface used by the admin UI
and email alerting. It deliberately keeps a narrow, focused API:

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

Operational logging configuration (Python ``logging``) is intentionally kept
separate from the searchable audit events. See ``configure_operational_logging``.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import socket
from datetime import datetime, timedelta
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from typing import Any

from sqlmodel import select

from .models import (
    LOG_CATEGORY_ALERT,
    LOG_CATEGORY_SECURITY,
    LOG_CATEGORY_VALUES,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_ORDER,
    LOG_LEVEL_VALUES,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
    SECURITY_EVENT_PREFIXES,
    ActivityLog,
    AlertRule,
)
from .settings_store import get_setting, set_setting
from .time_utils import utc_now

LOGGER = logging.getLogger("api_to_dns")

DETAILS_BYTE_CAP = 4096

# Setting names persisted in the encrypted Setting table.
SETTING_LOG_LEVEL = "log_level"
SETTING_RETENTION_DAYS = "activity_retention_days"
SETTING_LAST_RETENTION = "last_activity_retention_cleanup"

SETTING_SMTP_SERVERS = "smtp_servers"
SETTING_SMTP_PORT = "smtp_port"
SETTING_SMTP_ANONYMOUS = "smtp_anonymous"
SETTING_SMTP_USERNAME = "smtp_username"
SETTING_SMTP_PASSWORD = "smtp_password"
SETTING_SMTP_FROM = "smtp_from"
SETTING_SMTP_SECURITY = "smtp_security"  # one of "none", "starttls", "ssl"
SETTING_SMTP_TIMEOUT = "smtp_timeout"
SETTING_SMTP_ALLOW_INSECURE_AUTH = "smtp_allow_insecure_auth"

SETTING_LOG_FILE = "operational_log_file"
SETTING_LOG_MAX_BYTES = "operational_log_max_bytes"
SETTING_LOG_BACKUP_COUNT = "operational_log_backup_count"
SETTING_APP_DNS_NAME = "app_dns_name"

SETTING_SYSLOG_ENABLED = "remote_syslog_enabled"
SETTING_SYSLOG_HOST = "remote_syslog_host"
SETTING_SYSLOG_PORT = "remote_syslog_port"
SETTING_SYSLOG_PROTOCOL = "remote_syslog_protocol"
SETTING_SYSLOG_FACILITY = "remote_syslog_facility"
SETTING_SYSLOG_MINIMUM_LEVEL = "remote_syslog_minimum_level"
SETTING_SYSLOG_TIMEOUT = "remote_syslog_timeout"
SETTING_SYSLOG_QUEUE_SIZE = "remote_syslog_queue_size"
SETTING_SYSLOG_ALLOW_INSECURE = "remote_syslog_allow_insecure_plaintext"

DEFAULT_APP_DNS_NAME_DOCKER = "apitodns.local"
DOCKER_RUNTIME_LABEL = "Detected Docker container runtime."
DEFAULT_LOG_LEVEL = LOG_LEVEL_INFORMATIONAL
DEFAULT_RETENTION_DAYS = 90
DEFAULT_SMTP_PORT = 587
DEFAULT_SMTP_TIMEOUT = 10
DEFAULT_SMTP_SECURITY = "starttls"

DEFAULT_SUBJECT_TEMPLATE = "[api-to-dns] {level}: {event_type}"
DEFAULT_BODY_TEMPLATE = (
    "System: {system_dns_name} ({system_ip_address})\n"
    "Timestamp: {timestamp}\n"
    "Event: {event_type}\n"
    "Level: {level}\n"
    "Message: {message}\n"
    "Zone Name: {zone_name}\n"
    "Record: {record_name}\n"
    "Details: {details}"
)

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


def get_log_level(db) -> str:
    raw = (get_setting(db, SETTING_LOG_LEVEL) or "").strip().upper()
    if raw not in LOG_LEVEL_VALUES:
        return DEFAULT_LOG_LEVEL
    return raw


def set_log_level(db, value: str) -> str:
    cleaned = (value or "").strip().upper()
    if cleaned not in LOG_LEVEL_VALUES:
        raise ValueError(f"Unsupported log level: {value!r}")
    set_setting(db, SETTING_LOG_LEVEL, cleaned)
    return cleaned


def get_retention_days(db) -> int:
    raw = get_setting(db, SETTING_RETENTION_DAYS)
    if raw is None:
        return DEFAULT_RETENTION_DAYS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_RETENTION_DAYS
    return max(1, value)


def set_retention_days(db, value: int) -> int:
    days = max(1, int(value))
    set_setting(db, SETTING_RETENTION_DAYS, str(days))
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
# System identity
# ---------------------------------------------------------------------------


def is_running_in_docker() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as handle:
            return any("docker" in line or "kubepods" in line or "containerd" in line for line in handle)
    except OSError:
        return False


_host_system_dns_name_cache: str | None = None


def _host_system_dns_name() -> str:
    global _host_system_dns_name_cache
    if _host_system_dns_name_cache is not None:
        return _host_system_dns_name_cache
    try:
        hostname = socket.gethostname()
        try:
            resolved = socket.getfqdn(hostname) or hostname
        except OSError:
            resolved = hostname
    except OSError:
        resolved = "unknown"
    _host_system_dns_name_cache = resolved
    return resolved


def detect_system_dns_name() -> str:
    if is_running_in_docker():
        return "Docker Container"
    return _host_system_dns_name()


def default_app_dns_name() -> str:
    if is_running_in_docker():
        return DEFAULT_APP_DNS_NAME_DOCKER
    return _host_system_dns_name()


def get_app_dns_name(db) -> str:
    stored = (get_setting(db, SETTING_APP_DNS_NAME) or "").strip()
    if stored:
        return stored
    return default_app_dns_name()


def set_app_dns_name(db, name: str) -> str:
    from .hostnames import validate_dns_hostname

    cleaned = validate_dns_hostname(name)
    set_setting(db, SETTING_APP_DNS_NAME, cleaned)
    return cleaned


def detect_system_ip_address() -> str:
    if is_running_in_docker():
        return DOCKER_RUNTIME_LABEL
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        sock.connect(("203.0.113.1", 1))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "unknown"
    finally:
        sock.close()


def system_identity(db) -> dict[str, str]:
    return {"system_dns_name": get_app_dns_name(db), "system_ip_address": detect_system_ip_address()}


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
            evaluate_alert_rules(db, row)
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
        stored = get_setting(db, SETTING_LAST_RETENTION)
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
    set_setting(db, SETTING_LAST_RETENTION, now.isoformat())
    _retention_state["last"] = now
    return removed


# ---------------------------------------------------------------------------
# SMTP delivery
# ---------------------------------------------------------------------------


def _parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _smtp_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def validate_smtp_transport_security(
    *,
    anonymous: bool,
    username: str,
    password: str,
    security: str,
    allow_insecure_auth: bool,
) -> str | None:
    """Return an error message when credentialed cleartext SMTP is not allowed."""
    cleaned_security = (security or DEFAULT_SMTP_SECURITY).strip().lower()
    uses_credentials = (not anonymous) and bool((username or "").strip() or (password or "").strip())
    if not uses_credentials:
        return None
    if cleaned_security in {"starttls", "ssl"}:
        return None
    if allow_insecure_auth:
        return None
    return (
        "Credentialed SMTP requires STARTTLS or SSL. "
        "Enable 'Allow insecure cleartext SMTP authentication' only if you accept the risk, "
        "or use anonymous port-25 delivery without credentials."
    )


def get_smtp_config(db) -> dict[str, Any]:
    servers = _parse_csv(get_setting(db, SETTING_SMTP_SERVERS))
    try:
        port = int(get_setting(db, SETTING_SMTP_PORT) or DEFAULT_SMTP_PORT)
    except ValueError:
        port = DEFAULT_SMTP_PORT
    anonymous = _smtp_truthy(get_setting(db, SETTING_SMTP_ANONYMOUS))
    security = (get_setting(db, SETTING_SMTP_SECURITY) or DEFAULT_SMTP_SECURITY).strip().lower()
    if security not in {"none", "starttls", "ssl"}:
        security = DEFAULT_SMTP_SECURITY
    try:
        timeout = int(get_setting(db, SETTING_SMTP_TIMEOUT) or DEFAULT_SMTP_TIMEOUT)
    except ValueError:
        timeout = DEFAULT_SMTP_TIMEOUT
    return {
        "servers": servers,
        "port": port,
        "anonymous": anonymous,
        "username": get_setting(db, SETTING_SMTP_USERNAME) or "",
        "password": get_setting(db, SETTING_SMTP_PASSWORD) or "",
        "from_address": get_setting(db, SETTING_SMTP_FROM) or "",
        "security": security,
        "timeout": timeout,
        "allow_insecure_auth": _smtp_truthy(get_setting(db, SETTING_SMTP_ALLOW_INSECURE_AUTH)),
        "password_set": bool(get_setting(db, SETTING_SMTP_PASSWORD)),
    }


def get_remote_syslog_config(db) -> dict[str, Any]:
    """Return sanitized remote syslog settings for UI and worker configuration."""
    from .remote_syslog import (
        DEFAULT_FACILITY,
        DEFAULT_MINIMUM_LEVEL,
        DEFAULT_PROTOCOL,
        DEFAULT_QUEUE_SIZE,
        DEFAULT_TIMEOUT,
        DEFAULT_TLS_PORT,
        SYSLOG_FACILITY,
        SYSLOG_PROTOCOLS,
        validate_syslog_config,
    )

    enabled = _smtp_truthy(get_setting(db, SETTING_SYSLOG_ENABLED))
    host = get_setting(db, SETTING_SYSLOG_HOST) or ""
    try:
        port = int(get_setting(db, SETTING_SYSLOG_PORT) or DEFAULT_TLS_PORT)
    except ValueError:
        port = DEFAULT_TLS_PORT
    protocol = (get_setting(db, SETTING_SYSLOG_PROTOCOL) or DEFAULT_PROTOCOL).strip().lower()
    if protocol not in SYSLOG_PROTOCOLS:
        protocol = DEFAULT_PROTOCOL
    facility = (get_setting(db, SETTING_SYSLOG_FACILITY) or DEFAULT_FACILITY).strip().lower()
    if facility not in SYSLOG_FACILITY:
        facility = DEFAULT_FACILITY
    minimum_level = (get_setting(db, SETTING_SYSLOG_MINIMUM_LEVEL) or DEFAULT_MINIMUM_LEVEL).strip().upper()
    if minimum_level not in LOG_LEVEL_VALUES:
        minimum_level = DEFAULT_MINIMUM_LEVEL
    try:
        timeout = float(get_setting(db, SETTING_SYSLOG_TIMEOUT) or DEFAULT_TIMEOUT)
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    try:
        queue_size = int(get_setting(db, SETTING_SYSLOG_QUEUE_SIZE) or DEFAULT_QUEUE_SIZE)
    except ValueError:
        queue_size = DEFAULT_QUEUE_SIZE
    allow_insecure_plaintext = _smtp_truthy(get_setting(db, SETTING_SYSLOG_ALLOW_INSECURE))

    # Return a dict even when disabled/incomplete so the UI can render defaults.
    try:
        validated = validate_syslog_config(
            enabled=enabled,
            host=host,
            port=port,
            protocol=protocol,
            facility=facility,
            minimum_level=minimum_level,
            timeout=timeout,
            queue_size=queue_size,
            allow_insecure_plaintext=allow_insecure_plaintext,
            hostname=get_app_dns_name(db),
        )
        return {
            "enabled": validated.enabled,
            "host": validated.host,
            "port": validated.port,
            "protocol": validated.protocol,
            "facility": validated.facility,
            "minimum_level": validated.minimum_level,
            "timeout": validated.timeout,
            "queue_size": validated.queue_size,
            "allow_insecure_plaintext": validated.allow_insecure_plaintext,
            "hostname": validated.hostname,
            "facilities": list(SYSLOG_FACILITY.keys()),
            "protocols": list(SYSLOG_PROTOCOLS),
        }
    except ValueError:
        return {
            "enabled": False,
            "host": host,
            "port": port,
            "protocol": protocol,
            "facility": facility,
            "minimum_level": minimum_level,
            "timeout": timeout,
            "queue_size": queue_size,
            "allow_insecure_plaintext": allow_insecure_plaintext,
            "hostname": get_app_dns_name(db),
            "facilities": list(SYSLOG_FACILITY.keys()),
            "protocols": list(SYSLOG_PROTOCOLS),
        }


def set_remote_syslog_config(
    db,
    *,
    enabled: bool,
    host: str,
    port: int,
    protocol: str,
    facility: str,
    minimum_level: str,
    timeout: float,
    queue_size: int,
    allow_insecure_plaintext: bool = False,
) -> dict[str, Any]:
    """Validate and persist remote syslog settings; return the sanitized config dict."""
    from .remote_syslog import validate_syslog_config

    validated = validate_syslog_config(
        enabled=enabled,
        host=host,
        port=port,
        protocol=protocol,
        facility=facility,
        minimum_level=minimum_level,
        timeout=timeout,
        queue_size=queue_size,
        allow_insecure_plaintext=allow_insecure_plaintext,
        hostname=get_app_dns_name(db),
    )
    set_setting(db, SETTING_SYSLOG_ENABLED, "true" if validated.enabled else "false")
    set_setting(db, SETTING_SYSLOG_HOST, validated.host)
    set_setting(db, SETTING_SYSLOG_PORT, str(validated.port))
    set_setting(db, SETTING_SYSLOG_PROTOCOL, validated.protocol)
    set_setting(db, SETTING_SYSLOG_FACILITY, validated.facility)
    set_setting(db, SETTING_SYSLOG_MINIMUM_LEVEL, validated.minimum_level)
    set_setting(db, SETTING_SYSLOG_TIMEOUT, str(validated.timeout))
    set_setting(db, SETTING_SYSLOG_QUEUE_SIZE, str(validated.queue_size))
    set_setting(
        db,
        SETTING_SYSLOG_ALLOW_INSECURE,
        "true" if validated.allow_insecure_plaintext else "false",
    )
    return get_remote_syslog_config(db)


def apply_remote_syslog_config(db) -> None:
    """Load persisted settings and apply them to the process-wide forwarder."""
    from .remote_syslog import DEFAULT_PROTOCOL, DEFAULT_TLS_PORT, REMOTE_SYSLOG, validate_syslog_config

    raw = get_remote_syslog_config(db)
    config = validate_syslog_config(
        enabled=bool(raw.get("enabled")),
        host=str(raw.get("host") or ""),
        port=int(raw.get("port") or DEFAULT_TLS_PORT),
        protocol=str(raw.get("protocol") or DEFAULT_PROTOCOL),
        facility=str(raw.get("facility") or "local0"),
        minimum_level=str(raw.get("minimum_level") or LOG_LEVEL_INFORMATIONAL),
        timeout=float(raw.get("timeout") or 5.0),
        queue_size=int(raw.get("queue_size") or 1000),
        allow_insecure_plaintext=bool(raw.get("allow_insecure_plaintext")),
        hostname=str(raw.get("hostname") or get_app_dns_name(db)),
    )
    REMOTE_SYSLOG.configure(config)


def set_smtp_config(
    db,
    *,
    servers: str,
    port: int,
    anonymous: bool,
    username: str,
    password: str,
    from_address: str,
    security: str,
    timeout: int,
    allow_insecure_auth: bool = False,
    preserve_password_if_blank: bool = True,
) -> None:
    cleaned_security = (security or DEFAULT_SMTP_SECURITY).strip().lower()
    if cleaned_security not in {"none", "starttls", "ssl"}:
        cleaned_security = DEFAULT_SMTP_SECURITY
    existing_password = get_setting(db, SETTING_SMTP_PASSWORD) or ""
    effective_password = password if (password or not preserve_password_if_blank) else existing_password
    guard = validate_smtp_transport_security(
        anonymous=anonymous,
        username=username,
        password=effective_password,
        security=cleaned_security,
        allow_insecure_auth=allow_insecure_auth,
    )
    if guard:
        raise ValueError(guard)

    set_setting(db, SETTING_SMTP_SERVERS, servers or "")
    set_setting(db, SETTING_SMTP_PORT, str(int(port)))
    set_setting(db, SETTING_SMTP_ANONYMOUS, "true" if anonymous else "false")
    set_setting(db, SETTING_SMTP_USERNAME, username or "")
    if password or not preserve_password_if_blank:
        set_setting(db, SETTING_SMTP_PASSWORD, password or "")
    set_setting(db, SETTING_SMTP_FROM, from_address or "")
    set_setting(db, SETTING_SMTP_SECURITY, cleaned_security)
    set_setting(db, SETTING_SMTP_TIMEOUT, str(int(timeout)))
    set_setting(db, SETTING_SMTP_ALLOW_INSECURE_AUTH, "true" if allow_insecure_auth else "false")


def _build_smtp_client(server: str, port: int, security: str, timeout: int) -> smtplib.SMTP:
    if security == "ssl":
        return smtplib.SMTP_SSL(host=server, port=port, timeout=timeout)
    return smtplib.SMTP(host=server, port=port, timeout=timeout)


def send_alert_email(
    db,
    *,
    recipients: list[str],
    subject: str,
    body: str,
) -> tuple[bool, list[dict[str, str]]]:
    """Try the configured SMTP servers in order. Returns (sent, failures)."""
    config = get_smtp_config(db)
    failures: list[dict[str, str]] = []
    if not config["servers"]:
        failures.append({"server": "", "error": "No SMTP servers configured"})
        return False, failures
    if not config["from_address"]:
        failures.append({"server": "", "error": "SMTP from address is not configured"})
        return False, failures
    if not recipients:
        failures.append({"server": "", "error": "No recipients on alert rule"})
        return False, failures
    guard = validate_smtp_transport_security(
        anonymous=bool(config["anonymous"]),
        username=config.get("username") or "",
        password=config.get("password") or "",
        security=config.get("security") or DEFAULT_SMTP_SECURITY,
        allow_insecure_auth=bool(config.get("allow_insecure_auth")),
    )
    if guard:
        failures.append({"server": "", "error": guard})
        return False, failures

    message = EmailMessage()
    message["From"] = config["from_address"]
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)

    for server in config["servers"]:
        try:
            client = _build_smtp_client(server, config["port"], config["security"], config["timeout"])
            try:
                client.ehlo()
                if config["security"] == "starttls":
                    client.starttls()
                    client.ehlo()
                if not config["anonymous"] and config["username"]:
                    client.login(config["username"], config["password"])
                client.send_message(message)
            finally:
                try:
                    client.quit()
                except smtplib.SMTPException:
                    client.close()
            return True, failures
        except Exception as exc:  # pragma: no cover - exact exception surface depends on stdlib
            failures.append({"server": server, "error": str(exc)})
    return False, failures


# ---------------------------------------------------------------------------
# Templates and alert evaluation
# ---------------------------------------------------------------------------


def _template_values_for_event(row: ActivityLog) -> dict[str, str]:
    details_text = ""
    if row.details_json:
        try:
            parsed = json.loads(row.details_json)
            details_text = json.dumps(parsed, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            details_text = row.details_json
    return {
        "event_type": row.event_type or "",
        "level": row.level or "",
        "category": row.category or "",
        "timestamp": row.timestamp.isoformat() if row.timestamp else "",
        "message": row.message or "",
        "status": row.status or "",
        "actor_type": row.actor_type or "",
        "actor_label": row.actor_label or "",
        "actor_id": row.actor_id or "",
        "zone_name": row.zone_name or "",
        "record_name": row.record_name or "",
        "details": details_text,
    }


class _SafeFormat(dict):
    def __missing__(self, key: str) -> str:  # pragma: no cover - simple fallback
        return ""


def render_alert_template(template: str, values: dict[str, str]) -> str:
    """Render a template safely.

    - Missing placeholders render as the empty string.
    - Values are rendered verbatim (plain text). The caller is responsible for
      ensuring the email is sent as plain text so embedded HTML/script is inert.
    """
    if not template:
        return ""
    safe_values = _SafeFormat({key: ("" if value is None else str(value)) for key, value in values.items()})
    try:
        return template.format_map(safe_values)
    except (IndexError, KeyError, ValueError):
        return template


def evaluate_alert_rules(db, row: ActivityLog) -> list[AlertRule]:
    """Find matching enabled rules, render templates, send, and return triggered rules."""
    rules = list(db.exec(select(AlertRule).where(AlertRule.enabled == True)).all())  # noqa: E712
    if not rules:
        return []

    identity = system_identity(db)
    base_values = _template_values_for_event(row)
    base_values.update(identity)
    triggered: list[AlertRule] = []
    event_rank = LOG_LEVEL_ORDER.get(_normalize_level(row.level), LOG_LEVEL_ORDER[LOG_LEVEL_INFORMATIONAL])

    for rule in rules:
        if rule.event_type and rule.event_type != row.event_type:
            continue
        if rule.category and normalize_category(rule.category) != normalize_category(row.category):
            continue
        rule_threshold = LOG_LEVEL_ORDER.get(_normalize_level(rule.minimum_level), LOG_LEVEL_ORDER[LOG_LEVEL_WARNING])
        if event_rank < rule_threshold:
            continue
        if rule.message_contains:
            haystack = " ".join(filter(None, [row.message or "", row.details_json or ""])).lower()
            if rule.message_contains.lower() not in haystack:
                continue
        if rule.cooldown_minutes and rule.last_triggered_at:
            cooldown_delta = timedelta(minutes=max(0, int(rule.cooldown_minutes)))
            if (utc_now() - rule.last_triggered_at) < cooldown_delta:
                continue

        recipients = _parse_csv(rule.email_recipients)
        subject_template = rule.email_subject_template or DEFAULT_SUBJECT_TEMPLATE
        body_template = rule.email_body_template or DEFAULT_BODY_TEMPLATE
        subject = render_alert_template(subject_template, base_values)
        body = render_alert_template(body_template, base_values)

        sent, failures = send_alert_email(db, recipients=recipients, subject=subject, body=body)
        rule.last_triggered_at = utc_now()
        db.add(rule)
        db.commit()

        if not sent:
            try:
                emit_activity_event(
                    db,
                    event_type="alert.email_failed",
                    level=LOG_LEVEL_ERROR,
                    status="error",
                    actor_type="system",
                    actor_label=rule.name or "alert",
                    message=f"Alert {rule.name or rule.id!r} could not be delivered",
                    details={"rule_id": rule.id, "rule_name": rule.name, "failures": failures},
                    evaluate_alerts=False,
                )
            except Exception:  # pragma: no cover - never block on logging the failure
                LOGGER.exception("could not record alert.email_failed event")
        else:
            try:
                emit_activity_event(
                    db,
                    event_type="alert.email_sent",
                    level=LOG_LEVEL_INFORMATIONAL,
                    category=LOG_CATEGORY_ALERT,
                    status="success",
                    actor_type="system",
                    actor_label=rule.name or "alert",
                    message=f"Alert {rule.name or rule.id!r} delivered",
                    details={"rule_id": rule.id, "rule_name": rule.name, "recipients": recipients},
                    evaluate_alerts=False,
                )
            except Exception:  # pragma: no cover - never block on logging delivery success
                LOGGER.exception("could not record alert.email_sent event")
        triggered.append(rule)
    return triggered


# ---------------------------------------------------------------------------
# Operational logger setup
# ---------------------------------------------------------------------------


def configure_operational_logging(
    *,
    level: str = LOG_LEVEL_INFORMATIONAL,
    log_file: str | None = None,
    max_bytes: int = 1_048_576,
    backup_count: int = 5,
) -> None:
    """Configure the Python ``api_to_dns`` logger.

    This is intentionally separate from the database-backed audit log; it
    powers stdout/stderr for container deployments and an optional rotating
    file handler for non-Docker installs.
    """
    py_level = {
        LOG_LEVEL_VERBOSE: logging.DEBUG,
        LOG_LEVEL_INFORMATIONAL: logging.INFO,
        LOG_LEVEL_WARNING: logging.WARNING,
        LOG_LEVEL_ERROR: logging.ERROR,
    }.get(_normalize_level(level), logging.INFO)

    LOGGER.setLevel(py_level)
    for handler in list(LOGGER.handlers):
        LOGGER.removeHandler(handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOGGER.addHandler(stream_handler)

    target_file = log_file or os.getenv("LOG_FILE")
    if target_file:
        try:
            os.makedirs(os.path.dirname(target_file) or ".", exist_ok=True)
            file_handler = RotatingFileHandler(
                target_file, maxBytes=max(1024, int(max_bytes)), backupCount=max(0, int(backup_count))
            )
            file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            LOGGER.addHandler(file_handler)
        except OSError:  # pragma: no cover - best-effort file logging only
            LOGGER.exception("could not configure rotating file handler for %s", target_file)


__all__ = [
    "DEFAULT_BODY_TEMPLATE",
    "DEFAULT_RETENTION_DAYS",
    "DEFAULT_SMTP_PORT",
    "DEFAULT_SMTP_TIMEOUT",
    "DEFAULT_SUBJECT_TEMPLATE",
    "LOGGER",
    "SETTING_LOG_LEVEL",
    "SETTING_RETENTION_DAYS",
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
    "SETTING_APP_DNS_NAME",
    "should_store_event",
    "system_identity",
]
