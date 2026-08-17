"""SMTP transport, alert templates, and rule evaluation."""

from __future__ import annotations

import json
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from typing import Any

from sqlmodel import select

from .log_constants import (
    LOG_CATEGORY_ALERT,
    LOG_CATEGORY_VALUES,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_ORDER,
    LOG_LEVEL_VALUES,
    LOG_LEVEL_WARNING,
)
from .models import ActivityLog, AlertRule
from .operational_logging import LOGGER
from .settings_store import get_typed_setting_by_key, set_typed_setting_by_key
from .system_identity import system_identity
from .time_utils import utc_now

SETTING_SMTP_SERVERS = "smtp_servers"
SETTING_SMTP_PORT = "smtp_port"
SETTING_SMTP_ANONYMOUS = "smtp_anonymous"
SETTING_SMTP_USERNAME = "smtp_username"
SETTING_SMTP_PASSWORD = "smtp_password"
SETTING_SMTP_FROM = "smtp_from"
SETTING_SMTP_SECURITY = "smtp_security"  # one of "none", "starttls", "ssl"
SETTING_SMTP_TIMEOUT = "smtp_timeout"
SETTING_SMTP_ALLOW_INSECURE_AUTH = "smtp_allow_insecure_auth"

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


def _normalize_level(level: str) -> str:
    cleaned = (level or "").strip().upper()
    if cleaned not in LOG_LEVEL_VALUES:
        return LOG_LEVEL_INFORMATIONAL
    return cleaned


def _normalize_category(category: str | None) -> str | None:
    cleaned = (category or "").strip().lower()
    if not cleaned:
        return None
    return cleaned if cleaned in LOG_CATEGORY_VALUES else cleaned


def _parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


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
    servers = _parse_csv(_typed_str(db, SETTING_SMTP_SERVERS))
    port = _typed_int(db, SETTING_SMTP_PORT, DEFAULT_SMTP_PORT)
    anonymous = _typed_bool(db, SETTING_SMTP_ANONYMOUS)
    security = _typed_str(db, SETTING_SMTP_SECURITY).strip().lower() or DEFAULT_SMTP_SECURITY
    if security not in {"none", "starttls", "ssl"}:
        security = DEFAULT_SMTP_SECURITY
    timeout = _typed_int(db, SETTING_SMTP_TIMEOUT, DEFAULT_SMTP_TIMEOUT)
    password = _typed_str(db, SETTING_SMTP_PASSWORD)
    return {
        "servers": servers,
        "port": port,
        "anonymous": anonymous,
        "username": _typed_str(db, SETTING_SMTP_USERNAME),
        "password": password,
        "from_address": _typed_str(db, SETTING_SMTP_FROM),
        "security": security,
        "timeout": timeout,
        "allow_insecure_auth": _typed_bool(db, SETTING_SMTP_ALLOW_INSECURE_AUTH),
        "password_set": bool(password),
    }


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
    existing_password = _typed_str(db, SETTING_SMTP_PASSWORD)
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

    set_typed_setting_by_key(db, SETTING_SMTP_SERVERS, servers or "")
    set_typed_setting_by_key(db, SETTING_SMTP_PORT, int(port))
    set_typed_setting_by_key(db, SETTING_SMTP_ANONYMOUS, anonymous)
    set_typed_setting_by_key(db, SETTING_SMTP_USERNAME, username or "")
    if password or not preserve_password_if_blank:
        set_typed_setting_by_key(db, SETTING_SMTP_PASSWORD, password or "")
    set_typed_setting_by_key(db, SETTING_SMTP_FROM, from_address or "")
    set_typed_setting_by_key(db, SETTING_SMTP_SECURITY, cleaned_security)
    set_typed_setting_by_key(db, SETTING_SMTP_TIMEOUT, int(timeout))
    set_typed_setting_by_key(db, SETTING_SMTP_ALLOW_INSECURE_AUTH, allow_insecure_auth)


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
        if rule.category and _normalize_category(rule.category) != _normalize_category(row.category):
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

        from .activity_logging import emit_activity_event

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
