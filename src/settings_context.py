from typing import Any

from fastapi import Request
from sqlmodel import select

from . import activity_logging
from .activity_logging import (
    DEFAULT_BODY_TEMPLATE,
    DEFAULT_SUBJECT_TEMPLATE,
    get_log_level,
    get_remote_syslog_config,
    get_retention_days,
    get_smtp_config,
    is_running_in_docker,
    query_activity_logs,
    system_identity,
)
from .db import SessionLocal
from .letsencrypt import config_view as letsencrypt_config_view
from .models import LOG_CATEGORY_VALUES, LOG_LEVEL_VALUES, AlertRule, User
from .rbac import (
    BACKUP_SECTIONS,
    ROLE_ACCOUNT_RESET_PASSWORD,
    ROLE_ACCOUNT_UPDATE,
    ROLE_GLOBAL_ADMIN,
    ROLE_GLOBAL_READ,
    ROLE_PLUGIN_UPDATE,
    ROLE_SYSTEM_UPDATE,
    SYSTEM_SETTINGS_SECTIONS,
    accessible_settings_areas,
    default_backup_section,
    default_system_settings_section,
    get_user_roles,
    normalize_backup_section,
    normalize_system_settings_section,
    role_catalog_for_actor,
    user_public_dict,
)
from .restart import is_restart_required
from .settings_store import get_setting
from .ssl_certs import (
    DEFAULT_HTTP_PORT,
    DEFAULT_TLS_PORT,
    SOURCE_LETSENCRYPT,
    access_url,
    cert_exists,
    cert_metadata,
    cert_paths,
    http_port,
    is_ssl_enabled,
    tls_port,
)
from .web import nav_context, templates
from .zone_service import dns_provider_options_with_state

LOG_SEARCH_PAGE_SIZE = 25
ALERT_TEMPLATE_VARIABLES: list[dict[str, str]] = [
    {"name": "{event_type}", "description": "Activity event identifier (e.g. dns.record_created)"},
    {"name": "{level}", "description": "Event severity: VERBOSE, INFORMATIONAL, WARNING, or ERROR"},
    {"name": "{category}", "description": "Event category, such as security, http, dns, alert, system, or user"},
    {"name": "{timestamp}", "description": "Event timestamp in UTC ISO 8601"},
    {"name": "{message}", "description": "Short human-readable summary"},
    {"name": "{status}", "description": "success or error"},
    {"name": "{actor_type}", "description": "user, api_key, system, or anonymous"},
    {"name": "{actor_label}", "description": "Username or API key label"},
    {"name": "{zone_name}", "description": "DNS zone associated with the event (if any)"},
    {"name": "{record_name}", "description": "DNS record name (if any)"},
    {"name": "{details}", "description": "JSON-encoded sanitized event detail payload"},
    {"name": "{system_dns_name}", "description": "Configured app DNS name (System Settings → App DNS Name)"},
    {
        "name": "{system_ip_address}",
        "description": "Detected system IP address (or Docker container runtime message when containerized)",
    },
]


def settings_context(
    request: Request,
    user: str,
    area: str | None,
    message: str | None = None,
    message_kind: str = "success",
    auth_form_error: str | None = None,
    auth_form_username: str | None = None,
    auth_form_selected_roles: list[str] | None = None,
    log_search_params: dict[str, Any] | None = None,
    section: str | None = None,
) -> dict[str, Any]:
    with SessionLocal() as db:
        user_roles = get_user_roles(db, user)
        can_view_accounts = bool(
            {ROLE_GLOBAL_READ, ROLE_ACCOUNT_UPDATE, ROLE_ACCOUNT_RESET_PASSWORD}.intersection(user_roles)
        )
        users_view = (
            [user_public_dict(u) for u in sorted(db.exec(select(User)).all(), key=lambda u: u.username.lower())]
            if can_view_accounts
            else []
        )
        plugin_options = (
            dns_provider_options_with_state(db)
            if ROLE_GLOBAL_READ in user_roles or ROLE_PLUGIN_UPDATE in user_roles
            else []
        )
        accessible = accessible_settings_areas(user_roles)
        accessible_keys = {a["key"] for a in accessible}
        requested_area = (area or "").strip().lower() or (accessible[0]["key"] if accessible else "")
        if requested_area not in accessible_keys:
            requested_area = accessible[0]["key"] if accessible else ""

        can_access_system_settings = "system_settings" in accessible_keys
        selected_system_section = (
            normalize_system_settings_section(section)
            if requested_area == "system_settings" and can_access_system_settings
            else default_system_settings_section()
        )
        system_settings_sections = list(SYSTEM_SETTINGS_SECTIONS) if can_access_system_settings else []

        can_access_backup = "backup" in accessible_keys
        selected_backup_section = (
            normalize_backup_section(section)
            if requested_area == "backup" and can_access_backup
            else default_backup_section()
        )
        backup_sections = list(BACKUP_SECTIONS) if can_access_backup else []

        system_settings_view: dict[str, Any] | None = None
        log_view: dict[str, Any] | None = None
        alert_view: dict[str, Any] | None = None

        if requested_area in {"system_settings", "log_viewing", "email_alerting"} and (
            ROLE_GLOBAL_READ in user_roles or ROLE_SYSTEM_UPDATE in user_roles
        ):
            identity = system_identity(db)
            smtp = get_smtp_config(db)
            syslog = get_remote_syslog_config(db)
            current_level = get_log_level(db)
            retention_days = get_retention_days(db)
            ssl_enabled_flag = is_ssl_enabled(db)
            ssl_has_cert = cert_exists()
            ssl_key_path, ssl_cert_path = cert_paths()
            ssl_status = {
                "enabled": ssl_enabled_flag,
                "cert_exists": ssl_has_cert,
                "can_enable_ssl": ssl_has_cert,
                "can_upload": ROLE_SYSTEM_UPDATE in user_roles,
                "metadata": cert_metadata(),
                "source_letsencrypt": SOURCE_LETSENCRYPT,
                "access_url": access_url(db),
                "ports": {
                    "http": http_port(),
                    "https": tls_port(),
                    "default_http": DEFAULT_HTTP_PORT,
                    "default_https": DEFAULT_TLS_PORT,
                },
                "key_path": str(ssl_key_path),
                "cert_path": str(ssl_cert_path),
                "app_dns_name": identity.get("system_dns_name", ""),
                "letsencrypt": letsencrypt_config_view(db),
                "restart_required": is_restart_required(db),
            }
            shared_system = {
                "identity": identity,
                "is_docker": is_running_in_docker(),
                "log_level": current_level,
                "log_levels": list(LOG_LEVEL_VALUES),
                "log_categories": list(LOG_CATEGORY_VALUES),
                "retention_days": retention_days,
                "retention_options": [
                    {"value": 1, "label": "24 hours"},
                    {"value": 7, "label": "1 week"},
                    {"value": 30, "label": "30 days"},
                    {"value": 60, "label": "60 days"},
                    {"value": 90, "label": "90 days"},
                    {"value": 180, "label": "180 days"},
                    {"value": 365, "label": "365 days"},
                ],
                "smtp": {
                    "servers": smtp.get("servers") or [],
                    "port": smtp.get("port"),
                    "anonymous": bool(smtp.get("anonymous")),
                    "username": smtp.get("username") or "",
                    "from_address": smtp.get("from_address") or "",
                    "security": smtp.get("security") or activity_logging.DEFAULT_SMTP_SECURITY,
                    "timeout": smtp.get("timeout"),
                    "allow_insecure_auth": bool(smtp.get("allow_insecure_auth")),
                    "password_set": bool(smtp.get("password_set") or smtp.get("password")),
                },
                "syslog": {
                    "enabled": bool(syslog.get("enabled")),
                    "host": syslog.get("host") or "",
                    "port": syslog.get("port"),
                    "protocol": syslog.get("protocol") or "tls",
                    "facility": syslog.get("facility") or "local0",
                    "minimum_level": syslog.get("minimum_level") or "INFORMATIONAL",
                    "timeout": syslog.get("timeout"),
                    "queue_size": syslog.get("queue_size"),
                    "allow_insecure_plaintext": bool(syslog.get("allow_insecure_plaintext")),
                    "facilities": syslog.get("facilities") or [],
                    "protocols": syslog.get("protocols") or ["tls", "udp", "tcp"],
                },
                "ssl": ssl_status,
                "operational_log": {
                    "log_file": get_setting(db, activity_logging.SETTING_LOG_FILE) or "",
                    "max_bytes": int(get_setting(db, activity_logging.SETTING_LOG_MAX_BYTES) or 1_048_576),
                    "backup_count": int(get_setting(db, activity_logging.SETTING_LOG_BACKUP_COUNT) or 5),
                },
            }

            if requested_area == "system_settings":
                system_settings_view = shared_system

            if requested_area == "log_viewing":
                params = log_search_params or {}
                rows, total = query_activity_logs(
                    db,
                    event_type=params.get("event_type") or None,
                    level=params.get("level") or None,
                    category=params.get("category") or None,
                    status=params.get("status") or None,
                    zone_name=params.get("zone_name") or None,
                    actor=params.get("actor") or None,
                    text_query=params.get("text_query") or None,
                    start=params.get("start"),
                    end=params.get("end"),
                    limit=LOG_SEARCH_PAGE_SIZE,
                    offset=max(0, int(params.get("offset") or 0)),
                )
                current_offset = max(0, int(params.get("offset") or 0))
                previous_offset = max(0, current_offset - LOG_SEARCH_PAGE_SIZE)
                next_offset = current_offset + LOG_SEARCH_PAGE_SIZE
                log_view = {
                    "shared": shared_system,
                    "params": params,
                    "rows": [
                        {
                            "id": row.id,
                            "timestamp": row.timestamp.isoformat() if row.timestamp else "",
                            "level": row.level,
                            "category": row.category or "",
                            "event_type": row.event_type,
                            "status": row.status or "",
                            "actor_type": row.actor_type or "",
                            "actor_label": row.actor_label or "",
                            "zone_name": row.zone_name or "",
                            "record_name": row.record_name or "",
                            "message": row.message or "",
                            "details_json": row.details_json or "",
                            "request_method": row.request_method or "",
                            "request_path": row.request_path or "",
                            "request_status_code": row.request_status_code,
                            "request_ip": row.request_ip or "",
                        }
                        for row in rows
                    ],
                    "total": total,
                    "page_size": LOG_SEARCH_PAGE_SIZE,
                    "offset": current_offset,
                    "previous_offset": previous_offset,
                    "next_offset": next_offset,
                    "has_previous": current_offset > 0,
                    "has_next": next_offset < total,
                }

            if requested_area == "email_alerting":
                rules = list(db.exec(select(AlertRule)).all())
                alert_view = {
                    "shared": shared_system,
                    "rules": [
                        {
                            "id": rule.id,
                            "enabled": rule.enabled,
                            "name": rule.name or "",
                            "event_type": rule.event_type or "",
                            "category": rule.category or "",
                            "minimum_level": rule.minimum_level,
                            "message_contains": rule.message_contains or "",
                            "email_recipients": rule.email_recipients or "",
                            "email_subject_template": rule.email_subject_template or "",
                            "email_body_template": rule.email_body_template or "",
                            "cooldown_minutes": rule.cooldown_minutes,
                            "last_triggered_at": rule.last_triggered_at.isoformat() if rule.last_triggered_at else "",
                        }
                        for rule in sorted(rules, key=lambda r: (r.name or "", r.id or 0))
                    ],
                    "template_variables": ALERT_TEMPLATE_VARIABLES,
                    "default_subject": DEFAULT_SUBJECT_TEMPLATE,
                    "default_body": DEFAULT_BODY_TEMPLATE,
                }
        nav = nav_context(db, user, show_dashboard_link=True)

    return {
        "request": request,
        "user": user,
        "user_roles": sorted(user_roles),
        "accessible_areas": accessible,
        "selected_area": requested_area,
        "users": users_view,
        "role_catalog": role_catalog_for_actor(db, user) if can_view_accounts else [],
        "plugins": plugin_options,
        "message": message,
        "message_kind": message_kind,
        "auth_form_error": auth_form_error,
        "auth_form_username": auth_form_username or "",
        "auth_form_selected_roles": [] if auth_form_selected_roles is None else auth_form_selected_roles,
        "can_view_accounts": can_view_accounts,
        "can_account_update": ROLE_ACCOUNT_UPDATE in user_roles,
        "can_account_reset_password": ROLE_ACCOUNT_RESET_PASSWORD in user_roles,
        "can_global_admin": ROLE_GLOBAL_ADMIN in user_roles,
        "can_plugin_update": ROLE_PLUGIN_UPDATE in user_roles,
        "can_system_update": ROLE_SYSTEM_UPDATE in user_roles,
        "system_settings_view": system_settings_view,
        "system_settings_sections": system_settings_sections,
        "selected_system_section": selected_system_section,
        "backup_sections": backup_sections,
        "selected_backup_section": selected_backup_section,
        "can_backup": can_access_backup,
        "log_view": log_view,
        "alert_view": alert_view,
        **nav,
    }


def render_settings(request: Request, user: str, area: str | None, **kwargs: Any):
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=settings_context(request, user, area, **kwargs),
    )
