from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session

from .. import activity_logging
from ..activity_logging import (
    apply_remote_syslog_config,
    configure_operational_logging,
    emit_activity_event,
    get_log_level,
    is_running_in_docker,
    set_app_dns_name,
    set_log_level,
    set_remote_syslog_config,
    set_retention_days,
    set_smtp_config,
)
from ..db import get_db
from ..event_types import (
    EVENT_SYSTEM_SYSLOG_UPDATED,
)
from ..models import (
    LOG_LEVEL_INFORMATIONAL,
)
from ..rbac import (
    ROLE_SYSTEM_UPDATE,
    require_role,
)
from ..settings_context import render_settings
from ..settings_store import set_typed_setting_by_key

router = APIRouter(tags=["settings"], include_in_schema=False)


@router.post("/settings/system/app-dns-name", response_class=HTMLResponse, include_in_schema=False)
def settings_update_app_dns_name(
    request: Request,
    app_dns_name: str = Form(...),
    redirect_section: str = Form("system_identity"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    try:
        applied = set_app_dns_name(db, app_dns_name)
        emit_activity_event(
            db,
            event_type="system.app_dns_name_changed",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"App DNS name set to {applied}",
            details={"app_dns_name": applied},
        )
    except ValueError as exc:
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message=f"App DNS name saved as {applied}.",
        section=redirect_section,
    )


@router.post("/settings/system/log-level", response_class=HTMLResponse, include_in_schema=False)
def settings_update_log_level(
    request: Request,
    log_level: str = Form(...),
    redirect_area: str = Form("system_settings"),
    redirect_section: str = Form("logging_configuration"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    target_area = (redirect_area or "system_settings").strip().lower()
    if target_area not in {"system_settings", "log_viewing"}:
        target_area = "system_settings"
    target_section = redirect_section if target_area == "system_settings" else None
    try:
        previous = None
        previous = get_log_level(db)
        applied = set_log_level(db, log_level)
        configure_operational_logging(level=applied)
        emit_activity_event(
            db,
            event_type="system.log_level_changed",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Activity log level set to {applied}",
            details={"previous_level": previous, "new_level": applied},
        )
    except ValueError as exc:
        return render_settings(
            request, user, target_area, db=db, message=str(exc), message_kind="error", section=target_section
        )
    return render_settings(
        request, user, target_area, db=db, message=f"Activity log level set to {applied}.", section=target_section
    )


@router.post("/settings/system/retention", response_class=HTMLResponse, include_in_schema=False)
def settings_update_retention(
    request: Request,
    retention_days: int = Form(...),
    redirect_section: str = Form("audit_log_retention"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    if retention_days < 1:
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message="Retention must be at least 1 day.",
            message_kind="error",
            section=redirect_section,
        )
    applied = set_retention_days(db, retention_days)
    emit_activity_event(
        db,
        event_type="system.retention_changed",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"Activity log retention set to {applied} days",
        details={"retention_days": applied},
    )
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message=f"Activity log retention set to {applied} days.",
        section=redirect_section,
    )


@router.post("/settings/system/smtp", response_class=HTMLResponse, include_in_schema=False)
def settings_update_smtp(
    request: Request,
    smtp_servers: str = Form(""),
    smtp_port: int = Form(activity_logging.DEFAULT_SMTP_PORT),
    smtp_security: str = Form(activity_logging.DEFAULT_SMTP_SECURITY),
    smtp_anonymous: str | None = Form(None),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    smtp_timeout: int = Form(activity_logging.DEFAULT_SMTP_TIMEOUT),
    smtp_allow_insecure_auth: str | None = Form(None),
    redirect_section: str = Form("smtp_delivery"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    anonymous = smtp_anonymous is not None
    allow_insecure_auth = smtp_allow_insecure_auth is not None
    try:
        set_smtp_config(
            db,
            servers=smtp_servers,
            port=smtp_port,
            anonymous=anonymous,
            username=smtp_username,
            password=smtp_password,
            from_address=smtp_from,
            security=smtp_security,
            timeout=smtp_timeout,
            allow_insecure_auth=allow_insecure_auth,
        )
        emit_activity_event(
            db,
            event_type="system.smtp_updated",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message="SMTP delivery settings updated",
            details={
                "servers_count": len([s for s in (smtp_servers or "").split(",") if s.strip()]),
                "anonymous": anonymous,
                "security": smtp_security,
                "allow_insecure_auth": allow_insecure_auth,
            },
        )
    except ValueError as exc:
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )
    return render_settings(
        request, user, "system_settings", db=db, message="SMTP delivery settings saved.", section=redirect_section
    )


@router.post("/settings/system/syslog", response_class=HTMLResponse, include_in_schema=False)
def settings_update_syslog(
    request: Request,
    syslog_enabled: str | None = Form(None),
    syslog_host: str = Form(""),
    syslog_port: int = Form(6514),
    syslog_protocol: str = Form("tls"),
    syslog_facility: str = Form("local0"),
    syslog_minimum_level: str = Form(LOG_LEVEL_INFORMATIONAL),
    syslog_timeout: float = Form(5.0),
    syslog_queue_size: int = Form(1000),
    syslog_allow_insecure_plaintext: str | None = Form(None),
    redirect_section: str = Form("syslog_forwarding"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    enabled = syslog_enabled is not None
    allow_insecure_plaintext = syslog_allow_insecure_plaintext is not None
    try:
        config = set_remote_syslog_config(
            db,
            enabled=enabled,
            host=syslog_host,
            port=syslog_port,
            protocol=syslog_protocol,
            facility=syslog_facility,
            minimum_level=syslog_minimum_level,
            timeout=syslog_timeout,
            queue_size=syslog_queue_size,
            allow_insecure_plaintext=allow_insecure_plaintext,
        )
        apply_remote_syslog_config(db)
        emit_activity_event(
            db,
            event_type=EVENT_SYSTEM_SYSLOG_UPDATED,
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message="Remote syslog settings updated",
            details={
                "enabled": bool(config.get("enabled")),
                "host": config.get("host") or "",
                "port": config.get("port"),
                "protocol": config.get("protocol"),
                "facility": config.get("facility"),
                "minimum_level": config.get("minimum_level"),
                "timeout": config.get("timeout"),
                "queue_size": config.get("queue_size"),
                "allow_insecure_plaintext": bool(config.get("allow_insecure_plaintext")),
            },
        )
    except ValueError as exc:
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message="Remote syslog settings saved.",
        section=redirect_section,
    )


@router.post("/settings/system/log-rotation", response_class=HTMLResponse, include_in_schema=False)
def settings_update_log_rotation(
    request: Request,
    log_file: str = Form(""),
    max_bytes: int = Form(1_048_576),
    backup_count: int = Form(5),
    redirect_section: str = Form("operational_log_rotation"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    if is_running_in_docker():
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message="Operational log rotation is managed by Docker in container deployments.",
            message_kind="error",
            section=redirect_section,
        )
    set_typed_setting_by_key(db, activity_logging.SETTING_LOG_FILE, log_file or "")
    set_typed_setting_by_key(db, activity_logging.SETTING_LOG_MAX_BYTES, max(1024, int(max_bytes)))
    set_typed_setting_by_key(db, activity_logging.SETTING_LOG_BACKUP_COUNT, max(0, int(backup_count)))
    configure_operational_logging(
        level=get_log_level(db),
        log_file=log_file or None,
        max_bytes=max(1024, int(max_bytes)),
        backup_count=max(0, int(backup_count)),
    )
    emit_activity_event(
        db,
        event_type="system.log_rotation_updated",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message="Operational log rotation updated",
        details={
            "log_file_configured": bool(log_file),
            "max_bytes": max(1024, int(max_bytes)),
            "backup_count": max(0, int(backup_count)),
        },
    )
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message="Operational log rotation saved.",
        section=redirect_section,
    )
