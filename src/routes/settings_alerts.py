from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from ..activity_logging import (
    emit_activity_event,
)
from ..db import SessionLocal
from ..models import (
    LOG_CATEGORY_VALUES,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_VALUES,
    LOG_LEVEL_WARNING,
    AlertRule,
)
from ..rbac import (
    ROLE_SYSTEM_UPDATE,
    require_role,
)
from ..settings_context import render_settings

router = APIRouter(tags=["settings"], include_in_schema=False)


@router.post("/settings/alerts", response_class=HTMLResponse, include_in_schema=False)
def settings_alerts_create(
    request: Request,
    name: str = Form(...),
    event_type: str = Form(""),
    category: str = Form(""),
    minimum_level: str = Form(LOG_LEVEL_WARNING),
    message_contains: str = Form(""),
    email_recipients: str = Form(...),
    email_subject_template: str = Form(""),
    email_body_template: str = Form(""),
    cooldown_minutes: int = Form(0),
    enabled: str | None = Form("on"),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    cleaned_level = (minimum_level or LOG_LEVEL_WARNING).strip().upper()
    if cleaned_level not in LOG_LEVEL_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported level: {minimum_level}", message_kind="error"
        )
    cleaned_category = (category or "").strip().lower()
    if cleaned_category and cleaned_category not in LOG_CATEGORY_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported category: {category}", message_kind="error"
        )
    if not email_recipients.strip():
        return render_settings(
            request, user, "email_alerting", message="At least one email recipient is required.", message_kind="error"
        )
    with SessionLocal() as db:
        rule = AlertRule(
            enabled=bool(enabled),
            name=name.strip(),
            event_type=event_type.strip() or None,
            category=cleaned_category or None,
            minimum_level=cleaned_level,
            message_contains=message_contains.strip() or None,
            email_recipients=email_recipients.strip(),
            email_subject_template=email_subject_template,
            email_body_template=email_body_template,
            cooldown_minutes=max(0, int(cooldown_minutes)),
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        emit_activity_event(
            db,
            event_type="alert_rule.created",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Alert rule {name!r} created",
            details={
                "rule_id": rule.id,
                "rule_name": rule.name,
                "category": cleaned_category,
                "minimum_level": cleaned_level,
            },
        )
    return render_settings(request, user, "email_alerting", message=f"Alert rule {name!r} created.")


@router.post("/settings/alerts/{rule_id}", response_class=HTMLResponse, include_in_schema=False)
def settings_alerts_update(
    request: Request,
    rule_id: int,
    name: str = Form(...),
    event_type: str = Form(""),
    category: str = Form(""),
    minimum_level: str = Form(LOG_LEVEL_WARNING),
    message_contains: str = Form(""),
    email_recipients: str = Form(...),
    email_subject_template: str = Form(""),
    email_body_template: str = Form(""),
    cooldown_minutes: int = Form(0),
    enabled: str | None = Form(None),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    cleaned_level = (minimum_level or LOG_LEVEL_WARNING).strip().upper()
    if cleaned_level not in LOG_LEVEL_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported level: {minimum_level}", message_kind="error"
        )
    cleaned_category = (category or "").strip().lower()
    if cleaned_category and cleaned_category not in LOG_CATEGORY_VALUES:
        return render_settings(
            request, user, "email_alerting", message=f"Unsupported category: {category}", message_kind="error"
        )
    with SessionLocal() as db:
        rule = db.get(AlertRule, rule_id)
        if rule is None:
            return render_settings(
                request, user, "email_alerting", message="Alert rule not found.", message_kind="error"
            )
        rule.enabled = enabled is not None
        rule.name = name.strip()
        rule.event_type = event_type.strip() or None
        rule.category = cleaned_category or None
        rule.minimum_level = cleaned_level
        rule.message_contains = message_contains.strip() or None
        rule.email_recipients = email_recipients.strip()
        rule.email_subject_template = email_subject_template
        rule.email_body_template = email_body_template
        rule.cooldown_minutes = max(0, int(cooldown_minutes))
        db.add(rule)
        db.commit()
        emit_activity_event(
            db,
            event_type="alert_rule.updated",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Alert rule {name!r} updated",
            details={
                "rule_id": rule_id,
                "rule_name": rule.name,
                "category": cleaned_category,
                "minimum_level": cleaned_level,
            },
        )
    return render_settings(request, user, "email_alerting", message=f"Alert rule {name!r} updated.")


@router.post("/settings/alerts/{rule_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def settings_alerts_delete(
    request: Request,
    rule_id: int,
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    with SessionLocal() as db:
        rule = db.get(AlertRule, rule_id)
        if rule is None:
            return render_settings(
                request, user, "email_alerting", message="Alert rule not found.", message_kind="error"
            )
        rule_name = rule.name
        db.delete(rule)
        db.commit()
        emit_activity_event(
            db,
            event_type="alert_rule.deleted",
            level=LOG_LEVEL_WARNING,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Alert rule {rule_name!r} deleted",
            details={"rule_id": rule_id, "rule_name": rule_name},
        )
    return render_settings(request, user, "email_alerting", message=f"Alert rule {rule_name!r} deleted.")
