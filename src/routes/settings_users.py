from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from ..activity_logging import (
    emit_activity_event,
)
from ..auth import (
    bump_session_version,
    create_session_cookie,
    get_current_user_db,
    session_cookie_secure,
    session_cookie_settings,
)
from ..db import get_db
from ..models import (
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_WARNING,
    User,
)
from ..rbac import (
    ROLE_ACCOUNT_RESET_PASSWORD,
    ROLE_ACCOUNT_UPDATE,
    global_admin_guard_message,
    normalize_selected_roles,
    parse_roles,
    require_role,
    serialize_roles,
    validate_role_assignment,
)
from ..security import hash_password, verify_password
from ..settings_context import render_settings

router = APIRouter(tags=["settings"], include_in_schema=False)


@router.post("/settings/account/password", response_class=HTMLResponse, include_in_schema=False)
def settings_self_password_change(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user_db),
):
    if not new_password:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="A new password is required.",
            message_kind="error",
        )
    if new_password != confirm_password:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="New password and confirmation do not match.",
            message_kind="error",
        )
    target = db.exec(select(User).where(User.username == user)).first()
    if target is None or not verify_password(current_password, target.password_hash):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="Current password is incorrect.",
            message_kind="error",
        )
    target.password_hash = hash_password(new_password)
    new_version = bump_session_version(db, target)
    emit_activity_event(
        db,
        event_type="user.password_changed",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"User {user!r} changed their own password",
        details={"target_username": user},
    )
    response = render_settings(request, user, "authentication", db=db, message="Password changed.")
    response.set_cookie(
        "session",
        create_session_cookie(user, new_version),
        **session_cookie_settings(secure=session_cookie_secure(request)),
    )
    request.state.session_version = new_version
    return response


@router.post("/settings/users", response_class=HTMLResponse, include_in_schema=False)
def settings_user_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    roles: list[str] = Form(default_factory=list),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    normalized = username.strip()
    selected_roles = normalize_selected_roles(roles)
    if not normalized:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            auth_form_error="Username is required.",
            auth_form_username=username,
            auth_form_selected_roles=selected_roles,
        )
    if not password:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            auth_form_error="Password is required.",
            auth_form_username=normalized,
            auth_form_selected_roles=selected_roles,
        )
    if assignment_error := validate_role_assignment(db, user, selected_roles):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            auth_form_error=assignment_error,
            auth_form_username=normalized,
            auth_form_selected_roles=selected_roles,
        )
    if db.exec(select(User).where(User.username == normalized)).first():
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            auth_form_error=f"A user named {normalized!r} already exists.",
            auth_form_username=normalized,
            auth_form_selected_roles=selected_roles,
        )
    db.add(
        User(
            username=normalized,
            password_hash=hash_password(password),
            roles=serialize_roles(selected_roles),
            session_version=0,
        )
    )
    db.commit()
    emit_activity_event(
        db,
        event_type="user.created",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"User {normalized!r} created",
        details={"target_username": normalized, "roles": selected_roles},
    )
    return render_settings(
        request,
        user,
        "authentication",
        db=db,
        message=f"User {normalized!r} created.",
    )


@router.post("/settings/users/{user_id}/disable", response_class=HTMLResponse, include_in_schema=False)
def settings_user_disable(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    target = db.get(User, user_id)
    if not target:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="User not found.",
            message_kind="error",
        )
    if guard_message := global_admin_guard_message(db, user, target):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=guard_message,
            message_kind="error",
        )
    if target.disabled:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=f"User {target.username!r} is already disabled.",
            message_kind="error",
        )
    enabled_users = db.exec(select(User).where(User.disabled == False)).all()  # noqa: E712
    if len(enabled_users) <= 1:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="At least one enabled user account must remain.",
            message_kind="error",
        )
    if target.username == user:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="You cannot disable the user you are signed in as.",
            message_kind="error",
        )
    target.disabled = True
    bump_session_version(db, target)
    username = target.username
    emit_activity_event(
        db,
        event_type="user.disabled",
        level=LOG_LEVEL_WARNING,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"User {username!r} disabled",
        details={"target_username": username, "target_user_id": user_id},
    )
    return render_settings(
        request,
        user,
        "authentication",
        db=db,
        message=f"User {username!r} disabled.",
    )


@router.post("/settings/users/{user_id}/enable", response_class=HTMLResponse, include_in_schema=False)
def settings_user_enable(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    target = db.get(User, user_id)
    if not target:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="User not found.",
            message_kind="error",
        )
    if guard_message := global_admin_guard_message(db, user, target):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=guard_message,
            message_kind="error",
        )
    if not target.disabled:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=f"User {target.username!r} is already enabled.",
            message_kind="error",
        )
    target.disabled = False
    db.add(target)
    db.commit()
    username = target.username
    emit_activity_event(
        db,
        event_type="user.enabled",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"User {username!r} enabled",
        details={"target_username": username, "target_user_id": user_id},
    )
    return render_settings(
        request,
        user,
        "authentication",
        db=db,
        message=f"User {username!r} enabled.",
    )


@router.post("/settings/users/{user_id}/delete", response_class=HTMLResponse, include_in_schema=False)
def settings_user_delete(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    target = db.get(User, user_id)
    if not target:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="User not found.",
            message_kind="error",
        )
    if guard_message := global_admin_guard_message(db, user, target):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=guard_message,
            message_kind="error",
        )
    remaining = db.exec(select(User)).all()
    if len(remaining) <= 1:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="At least one user account must remain.",
            message_kind="error",
        )
    if target.username == user:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="You cannot delete the user you are signed in as.",
            message_kind="error",
        )
    if not target.disabled:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="Disable the user account before deleting it.",
            message_kind="error",
        )
    username = target.username
    db.delete(target)
    db.commit()
    emit_activity_event(
        db,
        event_type="user.deleted",
        level=LOG_LEVEL_WARNING,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"User {username!r} deleted",
        details={"target_username": username, "target_user_id": user_id},
    )
    return render_settings(
        request,
        user,
        "authentication",
        db=db,
        message=f"User {username!r} deleted.",
    )


@router.post("/settings/users/{user_id}/password", response_class=HTMLResponse, include_in_schema=False)
def settings_user_reset_password(
    request: Request,
    user_id: int,
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_ACCOUNT_RESET_PASSWORD)),
):
    if not password or not confirm_password:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="A new password is required.",
            message_kind="error",
        )
    if password != confirm_password:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="New password and confirmation do not match.",
            message_kind="error",
        )
    target = db.get(User, user_id)
    if not target:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="User not found.",
            message_kind="error",
        )
    if guard_message := global_admin_guard_message(db, user, target):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=guard_message,
            message_kind="error",
        )
    if target.disabled:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="Enable the user account before resetting its password.",
            message_kind="error",
        )
    target.password_hash = hash_password(password)
    bump_session_version(db, target)
    username = target.username
    emit_activity_event(
        db,
        event_type="user.password_reset",
        level=LOG_LEVEL_WARNING,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"Password reset for {username!r}",
        details={"target_username": username, "target_user_id": user_id},
    )
    return render_settings(
        request,
        user,
        "authentication",
        db=db,
        message=f"Password reset for {username!r}.",
    )


@router.post("/settings/users/{user_id}/roles", response_class=HTMLResponse, include_in_schema=False)
def settings_user_update_roles(
    request: Request,
    user_id: int,
    roles: list[str] = Form(default_factory=list),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_ACCOUNT_UPDATE)),
):
    selected = normalize_selected_roles(roles)
    target = db.get(User, user_id)
    if not target:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="User not found.",
            message_kind="error",
        )
    if guard_message := global_admin_guard_message(db, user, target):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=guard_message,
            message_kind="error",
        )
    if target.username == user:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="You cannot edit roles for the user you are signed in as.",
            message_kind="error",
        )
    target_stored_roles = parse_roles(target.roles)
    if assignment_error := validate_role_assignment(
        db,
        user,
        selected,
        previous_roles=target_stored_roles,
    ):
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message=assignment_error,
            message_kind="error",
        )
    if target.disabled:
        return render_settings(
            request,
            user,
            "authentication",
            db=db,
            message="Enable the user account before editing its roles.",
            message_kind="error",
        )
    target.roles = serialize_roles(selected)
    bump_session_version(db, target)
    username = target.username
    emit_activity_event(
        db,
        event_type="user.roles_updated",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"Roles updated for {username!r}",
        details={"target_username": username, "roles": selected},
    )
    return render_settings(
        request,
        user,
        "authentication",
        db=db,
        message=f"Roles updated for {username!r}.",
    )
