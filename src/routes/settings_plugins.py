from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session

from ..activity_logging import (
    emit_activity_event,
)
from ..db import get_db
from ..log_constants import (
    LOG_LEVEL_INFORMATIONAL,
)
from ..rbac import (
    ROLE_PLUGIN_UPDATE,
    require_role,
)
from ..settings_context import render_settings
from ..zone_service import (
    dns_provider_display_name,
    get_disabled_dns_plugins,
    get_dns_provider_options,
    get_known_dns_provider_keys,
    set_disabled_dns_plugins,
    zones_using_dns_provider,
)

router = APIRouter(tags=["settings"], include_in_schema=False)


@router.post("/settings/plugins/{plugin_key}/disable", response_class=HTMLResponse, include_in_schema=False)
def settings_plugin_disable(
    request: Request,
    plugin_key: str,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_PLUGIN_UPDATE)),
):
    normalized_key = plugin_key.strip().lower()
    known_keys = get_known_dns_provider_keys()
    if normalized_key not in known_keys:
        return render_settings(
            request,
            user,
            "plugins",
            db=db,
            message=f"Unknown DNS provider plugin: {plugin_key}.",
            message_kind="error",
        )

    disabled = get_disabled_dns_plugins(db)
    if normalized_key in disabled:
        return render_settings(
            request, user, "plugins", db=db, message=f"{dns_provider_display_name(normalized_key)} is already disabled."
        )
    enabled_count = len([plugin for plugin in get_dns_provider_options() if plugin["key"] not in disabled])
    if enabled_count <= 1:
        return render_settings(
            request,
            user,
            "plugins",
            db=db,
            message="At least one DNS provider plugin must remain enabled.",
            message_kind="error",
        )
    zone_names = zones_using_dns_provider(db, normalized_key)
    if zone_names:
        zones_text = ", ".join(zone_names)
        first_zone = zone_names[0]
        return render_settings(
            request,
            user,
            "plugins",
            db=db,
            message=(
                f"Cannot disable {dns_provider_display_name(normalized_key)}. Delete DNS zone {first_zone} first."
                if len(zone_names) == 1
                else f"Cannot disable {dns_provider_display_name(normalized_key)}. Delete DNS zones {zones_text} first."
            ),
            message_kind="error",
        )
    disabled.add(normalized_key)
    set_disabled_dns_plugins(db, disabled)
    emit_activity_event(
        db,
        event_type="plugin.disabled",
        level=LOG_LEVEL_INFORMATIONAL,
        status="success",
        actor_type="user",
        actor_label=user,
        message=f"Plugin {normalized_key!r} disabled",
        details={"plugin_key": normalized_key},
    )

    return render_settings(
        request, user, "plugins", db=db, message=f"{dns_provider_display_name(normalized_key)} disabled."
    )


@router.post("/settings/plugins/{plugin_key}/enable", response_class=HTMLResponse, include_in_schema=False)
def settings_plugin_enable(
    request: Request,
    plugin_key: str,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_PLUGIN_UPDATE)),
):
    normalized_key = plugin_key.strip().lower()
    known_keys = get_known_dns_provider_keys()
    if normalized_key not in known_keys:
        return render_settings(
            request,
            user,
            "plugins",
            db=db,
            message=f"Unknown DNS provider plugin: {plugin_key}.",
            message_kind="error",
        )

    disabled = get_disabled_dns_plugins(db)
    was_disabled = normalized_key in disabled
    disabled.discard(normalized_key)
    set_disabled_dns_plugins(db, disabled)
    if was_disabled:
        emit_activity_event(
            db,
            event_type="plugin.enabled",
            level=LOG_LEVEL_INFORMATIONAL,
            status="success",
            actor_type="user",
            actor_label=user,
            message=f"Plugin {normalized_key!r} enabled",
            details={"plugin_key": normalized_key},
        )

    return render_settings(
        request, user, "plugins", db=db, message=f"{dns_provider_display_name(normalized_key)} enabled."
    )
