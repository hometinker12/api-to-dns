"""Application restart coordination.

The process cannot swap HTTP/HTTPS listener mode or TLS files in-place. These
helpers persist a visible pending flag and terminate the current process after
the restart response has been sent.
"""

from __future__ import annotations

import asyncio
import os
import signal
from datetime import datetime
from typing import Any

from .settings_store import delete_setting, get_typed_setting_by_key, set_typed_setting_by_key
from .ssl_certs import access_url

SETTING_RESTART_REQUIRED = "restart_required"
SETTING_RESTART_REASON = "restart_reason"
SETTING_LAST_SCHEDULED_RESTART_DATE = "last_scheduled_restart_date"
SETTING_LE_RENEWAL_PENDING_RESTART = "letsencrypt_renewal_pending_restart"


def _typed_bool(db, key: str) -> bool:
    try:
        return bool(get_typed_setting_by_key(db, key))
    except ValueError:
        return False


def mark_restart_required(db, *, reason: str) -> None:
    set_typed_setting_by_key(db, SETTING_RESTART_REQUIRED, True)
    set_typed_setting_by_key(db, SETTING_RESTART_REASON, reason.strip() or "Application restart required.")


def clear_restart_required(db) -> None:
    delete_setting(db, SETTING_RESTART_REQUIRED)
    delete_setting(db, SETTING_RESTART_REASON)


def is_restart_required(db) -> bool:
    return _typed_bool(db, SETTING_RESTART_REQUIRED)


def restart_reason(db) -> str:
    value = get_typed_setting_by_key(db, SETTING_RESTART_REASON)
    return value or "Application restart required."


def mark_le_renewal_pending_restart(db) -> None:
    set_typed_setting_by_key(db, SETTING_LE_RENEWAL_PENDING_RESTART, True)


def clear_le_renewal_pending_restart(db) -> None:
    delete_setting(db, SETTING_LE_RENEWAL_PENDING_RESTART)


def is_le_renewal_pending_restart(db) -> bool:
    return _typed_bool(db, SETTING_LE_RENEWAL_PENDING_RESTART)


def apply_le_renewal_restart_policy(db, config: dict[str, Any]) -> None:
    if config.get("scheduled_restart_enabled") and config.get("scheduled_restart_time"):
        mark_le_renewal_pending_restart(db)
    else:
        mark_restart_required(db, reason="Let's Encrypt certificate renewed.")


def preview_restart_urls(db) -> dict[str, str]:
    return {
        "current_url": access_url(db, use_env_override=True),
        "after_restart_url": access_url(db, use_env_override=False),
    }


async def _terminate_self(delay_seconds: float) -> None:
    await asyncio.sleep(delay_seconds)
    os.kill(os.getpid(), signal.SIGTERM)


def perform_application_restart(*, scheduled: bool = False, delay_seconds: float = 0.35) -> None:
    """Schedule SIGTERM for this process after the response is returned."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        os.kill(os.getpid(), signal.SIGTERM)
        return
    loop.create_task(_terminate_self(delay_seconds))


def scheduled_restart_due(db, *, configured_time: str, now: datetime | None = None) -> bool:
    current = now or datetime.now().astimezone()
    if current.strftime("%H:%M") != configured_time:
        return False
    today = current.date().isoformat()
    if get_typed_setting_by_key(db, SETTING_LAST_SCHEDULED_RESTART_DATE) == today:
        return False
    set_typed_setting_by_key(db, SETTING_LAST_SCHEDULED_RESTART_DATE, today)
    return True
