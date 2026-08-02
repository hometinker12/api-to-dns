from typing import Any

from fastapi import Depends, HTTPException
from sqlmodel import select

from .auth import get_current_user
from .db import SessionLocal
from .models import User

ROLE_GLOBAL_ADMIN = "global.admin"
ROLE_GLOBAL_READ = "global.read"
ROLE_ACCOUNT_UPDATE = "account.update"
ROLE_ACCOUNT_RESET_PASSWORD = "account.reset_password"
ROLE_API_KEYS_READ = "api_keys.read"
ROLE_API_KEYS_UPDATE = "api_keys.update"
ROLE_DNS_ZONES_READ = "dns_zones.read"
ROLE_DNS_ZONES_UPDATE = "dns_zones.update"
ROLE_PLUGIN_UPDATE = "plugin.update"
ROLE_SYSTEM_UPDATE = "system.update"

ROLE_DEPENDENCIES: dict[str, str] = {
    ROLE_API_KEYS_UPDATE: ROLE_API_KEYS_READ,
    ROLE_DNS_ZONES_UPDATE: ROLE_DNS_ZONES_READ,
}
MANDATORY_ROLES: set[str] = {ROLE_DNS_ZONES_READ}

ALL_ROLES: list[str] = [
    ROLE_GLOBAL_ADMIN,
    ROLE_GLOBAL_READ,
    ROLE_ACCOUNT_UPDATE,
    ROLE_ACCOUNT_RESET_PASSWORD,
    ROLE_API_KEYS_READ,
    ROLE_API_KEYS_UPDATE,
    ROLE_DNS_ZONES_READ,
    ROLE_DNS_ZONES_UPDATE,
    ROLE_PLUGIN_UPDATE,
    ROLE_SYSTEM_UPDATE,
]
LEGACY_DEFAULT_ROLES: set[str] = set(ALL_ROLES) - {ROLE_GLOBAL_ADMIN}

# Roles that account.update may assign without being a global admin.
ACCOUNT_ADMIN_GRANTABLE_ROLES: set[str] = {
    ROLE_GLOBAL_READ,
    ROLE_API_KEYS_READ,
    ROLE_DNS_ZONES_READ,
    ROLE_DNS_ZONES_UPDATE,
}

# Roles that only a global.admin may grant or remove.
SENSITIVE_ROLES: set[str] = {
    ROLE_GLOBAL_ADMIN,
    ROLE_ACCOUNT_UPDATE,
    ROLE_ACCOUNT_RESET_PASSWORD,
    ROLE_API_KEYS_UPDATE,
    ROLE_PLUGIN_UPDATE,
    ROLE_SYSTEM_UPDATE,
}

ROLE_LABELS: list[dict[str, str]] = [
    {"key": ROLE_GLOBAL_ADMIN, "label": "Global: admin"},
    {"key": ROLE_GLOBAL_READ, "label": "Global: read-only"},
    {"key": ROLE_ACCOUNT_UPDATE, "label": "Account: update"},
    {"key": ROLE_ACCOUNT_RESET_PASSWORD, "label": "Account: reset password"},
    {"key": ROLE_API_KEYS_READ, "label": "API keys: read"},
    {"key": ROLE_API_KEYS_UPDATE, "label": "API keys: update", "requires_role": ROLE_API_KEYS_READ},
    {"key": ROLE_DNS_ZONES_READ, "label": "DNS zones: read", "mandatory": True},
    {"key": ROLE_DNS_ZONES_UPDATE, "label": "DNS zones: update", "requires_role": ROLE_DNS_ZONES_READ},
    {"key": ROLE_PLUGIN_UPDATE, "label": "Plugin management"},
    {"key": ROLE_SYSTEM_UPDATE, "label": "System: update"},
]

SETTINGS_AREAS: list[dict[str, Any]] = [
    {
        "key": "authentication",
        "label": "Authentication",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_ACCOUNT_UPDATE, ROLE_ACCOUNT_RESET_PASSWORD],
    },
    {
        "key": "plugins",
        "label": "Plugin Management",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_PLUGIN_UPDATE],
    },
    {
        "key": "email_alerting",
        "label": "Email Alerting",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
    {
        "key": "log_viewing",
        "label": "View Logs",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
    {
        "key": "system_settings",
        "label": "System Settings",
        "required_roles": [ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE],
    },
]

LEGACY_SETTINGS_AREA_ALIASES: dict[str, str] = {
    "logging": "log_viewing",
    "activity_logging": "log_viewing",
}

SYSTEM_SETTINGS_SECTIONS: list[dict[str, str]] = [
    {"key": "system_identity", "label": "App DNS Name"},
    {"key": "ssl_certificate", "label": "SSL Certificate"},
    {"key": "smtp_delivery", "label": "SMTP Delivery"},
    {"key": "logging_configuration", "label": "Logging Level"},
    {"key": "audit_log_retention", "label": "Audit Log Retention"},
    {"key": "operational_log_rotation", "label": "Operational Log Rotation"},
]

_SYSTEM_SETTINGS_SECTION_KEYS = {section["key"] for section in SYSTEM_SETTINGS_SECTIONS}

_LEGACY_SYSTEM_SETTINGS_SECTION_ALIASES: dict[str, str] = {
    "ssl_planned": "ssl_certificate",
}


def default_system_settings_section() -> str:
    return SYSTEM_SETTINGS_SECTIONS[0]["key"]


def normalize_system_settings_section(section: str | None) -> str:
    key = (section or "").strip().lower()
    key = _LEGACY_SYSTEM_SETTINGS_SECTION_ALIASES.get(key, key)
    if key in _SYSTEM_SETTINGS_SECTION_KEYS:
        return key
    return default_system_settings_section()


ROLE_FORBIDDEN_DETAIL = "You do not have permission to access this resource."


def parse_roles(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def serialize_roles(roles) -> str:
    cleaned = {r for r in roles if r in ALL_ROLES}
    if ROLE_GLOBAL_ADMIN in cleaned:
        cleaned = set(ALL_ROLES)
    cleaned.update(MANDATORY_ROLES)
    return ",".join(sorted(cleaned))


def normalize_selected_roles(roles) -> list[str]:
    selected = {r for r in roles if r in ALL_ROLES}
    if ROLE_GLOBAL_ADMIN in selected:
        return sorted(ALL_ROLES)
    selected.update(MANDATORY_ROLES)
    for role, required_role in ROLE_DEPENDENCIES.items():
        if role in selected:
            selected.add(required_role)
    return sorted(selected)


def effective_roles(stored_roles: set[str]) -> set[str]:
    if ROLE_GLOBAL_ADMIN in stored_roles:
        return set(ALL_ROLES)
    return stored_roles | MANDATORY_ROLES


def get_user_roles(db, username: str) -> set[str]:
    user_row = db.exec(select(User).where(User.username == username)).first()
    if user_row is None:
        return set()
    return effective_roles(parse_roles(user_row.roles))


def user_has_role(db, username: str, role: str) -> bool:
    roles = get_user_roles(db, username)
    return (
        ROLE_GLOBAL_ADMIN in roles
        or role in roles
        or (ROLE_GLOBAL_READ in roles and role in {ROLE_API_KEYS_READ, ROLE_DNS_ZONES_READ})
    )


def user_has_any_role(db, username: str, roles) -> bool:
    return any(user_has_role(db, username, role) for role in roles)


def user_is_global_admin(db, username: str) -> bool:
    return ROLE_GLOBAL_ADMIN in get_user_roles(db, username)


def target_is_global_admin(target: User) -> bool:
    return ROLE_GLOBAL_ADMIN in effective_roles(parse_roles(target.roles))


def global_admin_guard_message(db, actor: str, target: User) -> str | None:
    if target_is_global_admin(target) and not user_is_global_admin(db, actor):
        return "Only a global admin can manage another global admin account."
    return None


def role_is_grantable_by(actor_is_global_admin: bool, role: str) -> bool:
    """Return True when ``actor`` may assign ``role`` to another account."""
    if role not in ALL_ROLES:
        return False
    if actor_is_global_admin:
        return True
    return role in ACCOUNT_ADMIN_GRANTABLE_ROLES


def validate_role_assignment(
    db,
    actor: str,
    selected_roles,
    *,
    previous_roles: set[str] | None = None,
) -> str | None:
    """Validate that ``actor`` may assign ``selected_roles``.

    Returns an error message when the assignment is forbidden, otherwise ``None``.
    Account admins may only grant roles in ``ACCOUNT_ADMIN_GRANTABLE_ROLES`` and may
    not add or remove sensitive roles on an existing account.
    """
    selected = set(normalize_selected_roles(selected_roles))
    previous = set(previous_roles or set())
    actor_is_ga = user_is_global_admin(db, actor)
    if actor_is_ga:
        return None

    # Account admins may keep previously assigned sensitive roles, but may not
    # add or remove them. Newly selected non-grantable roles are rejected.
    newly_selected = selected - previous
    disallowed = sorted(
        role for role in newly_selected if role not in ACCOUNT_ADMIN_GRANTABLE_ROLES and role not in MANDATORY_ROLES
    )
    if disallowed:
        return "Only a global admin can grant sensitive roles: " + ", ".join(disallowed) + "."

    removed_sensitive = sorted((previous - selected) & SENSITIVE_ROLES)
    if removed_sensitive:
        return "Only a global admin can remove sensitive roles: " + ", ".join(removed_sensitive) + "."
    return None


def role_catalog_for_actor(db, actor: str) -> list[dict[str, Any]]:
    """Return ROLE_LABELS annotated with whether the actor may grant each role."""
    actor_is_ga = user_is_global_admin(db, actor)
    catalog: list[dict[str, Any]] = []
    for entry in ROLE_LABELS:
        item = dict(entry)
        item["grantable"] = role_is_grantable_by(actor_is_ga, entry["key"])
        item["sensitive"] = entry["key"] in SENSITIVE_ROLES
        catalog.append(item)
    return catalog


def require_role(role: str):
    def _dependency(username: str = Depends(get_current_user)) -> str:
        with SessionLocal() as db:
            if not user_has_role(db, username, role):
                raise HTTPException(status_code=403, detail=ROLE_FORBIDDEN_DETAIL)
        return username

    return _dependency


def user_public_dict(u: User) -> dict[str, Any]:
    stored_roles = parse_roles(u.roles)
    display_roles = stored_roles or LEGACY_DEFAULT_ROLES
    effective_display_roles = effective_roles(display_roles)
    return {
        "id": u.id,
        "username": u.username,
        "disabled": u.disabled,
        "roles": sorted(effective_display_roles),
        "stored_roles": sorted(display_roles | MANDATORY_ROLES),
        "is_global_admin": ROLE_GLOBAL_ADMIN in effective_display_roles,
        "has_default_roles": not stored_roles,
    }


def accessible_settings_areas(user_roles: set[str]) -> list[dict[str, str]]:
    return [
        area
        for area in SETTINGS_AREAS
        if area["key"] == "authentication" or any(role in user_roles for role in area["required_roles"])
    ]


# Backwards-compatible aliases for tests and callers using underscore-prefixed names.
_parse_roles = parse_roles
_serialize_roles = serialize_roles
