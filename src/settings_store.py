import json
import logging

from sqlmodel import select

from .models import Setting
from .security import decrypt_value, encrypt_value
from .settings_registry import SettingSpec, get_spec

LOGGER = logging.getLogger("api_to_dns")

_TRUTHY = {"1", "true", "yes", "on", "enabled"}
_FALSY = {"0", "false", "no", "off", "disabled", ""}


def get_setting(db, name: str) -> str | None:
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    return decrypt_value(record.value) if record else None


def set_setting(db, name: str, value: str) -> None:
    if get_spec(name) is None:
        LOGGER.debug("Writing unregistered setting key %s", name)
    encrypted = encrypt_value(value)
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    if record:
        record.value = encrypted
    else:
        db.add(Setting(name=name, value=encrypted))
    db.commit()


def delete_setting(db, name: str) -> None:
    record = db.exec(select(Setting).where(Setting.name == name)).first()
    if record:
        db.delete(record)
    db.commit()


def _parse_typed(spec: SettingSpec, raw: str | None):
    if raw is None:
        raw = spec.default
    if raw is None:
        if spec.value_type == "json":
            return None
        if spec.value_type == "bool":
            return False
        if spec.value_type == "int":
            return 0
        return ""
    if spec.value_type == "str":
        return raw
    if spec.value_type == "bool":
        lowered = raw.strip().lower()
        if lowered in _TRUTHY:
            return True
        if lowered in _FALSY:
            return False
        raise ValueError(f"Invalid boolean for {spec.key}: {raw!r}")
    if spec.value_type == "int":
        try:
            return int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid integer for {spec.key}: {raw!r}") from exc
    if spec.value_type == "json":
        if not str(raw).strip():
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON for {spec.key}") from exc
    raise ValueError(f"Unsupported setting type {spec.value_type}")


def _encode_typed(spec: SettingSpec, value) -> str:
    if spec.value_type == "bool":
        return "true" if bool(value) else "false"
    if spec.value_type == "int":
        return str(int(value))
    if spec.value_type == "json":
        return json.dumps(value, sort_keys=True)
    return str(value if value is not None else "")


def get_typed_setting(db, spec: SettingSpec):
    return _parse_typed(spec, get_setting(db, spec.key))


def set_typed_setting(db, spec: SettingSpec, value) -> None:
    set_setting(db, spec.key, _encode_typed(spec, value))


def require_spec(key: str) -> SettingSpec:
    spec = get_spec(key)
    if spec is None:
        raise KeyError(f"Unregistered setting key: {key}")
    return spec


def get_typed_setting_by_key(db, key: str):
    return get_typed_setting(db, require_spec(key))


def set_typed_setting_by_key(db, key: str, value) -> None:
    set_typed_setting(db, require_spec(key), value)


def unknown_setting_names(db) -> list[str]:
    from .settings_registry import SETTINGS

    names = {row.name for row in db.exec(select(Setting)).all() if row.name}
    return sorted(names - SETTINGS.keys())


def log_unknown_settings(db) -> list[str]:
    names = unknown_setting_names(db)
    if names:
        LOGGER.warning("Unregistered Setting rows present: %s", ", ".join(names))
    return names
