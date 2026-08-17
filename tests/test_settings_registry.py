"""Typed settings registry and store accessors."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from src.db import SessionLocal
from src.settings_registry import SETTINGS, SettingSpec, get_spec
from src.settings_store import (
    get_setting,
    get_typed_setting,
    get_typed_setting_by_key,
    log_unknown_settings,
    require_spec,
    set_setting,
    set_typed_setting,
    set_typed_setting_by_key,
    unknown_setting_names,
)
from src.ssl_certs import SETTING_SSL_ENABLED, is_ssl_enabled, set_ssl_enabled

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"


def _setting_constants() -> set[str]:
    keys: set[str] = set()
    for path in SRC_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if target.id.startswith("SETTING_") or target.id.endswith("_SETTING"):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    keys.add(node.value.value)
            if target.id == "LEGACY_DNS_SETTING_NAMES" and isinstance(node.value, ast.List):
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        keys.add(elt.value)
    return keys


def test_registry_covers_setting_constants() -> None:
    constants = _setting_constants()
    missing = sorted(constants - set(SETTINGS))
    assert missing == []
    extra = sorted(set(SETTINGS) - constants)
    assert extra == []


def test_sensitive_credentials_are_marked() -> None:
    for key in (
        "smtp_password",
        "dns_password",
        "dns_username",
        "azure_client_secret",
        "azure_tenant_id",
        "azure_client_id",
        "azure_subscription_id",
    ):
        assert SETTINGS[key].sensitive is True
    assert SETTINGS["ssl_enabled"].sensitive is False
    assert SETTINGS["log_level"].sensitive is False


def test_bool_int_json_round_trip(client) -> None:
    bool_spec = SETTINGS["ssl_enabled"]
    int_spec = SETTINGS["smtp_port"]
    json_spec = SETTINGS["disabled_dns_plugins"]
    with SessionLocal() as db:
        set_typed_setting(db, bool_spec, True)
        assert get_typed_setting(db, bool_spec) is True
        assert get_setting(db, bool_spec.key) == "true"
        set_typed_setting(db, bool_spec, False)
        assert get_typed_setting(db, bool_spec) is False
        assert get_setting(db, bool_spec.key) == "false"

        set_typed_setting(db, int_spec, 2525)
        assert get_typed_setting(db, int_spec) == 2525
        assert get_setting(db, int_spec.key) == "2525"

        set_typed_setting(db, json_spec, ["azure", "bind"])
        assert get_typed_setting(db, json_spec) == ["azure", "bind"]
        from src.settings_store import delete_setting

        delete_setting(db, int_spec.key)
        delete_setting(db, json_spec.key)
        set_ssl_enabled(db, False)


def test_defaults_when_row_missing(client) -> None:
    with SessionLocal() as db:
        from src.settings_store import delete_setting

        delete_setting(db, "activity_retention_days")
        delete_setting(db, "ssl_enabled")
        delete_setting(db, "letsencrypt_config")
        assert get_typed_setting_by_key(db, "activity_retention_days") == 90
        assert get_typed_setting_by_key(db, "ssl_enabled") is False
        assert get_typed_setting_by_key(db, "letsencrypt_config") is None


def test_invalid_values_raise(client) -> None:
    with SessionLocal() as db:
        set_setting(db, "ssl_enabled", "maybe")
        try:
            get_typed_setting_by_key(db, "ssl_enabled")
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
        set_setting(db, "smtp_port", "not-a-number")
        try:
            get_typed_setting_by_key(db, "smtp_port")
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
        set_setting(db, "letsencrypt_config", "{not-json")
        try:
            get_typed_setting_by_key(db, "letsencrypt_config")
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
        from src.settings_store import delete_setting

        delete_setting(db, "ssl_enabled")
        delete_setting(db, "smtp_port")
        delete_setting(db, "letsencrypt_config")


def test_unknown_keys_remain_readable(client, caplog) -> None:
    with SessionLocal() as db:
        with caplog.at_level(logging.DEBUG, logger="api_to_dns"):
            set_setting(db, "future_restored_key", "kept")
        assert get_setting(db, "future_restored_key") == "kept"
        assert "future_restored_key" in caplog.text
        assert "future_restored_key" in unknown_setting_names(db)
        with caplog.at_level(logging.WARNING, logger="api_to_dns"):
            logged = log_unknown_settings(db)
        assert "future_restored_key" in logged
        assert "Unregistered Setting rows present" in caplog.text
        from src.settings_store import delete_setting

        delete_setting(db, "future_restored_key")


def test_require_spec_rejects_unknown_keys() -> None:
    try:
        require_spec("not_a_real_setting")
        raise AssertionError("expected KeyError")
    except KeyError:
        pass
    assert isinstance(get_spec("ssl_enabled"), SettingSpec)
    try:
        set_typed_setting_by_key(None, "not_a_real_setting", "x")
        raise AssertionError("expected KeyError")
    except KeyError:
        pass


def test_ssl_helper_uses_typed_bool(client) -> None:
    with SessionLocal() as db:
        set_ssl_enabled(db, True)
        assert is_ssl_enabled(db) is True
        assert get_setting(db, SETTING_SSL_ENABLED) == "true"
        set_setting(db, SETTING_SSL_ENABLED, "enabled")
        assert is_ssl_enabled(db) is True
        set_setting(db, SETTING_SSL_ENABLED, "garbage")
        assert is_ssl_enabled(db) is False
        set_ssl_enabled(db, False)
