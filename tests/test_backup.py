"""Configuration backup export/import tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from src.auth import create_session_cookie
from src.backup_service import (
    CATEGORY_ACTIVITY_LOGS,
    CATEGORY_ALERT_RULES,
    CATEGORY_API_KEYS,
    CATEGORY_APPLICATION_SECRETS,
    CATEGORY_SETTINGS,
    CATEGORY_SSL_FILES,
    CATEGORY_USERS,
    CATEGORY_ZONES,
    DEFAULT_EXPORT_CATEGORIES,
    BackupError,
    build_payload,
    load_backup_bytes,
    restore_payload,
    serialize_backup,
)
from src.db import SessionLocal
from src.models import (
    LOG_LEVEL_INFORMATIONAL,
    ActivityLog,
    AlertRule,
    ApiKey,
    DnsZoneConfig,
    User,
)
from src.rbac import (
    ROLE_DNS_ZONES_READ,
    ROLE_GLOBAL_READ,
    ROLE_SYSTEM_UPDATE,
    serialize_roles,
)
from src.security import hash_api_key
from src.settings_store import get_setting, set_setting
from src.ssl_certs import cert_dir


def _admin_client(client: TestClient) -> TestClient:
    client.cookies.set("session", create_session_cookie("admin"))
    return client


def test_backup_nav_visible_for_global_admin(client: TestClient) -> None:
    _admin_client(client)
    response = client.get("/settings?area=backup&section=export")
    assert response.status_code == 200
    assert "Backup Export" in response.text
    assert "Encrypt backup with a password" in response.text
    assert 'href="/settings?area=backup&section=export"' in response.text
    assert 'href="/settings?area=backup&section=import"' in response.text
    # Backup appears before System Settings in the sidebar markup.
    backup_pos = response.text.find("Backup")
    system_pos = response.text.find("System Settings")
    assert backup_pos != -1 and system_pos != -1
    assert backup_pos < system_pos


def test_backup_nav_hidden_for_non_admin(client: TestClient) -> None:
    from src.rbac import ALL_ROLES

    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == "admin")).first()
        assert user is not None
        user.roles = serialize_roles([ROLE_GLOBAL_READ, ROLE_SYSTEM_UPDATE, ROLE_DNS_ZONES_READ])
        db.add(user)
        db.commit()
    try:
        client.cookies.set("session", create_session_cookie("admin"))
        response = client.get("/settings")
        assert response.status_code == 200
        assert 'href="/settings?area=backup&section=export"' not in response.text
        assert "Backup Export" not in response.text

        denied = client.post(
            "/settings/backup/export",
            data={
                "categories": "settings",
                "encrypt": "1",
                "password": "password1",
                "password_confirm": "password1",
            },
        )
        assert denied.status_code == 403
    finally:
        with SessionLocal() as db:
            user = db.exec(select(User).where(User.username == "admin")).first()
            assert user is not None
            user.roles = serialize_roles(ALL_ROLES)
            db.add(user)
            db.commit()


def test_export_encrypted_download(client: TestClient) -> None:
    _admin_client(client)
    with SessionLocal() as db:
        set_setting(db, "app_dns_name", "backup.example.com")
        db.commit()
    response = client.post(
        "/settings/backup/export",
        data={
            "categories": [CATEGORY_SETTINGS, CATEGORY_APPLICATION_SECRETS],
            "encrypt": "1",
            "password": "password1",
            "password_confirm": "password1",
        },
    )
    assert response.status_code == 200
    assert "attachment" in response.headers.get("content-disposition", "")
    assert response.headers.get("content-disposition", "").endswith('.atdb"')
    envelope = json.loads(response.content.decode("utf-8"))
    assert envelope["encrypted"] is True
    assert envelope["format"] == "api-to-dns-backup"
    payload = load_backup_bytes(response.content, "password1")
    assert CATEGORY_SETTINGS in payload
    assert CATEGORY_APPLICATION_SECRETS in payload
    assert payload[CATEGORY_APPLICATION_SECRETS]["ENCRYPTION_KEY"]


def test_export_unencrypted_warning_present(client: TestClient) -> None:
    _admin_client(client)
    response = client.get("/settings?area=backup&section=export")
    assert "unencrypted backup includes" in response.text
    assert 'id="backup-unencrypted-warning"' in response.text


def test_export_wrong_password_confirm(client: TestClient) -> None:
    _admin_client(client)
    response = client.post(
        "/settings/backup/export",
        data={
            "categories": CATEGORY_SETTINGS,
            "encrypt": "1",
            "password": "password1",
            "password_confirm": "password2",
        },
    )
    assert response.status_code == 200
    assert "do not match" in response.text


def test_load_backup_wrong_password() -> None:
    with SessionLocal() as db:
        payload = build_payload(db, [CATEGORY_SETTINGS])
    raw = serialize_backup(payload, encrypt=True, password="password1")
    with pytest.raises(BackupError, match="Incorrect backup password"):
        load_backup_bytes(raw, "wrong-password")


def test_round_trip_restore_replaces_categories(client: TestClient) -> None:
    _admin_client(client)
    with SessionLocal() as db:
        set_setting(db, "app_dns_name", "original.example.com")
        db.add(
            AlertRule(
                name="keep-me",
                email_recipients="a@example.com",
                minimum_level="WARNING",
            )
        )
        db.add(
            ActivityLog(
                level=LOG_LEVEL_INFORMATIONAL,
                event_type="test.event",
                message="before",
            )
        )
        db.commit()
        payload = build_payload(
            db,
            [
                CATEGORY_SETTINGS,
                CATEGORY_USERS,
                CATEGORY_ZONES,
                CATEGORY_API_KEYS,
                CATEGORY_ALERT_RULES,
                CATEGORY_APPLICATION_SECRETS,
                CATEGORY_ACTIVITY_LOGS,
            ],
        )
        raw = serialize_backup(payload, encrypt=True, password="password1")

        # Mutate installation away from backup contents.
        set_setting(db, "app_dns_name", "mutated.example.com")
        for rule in list(db.exec(select(AlertRule)).all()):
            db.delete(rule)
        db.add(AlertRule(name="new-rule", email_recipients="b@example.com", minimum_level="ERROR"))
        for row in list(db.exec(select(ActivityLog)).all()):
            db.delete(row)
        db.add(ActivityLog(level=LOG_LEVEL_INFORMATIONAL, event_type="test.other", message="after"))
        db.commit()

        restored = load_backup_bytes(raw, "password1")
        with patch("src.app.perform_application_restart") as restart_mock:
            # Direct restore (unit path); secrets would restart via route.
            result = restore_payload(
                db,
                restored,
                [
                    CATEGORY_SETTINGS,
                    CATEGORY_ALERT_RULES,
                    CATEGORY_ACTIVITY_LOGS,
                    CATEGORY_APPLICATION_SECRETS,
                ],
            )
            assert result["restarting"] is True
            restart_mock.assert_not_called()

        assert get_setting(db, "app_dns_name") == "original.example.com"
        rules = list(db.exec(select(AlertRule)).all())
        assert len(rules) == 1
        assert rules[0].name == "keep-me"
        logs = list(db.exec(select(ActivityLog)).all())
        assert any(row.message == "before" for row in logs)
        assert not any(row.message == "after" for row in logs)


def test_import_async_progress_and_restart(client: TestClient) -> None:
    from src.app import _run_backup_import_sync
    from src.backup_service import set_import_in_progress

    _admin_client(client)
    with SessionLocal() as db:
        set_setting(db, "app_dns_name", "async.example.com")
        payload = build_payload(db, DEFAULT_EXPORT_CATEGORIES)
        raw = serialize_backup(payload, encrypt=True, password="password1")
        set_setting(db, "app_dns_name", "changed.example.com")
        db.commit()

    set_import_in_progress(False)
    try:
        with patch("src.app.perform_application_restart") as restart_mock:
            with patch("src.app.asyncio.create_task") as create_task:

                def _discard(coro):
                    coro.close()
                    return None

                create_task.side_effect = _discard
                response = client.post(
                    "/settings/backup/import-async",
                    data={
                        "categories": [CATEGORY_SETTINGS, CATEGORY_APPLICATION_SECRETS],
                        "password": "password1",
                        "confirm_replace": "1",
                    },
                    files={"backup_file": ("test.atdb", raw, "application/octet-stream")},
                )
                assert response.status_code == 202
                create_task.assert_called_once()
                _run_backup_import_sync(
                    raw=raw,
                    password="password1",
                    categories=[CATEGORY_SETTINGS, CATEGORY_APPLICATION_SECRETS],
                    user="admin",
                )
                restart_mock.assert_called_once()

        progress = client.get("/settings/backup/import/progress")
        assert progress.status_code == 200
        body = progress.json()
        assert body["done"] is True
        assert body.get("error") is None
        assert body.get("restarting") is True

        with SessionLocal() as db:
            assert get_setting(db, "app_dns_name") == "async.example.com"
    finally:
        set_import_in_progress(False)


def test_import_requires_confirm(client: TestClient) -> None:
    _admin_client(client)
    with SessionLocal() as db:
        payload = build_payload(db, [CATEGORY_SETTINGS, CATEGORY_APPLICATION_SECRETS])
        raw = serialize_backup(payload, encrypt=False, password=None)
    response = client.post(
        "/settings/backup/import-async",
        data={
            "categories": [CATEGORY_SETTINGS, CATEGORY_APPLICATION_SECRETS],
            "confirm_replace": "0",
        },
        files={"backup_file": ("test.atdb", raw, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "Confirm" in response.json()["detail"]


def test_import_fernet_categories_require_secrets(client: TestClient) -> None:
    _admin_client(client)
    with SessionLocal() as db:
        payload = build_payload(db, [CATEGORY_SETTINGS, CATEGORY_APPLICATION_SECRETS])
        raw = serialize_backup(payload, encrypt=False, password=None)
    response = client.post(
        "/settings/backup/import-async",
        data={
            "categories": [CATEGORY_SETTINGS],
            "confirm_replace": "1",
        },
        files={"backup_file": ("test.atdb", raw, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "Application secrets" in response.json()["detail"]


def test_import_dialog_markup(client: TestClient) -> None:
    _admin_client(client)
    response = client.get("/settings?area=backup&section=import")
    assert response.status_code == 200
    assert 'id="backup-restore-dialog"' in response.text
    assert 'id="backup-restore-progress"' in response.text
    assert "Replace selected data on this installation" in response.text


def test_ssl_files_round_trip(client: TestClient) -> None:
    key_path = cert_dir() / "server.key"
    cert_path = cert_dir() / "server.crt"
    source_path = cert_dir() / "server.source"
    key_path.write_text("KEYDATA", encoding="utf-8")
    cert_path.write_text("CERTDATA", encoding="utf-8")
    source_path.write_text("uploaded\n", encoding="utf-8")

    with SessionLocal() as db:
        payload = build_payload(db, [CATEGORY_SSL_FILES, CATEGORY_APPLICATION_SECRETS])
        raw = serialize_backup(payload, encrypt=True, password="password1")
        key_path.unlink()
        cert_path.unlink()
        source_path.unlink()
        restored = load_backup_bytes(raw, "password1")
        restore_payload(db, restored, [CATEGORY_SSL_FILES, CATEGORY_APPLICATION_SECRETS])

    assert key_path.read_text(encoding="utf-8") == "KEYDATA"
    assert cert_path.read_text(encoding="utf-8") == "CERTDATA"
    assert "uploaded" in source_path.read_text(encoding="utf-8")


def test_api_key_hash_survives_restore(client: TestClient, api_key_value: str) -> None:
    digest = hash_api_key(api_key_value)
    with SessionLocal() as db:
        payload = build_payload(db, [CATEGORY_API_KEYS, CATEGORY_ZONES, CATEGORY_APPLICATION_SECRETS])
        raw = serialize_backup(payload, encrypt=False, password=None)
        for row in list(db.exec(select(ApiKey)).all()):
            db.delete(row)
        db.commit()
        restored = load_backup_bytes(raw, None)
        restore_payload(
            db,
            restored,
            [CATEGORY_API_KEYS, CATEGORY_ZONES, CATEGORY_APPLICATION_SECRETS],
        )
        key = db.exec(select(ApiKey).where(ApiKey.key == digest)).first()
        assert key is not None
        zones = list(db.exec(select(DnsZoneConfig)).all())
        assert zones


def test_restore_rejects_malformed_users_before_wipe() -> None:
    from src.backup_service import validate_restore_records

    with SessionLocal() as db:
        before = {u.username for u in db.exec(select(User)).all()}
        assert "admin" in before
        payload = build_payload(db, [CATEGORY_USERS])
        payload[CATEGORY_USERS] = [{"username": "broken"}]  # missing password_hash
        with pytest.raises(BackupError, match="password_hash"):
            validate_restore_records([CATEGORY_USERS], payload)
        with pytest.raises(BackupError, match="password_hash"):
            restore_payload(db, payload, [CATEGORY_USERS])
        after = {u.username for u in db.exec(select(User)).all()}
        assert after == before


def test_restore_users_bumps_session_version() -> None:
    with SessionLocal() as db:
        admin = db.exec(select(User).where(User.username == "admin")).first()
        assert admin is not None
        previous = int(admin.session_version or 0)
        try:
            admin.session_version = 7
            db.add(admin)
            db.commit()
            payload = build_payload(db, [CATEGORY_USERS])
            assert payload[CATEGORY_USERS][0]["session_version"] == 7
            restore_payload(db, payload, [CATEGORY_USERS])
            restored = db.exec(select(User).where(User.username == "admin")).first()
            assert restored is not None
            assert int(restored.session_version) == 8
        finally:
            admin = db.exec(select(User).where(User.username == "admin")).first()
            if admin is not None:
                admin.session_version = previous
                db.add(admin)
                db.commit()


def test_shell_export_quotes_metacharacters(tmp_path, monkeypatch) -> None:
    import shlex

    from src import env_bootstrap

    secrets = tmp_path / "app_secrets.env"
    # Hostile value that would execute if the file were shell-sourced.
    secrets.write_text(
        "SECRET_KEY=$(touch /tmp/pwned)\nENCRYPTION_KEY=not-a-fernet\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(env_bootstrap, "app_secrets_path", lambda: secrets)
    # ENCRYPTION_KEY invalid → skipped; SECRET_KEY exported with shlex.quote.
    exported = env_bootstrap.shell_export_persisted_secrets()
    assert exported == "export SECRET_KEY=" + shlex.quote("$(touch /tmp/pwned)")
    words = shlex.split(exported)
    assert words == ["export", "SECRET_KEY=$(touch /tmp/pwned)"]


def test_write_rejects_control_chars_in_secrets(tmp_path, monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from src import env_bootstrap

    monkeypatch.setattr(env_bootstrap, "app_secrets_path", lambda: tmp_path / "app_secrets.env")
    monkeypatch.setattr(env_bootstrap, "project_env_path", lambda: tmp_path / "missing.env")
    with pytest.raises(ValueError, match="control characters"):
        env_bootstrap.write_application_secrets(
            secret_key="good-secret\nbad",
            encryption_key=Fernet.generate_key().decode(),
        )


def test_decrypt_rejects_extreme_pbkdf2_iterations() -> None:
    from src.backup_crypto import MAX_PBKDF2_ITERATIONS, decrypt_envelope, encrypt_payload

    envelope = encrypt_payload(b'{"manifest":{}}', "password1")
    envelope["iterations"] = MAX_PBKDF2_ITERATIONS + 1
    with pytest.raises(ValueError, match="too high|Invalid PBKDF2"):
        decrypt_envelope(envelope, "password1")
