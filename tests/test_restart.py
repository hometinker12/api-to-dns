from datetime import datetime

from fastapi.testclient import TestClient

import src.app as app_module
from src.auth import create_session_cookie
from src.db import SessionLocal
from src.restart import (
    clear_restart_required,
    is_restart_required,
    mark_restart_required,
    preview_restart_urls,
    scheduled_restart_due,
)
from src.settings_store import delete_setting
from src.ssl_certs import set_ssl_enabled


def test_restart_flag_round_trip(client: TestClient) -> None:
    with SessionLocal() as db:
        clear_restart_required(db)
        assert is_restart_required(db) is False
        mark_restart_required(db, reason="test")
        assert is_restart_required(db) is True
        clear_restart_required(db)
        assert is_restart_required(db) is False


def test_preview_restart_urls_reflect_persisted_ssl(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("SSL_ENABLED", "0")
    with SessionLocal() as db:
        set_ssl_enabled(db, True)
        preview = preview_restart_urls(db)
    assert preview["current_url"].startswith("http://")
    assert preview["after_restart_url"].startswith("https://")


def test_scheduled_restart_due_once_per_day(client: TestClient) -> None:
    now = datetime(2026, 5, 20, 3, 0)
    with SessionLocal() as db:
        delete_setting(db, "last_scheduled_restart_date")
        assert scheduled_restart_due(db, configured_time="03:00", now=now) is True
        assert scheduled_restart_due(db, configured_time="03:00", now=now) is False
        assert scheduled_restart_due(db, configured_time="04:00", now=now) is False


def test_restart_route_clears_flag_without_sigterm(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(app_module, "perform_application_restart", lambda *, scheduled=False: None)
    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        mark_restart_required(db, reason="test")
    response = client.post("/system/restart", headers={"accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["status"] == "restarting"
    with SessionLocal() as db:
        assert is_restart_required(db) is False
