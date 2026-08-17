"""Branded HTML error pages and CSRF JSON/HTML negotiation."""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select
from starlette.requests import Request

from src.auth import create_session_cookie
from src.csrf import csrf_rejection_response
from src.db import SessionLocal
from src.models import User
from src.rbac import ALL_ROLES, ROLE_FORBIDDEN_DETAIL, ROLE_GLOBAL_READ, serialize_roles
from src.security import hash_password
from src.web import render_error_response


def _http_request(*, accept: str = "text/html") -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [(b"accept", accept.encode())],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
        }
    )


def _assert_branded_error(body: str) -> None:
    assert "/static/style.css" in body
    assert "/static/favicon.svg" in body
    assert "/static/theme.js" in body
    assert "/static/logo-mark.svg" in body
    assert "api-to-dns-theme" not in body


def test_csrf_html_uses_branded_template(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.csrf.relax_csrf_for_tests", lambda: False)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/api-keys",
        data={"label": "x", "zone_ids": "1"},
        headers={"Origin": "https://evil.example", "Host": "localhost"},
    )
    assert response.status_code == 403
    assert "CSRF validation failed" in response.text
    assert "Request blocked" in response.text
    _assert_branded_error(response.text)


def test_csrf_json_envelope_unchanged(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.csrf.relax_csrf_for_tests", lambda: False)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/api-keys",
        data={"label": "x", "zone_ids": "1"},
        headers={
            "Origin": "https://evil.example",
            "Host": "localhost",
            "Accept": "application/json",
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "csrf_failed", "message": "CSRF validation failed"}


def test_csrf_json_helper_matches_http_envelope() -> None:
    response = csrf_rejection_response(_http_request(accept="application/json"))
    assert response.status_code == 403
    assert response.body  # JSONResponse
    assert b"csrf_failed" in response.body


def test_access_denied_html_is_branded(client: TestClient) -> None:
    with SessionLocal() as db:
        for user in db.exec(select(User)).all():
            db.delete(user)
        db.commit()
        db.add(
            User(
                username="readonly",
                password_hash=hash_password("x"),
                roles=serialize_roles([ROLE_GLOBAL_READ]),
            )
        )
        db.add(
            User(
                username="admin",
                password_hash=hash_password("x"),
                roles=serialize_roles(ALL_ROLES),
            )
        )
        db.commit()
    client.cookies.set("session", create_session_cookie("readonly"))
    response = client.post(
        "/settings/users",
        data={"username": "nope", "password": "x", "roles": []},
    )
    assert response.status_code == 403
    assert ROLE_FORBIDDEN_DETAIL in response.text
    assert "Access denied" in response.text
    _assert_branded_error(response.text)


def test_generic_500_is_branded_without_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEBUG_ERRORS", "0")
    try:
        raise RuntimeError("<script>alert(1)</script>")
    except RuntimeError as exc:
        response = render_error_response(_http_request(), exc)
    body = response.body.decode()
    assert response.status_code == 500
    assert "Application error" in body
    assert "unexpected error occurred" in body
    assert "<script>alert(1)</script>" not in body
    assert "Traceback" not in body
    _assert_branded_error(body)


def test_debug_500_escapes_exception_and_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEBUG_ERRORS", "1")
    try:
        raise RuntimeError("<script>alert(1)</script>")
    except RuntimeError as exc:
        response = render_error_response(_http_request(), exc)
    body = response.body.decode()
    assert response.status_code == 500
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    _assert_branded_error(body)


def test_unauthenticated_admin_still_redirects_to_login(client: TestClient) -> None:
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
