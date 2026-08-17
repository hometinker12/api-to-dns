"""Request-scoped DB session and RBAC request-state cache."""

from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import select

from src.auth import create_session_cookie
from src.db import SessionLocal, get_db
from src.models import User
from src.rbac import (
    ROLE_API_KEYS_READ,
    ROLE_DNS_ZONES_READ,
    ROLE_FORBIDDEN_DETAIL,
    ROLE_GLOBAL_ADMIN,
    ROLE_GLOBAL_READ,
    require_role,
    roles_satisfy,
    serialize_roles,
)
from src.security import hash_password


def test_get_db_yields_one_session() -> None:
    yielded = []
    for db in get_db():
        yielded.append(db)
        assert db.is_active
    assert len(yielded) == 1


def test_roles_satisfy_global_admin_and_global_read() -> None:
    assert roles_satisfy({ROLE_GLOBAL_ADMIN}, ROLE_API_KEYS_READ)
    assert roles_satisfy({ROLE_GLOBAL_READ}, ROLE_API_KEYS_READ)
    assert roles_satisfy({ROLE_GLOBAL_READ}, ROLE_DNS_ZONES_READ)
    assert not roles_satisfy({ROLE_GLOBAL_READ}, "system.update")
    assert roles_satisfy({ROLE_API_KEYS_READ}, ROLE_API_KEYS_READ)
    assert not roles_satisfy({ROLE_DNS_ZONES_READ}, ROLE_API_KEYS_READ)


def test_require_role_uses_request_state_without_db() -> None:
    dep = require_role(ROLE_API_KEYS_READ)

    class _State:
        user_roles: frozenset[str] | None = None

    class _Request:
        def __init__(self) -> None:
            self.state = _State()

    request = _Request()
    request.state.user_roles = frozenset({ROLE_API_KEYS_READ, ROLE_DNS_ZONES_READ})
    assert dep(request, username="alice") == "alice"

    request.state.user_roles = frozenset({ROLE_DNS_ZONES_READ})
    try:
        dep(request, username="alice")
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == ROLE_FORBIDDEN_DETAIL
    else:
        raise AssertionError("expected 403 when cached roles omit the required role")

    request.state.user_roles = None
    try:
        dep(request, username="alice")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("expected 401 when request.state.user_roles is missing")


def test_get_current_user_can_be_called_without_fastapi_di(client: TestClient) -> None:
    from starlette.requests import Request as StarletteRequest

    from src.auth import get_current_user

    cookie = create_session_cookie("admin")
    scope = {
        "type": "http",
        "asgi": {"spec_version": "2.3", "version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/admin",
        "raw_path": b"/admin",
        "query_string": b"",
        "headers": [(b"cookie", f"session={cookie}".encode())],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "state": {},
    }
    request = StarletteRequest(scope)
    assert get_current_user(request) == "admin"
    assert request.state.session_user == "admin"
    assert ROLE_API_KEYS_READ in request.state.user_roles


def test_disabled_user_rejected_after_request_state_auth(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("cached-disabled"))
    with SessionLocal() as db:
        db.add(
            User(
                username="cached-disabled",
                password_hash=hash_password("x"),
                roles=serialize_roles([ROLE_API_KEYS_READ]),
                disabled=True,
            )
        )
        db.commit()

    response = client.get("/api-keys", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_request_state_roles_are_not_reused_across_requests(client: TestClient) -> None:
    client.cookies.set("session", create_session_cookie("state-user"))
    with SessionLocal() as db:
        db.add(
            User(
                username="state-user",
                password_hash=hash_password("x"),
                roles=serialize_roles([ROLE_API_KEYS_READ]),
            )
        )
        db.commit()

    first = client.get("/api-keys", follow_redirects=False)
    assert first.status_code == 200

    with SessionLocal() as db:
        user = db.exec(select(User).where(User.username == "state-user")).first()
        assert user is not None
        user.roles = serialize_roles([ROLE_DNS_ZONES_READ])
        db.add(user)
        db.commit()

    second = client.get("/api-keys", follow_redirects=False)
    assert second.status_code == 403


def test_settings_page_does_not_open_a_second_session(client: TestClient, monkeypatch) -> None:
    def _boom(*_args, **_kwargs):
        raise AssertionError("settings_context must reuse the request session")

    monkeypatch.setattr("src.settings_context.SessionLocal", _boom)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings")
    assert response.status_code == 200
    assert "Settings" in response.text or "settings" in response.text.lower()
