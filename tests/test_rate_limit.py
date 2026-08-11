"""SQLite-backed rate-limit regression tests."""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select
from starlette.requests import Request

from src.auth import create_session_cookie
from src.db import SessionLocal, init_db
from src.models import DnsZoneConfig
from src.rate_limit import rate_limit_exceeded


def _request(path: str, *, headers=None, client_host: str = "203.0.113.10") -> Request:
    header_list = []
    for key, value in (headers or {}).items():
        header_list.append((key.lower().encode("latin-1"), value.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": header_list,
        "client": (client_host, 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


@pytest.fixture
def enable_rate_limit(monkeypatch: pytest.MonkeyPatch):
    from sqlalchemy import text

    monkeypatch.delenv("API_TO_DNS_DISABLE_RATE_LIMIT", raising=False)
    monkeypatch.setenv("RATE_LIMIT_LOGIN", "3:60")
    monkeypatch.setenv("RATE_LIMIT_KEYCHECK", "3:60")
    monkeypatch.setenv("RATE_LIMIT_DNS_RECORD", "3:60")
    monkeypatch.setenv("RATE_LIMIT_DNS_BROWSER", "3:60")
    init_db()
    with SessionLocal() as db:
        db.execute(text("DELETE FROM rate_limit_bucket"))
        db.commit()
    yield


def test_rate_limit_bypass_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_TO_DNS_DISABLE_RATE_LIMIT", "1")
    for _ in range(20):
        assert rate_limit_exceeded(_request("/login")) is False


def test_login_route_limit(enable_rate_limit) -> None:
    req = _request("/login")
    assert rate_limit_exceeded(req) is False
    assert rate_limit_exceeded(req) is False
    assert rate_limit_exceeded(req) is False
    assert rate_limit_exceeded(req) is True


def test_x_api_key_and_bearer_share_bucket(enable_rate_limit) -> None:
    key = "shared-rate-limit-key"
    assert rate_limit_exceeded(_request("/keycheck", headers={"x-api-key": key})) is False
    assert rate_limit_exceeded(_request("/keycheck", headers={"authorization": f"Bearer {key}"})) is False
    assert rate_limit_exceeded(_request("/keycheck", headers={"x-api-key": key})) is False
    assert rate_limit_exceeded(_request("/keycheck", headers={"authorization": f"Bearer {key}"})) is True


def test_separate_api_keys_have_separate_buckets(enable_rate_limit) -> None:
    for _ in range(3):
        assert rate_limit_exceeded(_request("/dns-record", headers={"x-api-key": "key-a"})) is False
    assert rate_limit_exceeded(_request("/dns-record", headers={"x-api-key": "key-a"})) is True
    assert rate_limit_exceeded(_request("/dns-record", headers={"x-api-key": "key-b"})) is False


def test_shared_counters_across_independent_clients(enable_rate_limit) -> None:
    # Two independent request objects / "workers" share SQLite counters.
    for _ in range(3):
        assert rate_limit_exceeded(_request("/login", client_host="198.51.100.1")) is False
    assert rate_limit_exceeded(_request("/login", client_host="198.51.100.1")) is True
    # Different IP still has its own bucket.
    assert rate_limit_exceeded(_request("/login", client_host="198.51.100.2")) is False


def test_expired_buckets_are_cleaned(enable_rate_limit, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import text

    import src.rate_limit as rate_limit_module

    monkeypatch.setattr(rate_limit_module.random, "random", lambda: 0.0)
    # Seed an already-expired row.
    with SessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO rate_limit_bucket (route_prefix, identity_hash, window_start, count, expires_at)
                VALUES ('/login', 'ip:203.0.113.10', 1, 99, 2)
                """
            )
        )
        db.commit()

    assert rate_limit_exceeded(_request("/login")) is False
    with SessionLocal() as db:
        remaining = db.execute(text("SELECT COUNT(*) FROM rate_limit_bucket WHERE expires_at = 2")).scalar()
    assert remaining == 0


def test_rate_limit_retries_transient_sqlite_lock(enable_rate_limit, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy.exc import OperationalError

    import src.rate_limit as rate_limit_module

    original_cleanup = rate_limit_module._maybe_cleanup_expired
    calls = 0
    delays: list[float] = []

    def lock_once(db, now: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OperationalError("DELETE", {}, RuntimeError("database is locked"))
        original_cleanup(db, now)

    monkeypatch.setattr(rate_limit_module, "_maybe_cleanup_expired", lock_once)
    monkeypatch.setattr(rate_limit_module.time, "sleep", delays.append)

    assert rate_limit_exceeded(_request("/login")) is False
    assert calls == 2
    assert delays == [rate_limit_module._RATE_LIMIT_DB_LOCK_BACKOFF_SECONDS]


def test_rate_limit_fails_closed_after_transient_lock_retries(
    enable_rate_limit, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.exc import OperationalError

    import src.rate_limit as rate_limit_module

    calls = 0
    delays: list[float] = []

    def always_locked(_db, _now: int) -> None:
        nonlocal calls
        calls += 1
        raise OperationalError("DELETE", {}, RuntimeError("database is busy"))

    monkeypatch.setattr(rate_limit_module, "_maybe_cleanup_expired", always_locked)
    monkeypatch.setattr(rate_limit_module.time, "sleep", delays.append)

    assert rate_limit_exceeded(_request("/login")) is True
    assert calls == rate_limit_module._RATE_LIMIT_DB_LOCK_ATTEMPTS
    assert delays == [
        rate_limit_module._RATE_LIMIT_DB_LOCK_BACKOFF_SECONDS,
        rate_limit_module._RATE_LIMIT_DB_LOCK_BACKOFF_SECONDS * 2,
    ]


def test_http_login_returns_429_when_limited(client: TestClient, enable_rate_limit) -> None:
    # Disable CSRF relax? keep default. Hit login until limited.
    for _ in range(3):
        response = client.post("/login", data={"username": "nobody", "password": "x"})
        assert response.status_code in {200, 429}
    response = client.post("/login", data={"username": "nobody", "password": "x"})
    assert response.status_code == 429


def test_dns_browser_route_limit(enable_rate_limit) -> None:
    search = _request("/zones/1/records/search")
    page = _request("/zones/1/records")
    assert rate_limit_exceeded(search) is False
    assert rate_limit_exceeded(page) is False
    assert rate_limit_exceeded(search) is False
    assert rate_limit_exceeded(page) is True
    # Unrelated zone admin path is not in this bucket.
    assert rate_limit_exceeded(_request("/zones/1")) is False


def test_http_dns_browser_returns_429_when_limited(
    client: TestClient,
    enable_rate_limit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unittest.mock import MagicMock

    client.cookies.set("session", create_session_cookie("admin"))
    with SessionLocal() as db:
        zone = db.exec(select(DnsZoneConfig)).first()
        assert zone is not None
        zone_id = zone.id

    fake = MagicMock()
    fake.get_record.return_value = []
    monkeypatch.setattr("src.dns_browser_service.create_dns_client_from_settings", lambda *_a, **_k: fake)

    path = f"/zones/{zone_id}/records/search"
    for _ in range(3):
        response = client.get(path, params={"record_name": "@"})
        assert response.status_code in {200, 429}
    limited = client.get(path, params={"record_name": "@"})
    assert limited.status_code == 429
    body = limited.json()
    assert body["detail"]["error"] == "rate_limited"


def test_dns_browser_ignores_rotating_api_key_headers(enable_rate_limit) -> None:
    cookie = create_session_cookie("admin")
    for i in range(3):
        assert (
            rate_limit_exceeded(
                _request(
                    "/zones/1/records/search",
                    headers={"cookie": f"session={cookie}", "x-api-key": f"junk-{i}"},
                )
            )
            is False
        )
    assert (
        rate_limit_exceeded(
            _request(
                "/zones/1/records/search",
                headers={"cookie": f"session={cookie}", "x-api-key": "junk-bypass"},
            )
        )
        is True
    )
