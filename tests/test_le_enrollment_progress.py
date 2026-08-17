import src.routes.settings_ssl as ssl_routes
from src import letsencrypt
from src.auth import create_session_cookie
from src.db import SessionLocal, init_db
from src.letsencrypt import CHALLENGE_DNS


def _ensure_db() -> None:
    init_db()


def test_enrollment_progress_round_trip() -> None:
    _ensure_db()
    with SessionLocal() as db:
        letsencrypt.clear_enrollment_progress(db)
        letsencrypt.write_enrollment_progress(
            db,
            phase="verify_dns",
            percent=45,
            message="Waiting for DNS propagation (attempt 2/5)...",
        )
        payload = letsencrypt.get_enrollment_progress(db)
    assert payload["phase"] == "verify_dns"
    assert payload["percent"] == 45
    assert payload["done"] is False
    assert payload["error"] is None


def test_get_progress_idle_when_missing(client) -> None:
    _ensure_db()
    with SessionLocal() as db:
        letsencrypt.clear_enrollment_progress(db)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.get("/settings/system/ssl-letsencrypt/progress")
    assert response.status_code == 200
    payload = response.json()
    assert payload["percent"] == 0
    assert payload["done"] is False
    assert payload["phase"] == "idle"


def test_start_enrollment_reports_progress_via_callback(monkeypatch) -> None:
    _ensure_db()
    calls: list[tuple[str, int, str]] = []

    def progress(phase: str, percent: int, message: str) -> None:
        calls.append((phase, percent, message))

    monkeypatch.setattr(letsencrypt, "_sleep_fn", lambda _seconds: None)
    monkeypatch.setattr(
        letsencrypt,
        "_acme_prepare_order",
        lambda _config: {
            "challenges": [
                {"domain": "api.example.com", "dns_value": "txt-value", "name": "_acme-challenge.api.example.com"}
            ],
            "challenge": {"domain": "api.example.com", "dns_value": "txt-value"},
            "order_resource": "{}",
            "private_key_pem": "key",
        },
    )
    monkeypatch.setattr(
        letsencrypt,
        "_acme_finalize_order",
        lambda _enrollment: {"key_pem": b"key", "cert_pem": b"cert"},
    )
    monkeypatch.setattr(letsencrypt, "install_letsencrypt_cert", lambda _k, _c: {"source": "letsencrypt"})
    monkeypatch.setattr(
        letsencrypt,
        "create_dns_txt_challenge",
        lambda *_args, **_kwargs: {"record_name": "x", "value": "txt-value"},
    )
    monkeypatch.setattr(letsencrypt, "_verify_dns_txt_challenge", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(letsencrypt, "delete_dns_txt_challenge", lambda *_args, **_kwargs: None)

    with SessionLocal() as db:
        from tests.test_letsencrypt import _sample_config_kwargs

        letsencrypt.start_enrollment(
            db,
            progress_cb=progress,
            **_sample_config_kwargs(challenge_type=CHALLENGE_DNS, zone_id=1),
        )

    phases = [phase for phase, _percent, _message in calls]
    assert "save_config" in phases
    assert "prepare_order" in phases
    assert "create_dns_records" in phases
    assert "finalize_order" in phases
    assert "install_cert" in phases
    assert calls[-1][1] == 95


def test_start_async_returns_202(client, monkeypatch) -> None:
    def fake_sync(kwargs, *, user: str) -> None:
        with SessionLocal() as db:
            letsencrypt.write_enrollment_progress(
                db,
                phase="complete",
                percent=100,
                message="Done",
                done=True,
                result_status="issued",
            )

    monkeypatch.setattr(ssl_routes, "_run_le_auto_enrollment_sync", fake_sync)
    with SessionLocal() as db:
        letsencrypt.clear_enrollment_progress(db)
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/settings/system/ssl-letsencrypt/start-async",
        data={
            "email": "admin@example.com",
            "root_dns_domain": "example.com",
            "common_name": "api.example.com",
            "subject_alt_names": "",
            "challenge_type": "dns-01",
            "zone_id": "1",
        },
    )
    assert response.status_code == 202
    assert response.json()["status"] == "started"


def test_start_async_rejects_concurrent_run(client) -> None:
    with SessionLocal() as db:
        letsencrypt.write_enrollment_progress(
            db,
            phase="verify_dns",
            percent=40,
            message="Waiting for DNS",
        )
    client.cookies.set("session", create_session_cookie("admin"))
    response = client.post(
        "/settings/system/ssl-letsencrypt/start-async",
        data={
            "email": "admin@example.com",
            "root_dns_domain": "example.com",
            "common_name": "api.example.com",
            "challenge_type": "dns-01",
            "zone_id": "1",
        },
    )
    assert response.status_code == 409
    with SessionLocal() as db:
        letsencrypt.clear_enrollment_progress(db)


def test_try_begin_enrollment_is_exclusive() -> None:
    _ensure_db()
    with SessionLocal() as db:
        letsencrypt.clear_enrollment_progress(db)
        assert letsencrypt.try_begin_enrollment(db) is True
        assert letsencrypt.try_begin_enrollment(db) is False
        letsencrypt.write_enrollment_progress(
            db,
            phase="complete",
            percent=100,
            message="Done",
            done=True,
            result_status="issued",
        )
        assert letsencrypt.try_begin_enrollment(db) is True
        letsencrypt.clear_enrollment_progress(db)
