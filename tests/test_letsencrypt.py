from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from src import letsencrypt, ssl_certs
from src.db import SessionLocal
from src.settings_store import delete_setting


def test_renew_threshold_honors_configured_days() -> None:
    metadata = {
        "source": ssl_certs.SOURCE_LETSENCRYPT,
        "not_after": datetime.now(timezone.utc) + timedelta(days=10),
    }
    assert letsencrypt.should_renew_cert(metadata, 30) is True
    assert letsencrypt.should_renew_cert(metadata, 7) is False


def test_self_signed_cert_never_renews(client: TestClient, monkeypatch) -> None:
    called = False

    def prepare(_config):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(letsencrypt, "_acme_prepare_order", prepare)
    monkeypatch.setattr(letsencrypt, "_read_source", lambda: ssl_certs.SOURCE_SELF_SIGNED)
    with SessionLocal() as db:
        delete_setting(db, letsencrypt.SETTING_CONFIG)
        letsencrypt.save_config(
            db,
            email="admin@example.com",
            domains="example.com",
            challenge_type=letsencrypt.CHALLENGE_HTTP,
            zone_id=None,
            staging=True,
        )
        assert letsencrypt.maybe_renew_certificate(db) is None
    assert called is False


def test_http_challenge_state_round_trip(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(
        letsencrypt,
        "_acme_prepare_order",
        lambda _config: {
            "challenge": {
                "token": "abc",
                "response": "abc.response",
            }
        },
    )
    with SessionLocal() as db:
        letsencrypt.start_enrollment(
            db,
            email="admin@example.com",
            domains="example.com",
            challenge_type=letsencrypt.CHALLENGE_HTTP,
            zone_id=None,
            staging=True,
        )
    response = client.get("/.well-known/acme-challenge/abc")
    assert response.status_code == 200
    assert response.text == "abc.response"
