"""Unit tests for remote syslog formatting and the bounded forwarder."""

from __future__ import annotations

import json
import socket
import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from src.log_constants import LOG_LEVEL_ERROR, LOG_LEVEL_INFORMATIONAL, LOG_LEVEL_WARNING
from src.models import ActivityLog
from src.remote_syslog import (
    APP_NAME,
    ActivityLogSnapshot,
    RemoteSyslogForwarder,
    SyslogConfig,
    encode_rfc5424,
    frame_tcp,
    meets_minimum_level,
    sanitize_msg_id,
    validate_syslog_config,
)


def _snapshot(**overrides) -> ActivityLogSnapshot:
    base = {
        "id": 42,
        "timestamp": datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC),
        "level": LOG_LEVEL_WARNING,
        "category": "security",
        "event_type": "auth.login_failed",
        "status": "error",
        "actor_type": "anonymous",
        "actor_label": "guest",
        "message": "login failed",
        "details": {"password": "***redacted***", "reason": "bad credentials"},
        "request_ip": "203.0.113.10",
    }
    base.update(overrides)
    return ActivityLogSnapshot(**base)


def test_encode_rfc5424_includes_json_payload_and_pri() -> None:
    config = SyslogConfig(enabled=True, host="syslog.example", facility="local0", hostname="apitodns.local")
    event = _snapshot()
    encoded = encode_rfc5424(event, config).decode("ascii")
    assert encoded.startswith("<132>1 ")  # local0(16)*8 + warning(4)
    assert f" {APP_NAME} - auth.login_failed - " in encoded
    payload = json.loads(encoded.split(" - ", 2)[-1])
    assert payload["event_type"] == "auth.login_failed"
    assert payload["details"]["password"] == "***redacted***"
    assert payload["level"] == LOG_LEVEL_WARNING


def test_frame_tcp_uses_octet_counting() -> None:
    message = b"<134>1 test"
    framed = frame_tcp(message)
    assert framed == b"11 <134>1 test"
    assert int(framed.split(b" ", 1)[0]) == len(message)


def test_sanitize_msg_id_strips_unsafe_characters() -> None:
    assert sanitize_msg_id("dns.record_created") == "dns.record_created"
    assert sanitize_msg_id("a/b c") == "a_b_c"


def test_meets_minimum_level() -> None:
    assert meets_minimum_level(LOG_LEVEL_ERROR, LOG_LEVEL_WARNING)
    assert not meets_minimum_level(LOG_LEVEL_INFORMATIONAL, LOG_LEVEL_WARNING)


def test_validate_syslog_config_requires_host_when_enabled() -> None:
    with pytest.raises(ValueError, match="Host is required"):
        validate_syslog_config(
            enabled=True,
            host="",
            port=6514,
            protocol="tls",
            facility="local0",
            minimum_level=LOG_LEVEL_INFORMATIONAL,
            timeout=5,
            queue_size=100,
        )


def test_validate_syslog_config_requires_plaintext_opt_in() -> None:
    with pytest.raises(ValueError, match="Allow insecure plaintext"):
        validate_syslog_config(
            enabled=True,
            host="syslog.example",
            port=514,
            protocol="udp",
            facility="local0",
            minimum_level=LOG_LEVEL_INFORMATIONAL,
            timeout=5,
            queue_size=100,
            allow_insecure_plaintext=False,
        )
    cfg = validate_syslog_config(
        enabled=True,
        host="syslog.example",
        port=514,
        protocol="udp",
        facility="local0",
        minimum_level=LOG_LEVEL_INFORMATIONAL,
        timeout=5,
        queue_size=100,
        allow_insecure_plaintext=True,
    )
    assert cfg.uses_plaintext is True


def test_snapshot_from_row_parses_details_json() -> None:
    row = ActivityLog(
        id=7,
        timestamp=datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC),
        level=LOG_LEVEL_INFORMATIONAL,
        category="dns",
        event_type="dns.record_created",
        details_json='{"record_type":"A"}',
        message="created",
    )
    snapshot = ActivityLogSnapshot.from_row(row)
    assert snapshot.details == {"record_type": "A"}
    assert snapshot.as_dict()["event_type"] == "dns.record_created"


def test_forwarder_udp_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[bytes, tuple[str, int]]] = []

    class FakeUDP:
        def __init__(self, *args, **kwargs):
            pass

        def settimeout(self, value):
            return None

        def sendto(self, data, addr):
            sent.append((data, addr))

        def close(self):
            return None

    monkeypatch.setattr(socket, "socket", FakeUDP)
    forwarder = RemoteSyslogForwarder()
    config = SyslogConfig(
        enabled=True,
        host="127.0.0.1",
        port=5514,
        protocol="udp",
        facility="local0",
        minimum_level=LOG_LEVEL_INFORMATIONAL,
        hostname="test-host",
        queue_size=10,
        allow_insecure_plaintext=True,
    )
    forwarder.configure(config)
    forwarder.enqueue(_snapshot(event_type="system.syslog_updated", level=LOG_LEVEL_INFORMATIONAL))
    deadline = time.time() + 2
    while not sent and time.time() < deadline:
        time.sleep(0.01)
    forwarder.stop(drain_timeout=1)
    assert sent
    message, addr = sent[0]
    assert addr == ("127.0.0.1", 5514)
    assert b'"event_type":"system.syslog_updated"' in message


def test_forwarder_tcp_framing_and_reconnect(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads: list[bytes] = []
    connects = {"count": 0}
    fail_next_send = {"value": False}

    class FakeTCP:
        def settimeout(self, value):
            return None

        def sendall(self, data):
            if fail_next_send["value"]:
                fail_next_send["value"] = False
                raise OSError("broken pipe")
            payloads.append(data)

        def close(self):
            return None

    def fake_create_connection(addr, timeout=None):
        connects["count"] += 1
        return FakeTCP()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    forwarder = RemoteSyslogForwarder()
    forwarder.configure(
        SyslogConfig(
            enabled=True,
            host="127.0.0.1",
            port=6514,
            protocol="tcp",
            facility="user",
            minimum_level=LOG_LEVEL_INFORMATIONAL,
            hostname="test-host",
            queue_size=10,
            allow_insecure_plaintext=True,
        )
    )
    forwarder.enqueue(_snapshot(event_type="dns.record_created", level=LOG_LEVEL_INFORMATIONAL))
    deadline = time.time() + 2
    while not payloads and time.time() < deadline:
        time.sleep(0.01)
    fail_next_send["value"] = True
    forwarder.enqueue(_snapshot(event_type="dns.record_updated", level=LOG_LEVEL_INFORMATIONAL))
    deadline = time.time() + 2
    while len(payloads) < 2 and time.time() < deadline:
        time.sleep(0.01)
    forwarder.stop(drain_timeout=1)
    assert len(payloads) >= 2
    assert connects["count"] >= 2
    first = payloads[0]
    length_str, rest = first.split(b" ", 1)
    assert int(length_str) == len(rest)
    assert b"dns.record_created" in rest


def test_forwarder_respects_minimum_level_and_disabled() -> None:
    forwarder = RemoteSyslogForwarder()
    forwarder.configure(
        SyslogConfig(
            enabled=True,
            host="127.0.0.1",
            port=5514,
            protocol="udp",
            minimum_level=LOG_LEVEL_WARNING,
            queue_size=2,
            allow_insecure_plaintext=True,
        )
    )
    forwarder.enqueue(_snapshot(level=LOG_LEVEL_INFORMATIONAL, event_type="dns.zones_list"))
    assert forwarder._queue.empty()
    forwarder.configure(
        SyslogConfig(
            enabled=False,
            host="127.0.0.1",
            port=5514,
            queue_size=2,
            allow_insecure_plaintext=True,
        )
    )
    forwarder.enqueue(_snapshot(level=LOG_LEVEL_ERROR, event_type="dns.provider_failed"))
    assert forwarder._queue.empty()
    forwarder.stop(drain_timeout=0.5)


def test_forwarder_drops_when_queue_full(monkeypatch: pytest.MonkeyPatch) -> None:
    warnings: list[str] = []

    forwarder = RemoteSyslogForwarder()
    monkeypatch.setattr(forwarder, "_warn_rate_limited", lambda msg, *a, **k: warnings.append(msg % a if a else msg))
    # Block the worker from draining by not starting it and filling manually.
    forwarder._config = SyslogConfig(
        enabled=True,
        host="127.0.0.1",
        port=5514,
        queue_size=1,
        allow_insecure_plaintext=True,
    )
    forwarder._queue = __import__("queue").Queue(maxsize=1)
    forwarder._queue.put_nowait((1, _snapshot()))
    forwarder.enqueue(_snapshot(event_type="system.smtp_updated"))
    assert warnings
    assert "queue is full" in warnings[0]


def test_forwarder_reconfigure_updates_generation() -> None:
    forwarder = RemoteSyslogForwarder()
    first = SyslogConfig(enabled=True, host="a.example", port=6514, protocol="tls", queue_size=5)
    second = SyslogConfig(enabled=True, host="b.example", port=6514, protocol="tls", queue_size=5)
    forwarder.configure(first)
    gen1 = forwarder.current_config().generation
    forwarder.configure(second)
    gen2 = forwarder.current_config().generation
    assert gen2 == gen1 + 1
    assert forwarder.current_config().host == "b.example"
    forwarder.stop(drain_timeout=0.5)


def test_forwarder_stop_is_idempotent() -> None:
    forwarder = RemoteSyslogForwarder()
    forwarder.configure(SyslogConfig(enabled=False, host="", port=514, queue_size=5))
    forwarder.stop(drain_timeout=0.2)
    forwarder.stop(drain_timeout=0.2)


def test_emit_redacts_secrets_before_forward(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Raw sensitive details must be redacted before the forwarder serializes JSON."""
    import src.remote_syslog as remote_syslog
    from src import activity_logging
    from src.db import SessionLocal

    captured: list[ActivityLogSnapshot] = []

    class Capture:
        def enqueue(self, event):
            captured.append(event)

    monkeypatch.setattr(remote_syslog, "REMOTE_SYSLOG", Capture())
    with SessionLocal() as db:
        activity_logging.emit_activity_event(
            db,
            event_type="system.smtp_updated",
            level=LOG_LEVEL_INFORMATIONAL,
            message="smtp touched",
            details={"smtp_password": "super-secret", "servers_count": 1},
            evaluate_alerts=False,
        )
    assert captured
    assert captured[0].details["smtp_password"] == "***redacted***"
    encoded = encode_rfc5424(captured[0], SyslogConfig(hostname="host"))
    assert b"super-secret" not in encoded
    assert b"***redacted***" in encoded


def test_apply_remote_syslog_config_rehydrates_worker(client: TestClient) -> None:
    from src.activity_logging import apply_remote_syslog_config, set_remote_syslog_config
    from src.db import SessionLocal
    from src.remote_syslog import REMOTE_SYSLOG

    try:
        with SessionLocal() as db:
            set_remote_syslog_config(
                db,
                enabled=True,
                host="rehydrate.example",
                port=5514,
                protocol="udp",
                facility="local2",
                minimum_level=LOG_LEVEL_WARNING,
                timeout=4,
                queue_size=123,
                allow_insecure_plaintext=True,
            )
            REMOTE_SYSLOG.configure(SyslogConfig(enabled=False))
            assert REMOTE_SYSLOG.current_config().enabled is False
            apply_remote_syslog_config(db)
        cfg = REMOTE_SYSLOG.current_config()
        assert cfg.enabled is True
        assert cfg.host == "rehydrate.example"
        assert cfg.port == 5514
        assert cfg.facility == "local2"
        assert cfg.minimum_level == LOG_LEVEL_WARNING
        assert cfg.queue_size == 123
    finally:
        REMOTE_SYSLOG.configure(SyslogConfig(enabled=False))


def test_enqueue_failure_isolation(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Emitting an activity event must not raise when the forwarder misbehaves."""
    import src.remote_syslog as remote_syslog
    from src import activity_logging
    from src.db import SessionLocal

    class Boom:
        def enqueue(self, event):
            raise RuntimeError("boom")

    monkeypatch.setattr(remote_syslog, "REMOTE_SYSLOG", Boom())
    with SessionLocal() as db:
        row = activity_logging.emit_activity_event(
            db,
            event_type="system.app_dns_name_changed",
            level=LOG_LEVEL_INFORMATIONAL,
            message="ok",
            evaluate_alerts=False,
        )
    assert row is not None
