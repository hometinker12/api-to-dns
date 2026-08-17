"""SQLite support checks without constructing a non-SQLite engine."""

import logging

import pytest

from src.db import (
    NON_SQLITE_WARNING,
    is_sqlite_database_url,
    warn_if_non_sqlite_database,
)


def test_sqlite_urls_are_recognized() -> None:
    assert is_sqlite_database_url("sqlite:///./data/app.db")
    assert is_sqlite_database_url("sqlite:////app/data/app.db")
    assert is_sqlite_database_url("sqlite+pysqlite:///./data/app.db")
    assert is_sqlite_database_url("SQLITE:///./data/app.db")
    assert not is_sqlite_database_url("postgresql://user:pass@localhost/dns")
    assert not is_sqlite_database_url("mysql://localhost/dns")
    assert not is_sqlite_database_url("")


def test_non_sqlite_url_emits_warning(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("api_to_dns.test_db")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        asserted = warn_if_non_sqlite_database("postgresql://localhost/dns", logger=logger)
    assert asserted is True
    assert NON_SQLITE_WARNING in caplog.text


def test_sqlite_url_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("api_to_dns.test_db")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        asserted = warn_if_non_sqlite_database("sqlite:///./data/app.db", logger=logger)
    assert asserted is False
    assert NON_SQLITE_WARNING not in caplog.text


def test_allow_non_sqlite_suppresses_warning(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("API_TO_DNS_ALLOW_NON_SQLITE", "1")
    logger = logging.getLogger("api_to_dns.test_db")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        asserted = warn_if_non_sqlite_database("postgresql://localhost/dns", logger=logger)
    assert asserted is False
    assert NON_SQLITE_WARNING not in caplog.text


def test_init_db_invokes_non_sqlite_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_warn() -> bool:
        calls.append("called")
        return False

    monkeypatch.setattr("src.db.warn_if_non_sqlite_database", fake_warn)
    from src.db import init_db

    init_db()
    assert calls == ["called"]
