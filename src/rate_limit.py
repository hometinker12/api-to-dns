"""SQLite-backed rate limiting shared across workers/processes."""

from __future__ import annotations

import hashlib
import logging
import os
import random
import time

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from .db import SessionLocal
from .http_utils import api_key_from_headers, wants_json_response

LOGGER = logging.getLogger("api-to-dns")

# path prefix -> (max_requests, window_seconds)
_DEFAULT_LIMITS = {
    "/login": (20, 60),
    "/keycheck": (60, 60),
    "/dns-record": (180, 60),
    # Synthetic prefix for /zones/{id}/records[+ /search] (matched specially below).
    "/zones/*/records": (60, 60),
}


def _limits() -> dict[str, tuple[int, int]]:
    """Allow env overrides like RATE_LIMIT_LOGIN=30:60."""
    limits = dict(_DEFAULT_LIMITS)
    mapping = {
        "RATE_LIMIT_LOGIN": "/login",
        "RATE_LIMIT_KEYCHECK": "/keycheck",
        "RATE_LIMIT_DNS_RECORD": "/dns-record",
        "RATE_LIMIT_DNS_BROWSER": "/zones/*/records",
    }
    for env_name, path in mapping.items():
        raw = os.getenv(env_name, "").strip()
        if not raw or ":" not in raw:
            continue
        count_s, window_s = raw.split(":", 1)
        try:
            limits[path] = (max(1, int(count_s)), max(1, int(window_s)))
        except ValueError:
            continue
    return limits


def _is_dns_browser_path(path: str) -> bool:
    parts = [part for part in (path or "").split("/") if part]
    if len(parts) < 3 or parts[0] != "zones" or parts[2] != "records":
        return False
    if len(parts) == 3:
        return True
    return len(parts) == 4 and parts[3] == "search"


def _match_route(path: str, limits: dict[str, tuple[int, int]]) -> tuple[str, tuple[int, int]] | None:
    if _is_dns_browser_path(path) and "/zones/*/records" in limits:
        return "/zones/*/records", limits["/zones/*/records"]
    for prefix, rule in limits.items():
        if prefix == "/zones/*/records":
            continue
        if path == prefix or path.startswith(prefix + "/"):
            return prefix, rule
    return None


def _identity_hash(request: Request) -> str:
    path = request.url.path or ""
    # Session-only browser routes ignore unvalidated API-key headers so clients
    # cannot rotate X-API-Key / Bearer values to mint a fresh bucket per request.
    if _is_dns_browser_path(path):
        session_token = request.cookies.get("session")
        if session_token:
            try:
                from .auth import verify_session_cookie

                username, _version = verify_session_cookie(session_token)
                return f"session:{username.strip().lower()}"
            except Exception:
                pass
        client = getattr(request, "client", None)
        host = client.host if client else "unknown"
        return f"ip:{host}"

    api_key = api_key_from_headers(
        request.headers.get("x-api-key"),
        request.headers.get("authorization"),
    )
    if api_key:
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        return f"key:{digest}"
    client = getattr(request, "client", None)
    host = client.host if client else "unknown"
    return f"ip:{host}"


def _maybe_cleanup_expired(db, now: int) -> None:
    # Opportunistic cleanup keeps the table small without a dedicated sweeper.
    if random.random() > 0.05:
        return
    db.execute(text("DELETE FROM rate_limit_bucket WHERE expires_at < :now"), {"now": now})


def rate_limit_exceeded(request: Request) -> bool:
    if os.getenv("API_TO_DNS_DISABLE_RATE_LIMIT", "").strip().lower() in {"1", "true", "yes"}:
        return False
    path = request.url.path or ""
    limits = _limits()
    matched = _match_route(path, limits)
    if matched is None:
        return False
    route_prefix, (max_requests, window) = matched
    identity = _identity_hash(request)
    now = int(time.time())
    window_start = now - (now % window)
    expires_at = window_start + window

    try:
        with SessionLocal() as db:
            _maybe_cleanup_expired(db, now)
            # Atomic upsert/increment shared across workers.
            db.execute(
                text(
                    """
                    INSERT INTO rate_limit_bucket (route_prefix, identity_hash, window_start, count, expires_at)
                    VALUES (:route_prefix, :identity_hash, :window_start, 1, :expires_at)
                    ON CONFLICT(route_prefix, identity_hash, window_start)
                    DO UPDATE SET count = count + 1
                    """
                ),
                {
                    "route_prefix": route_prefix,
                    "identity_hash": identity,
                    "window_start": window_start,
                    "expires_at": expires_at,
                },
            )
            row = db.execute(
                text(
                    """
                    SELECT count FROM rate_limit_bucket
                    WHERE route_prefix = :route_prefix
                      AND identity_hash = :identity_hash
                      AND window_start = :window_start
                    """
                ),
                {
                    "route_prefix": route_prefix,
                    "identity_hash": identity,
                    "window_start": window_start,
                },
            ).first()
            db.commit()
            count = int(row[0]) if row else 1
            return count > max_requests
    except OperationalError as exc:
        # Fail closed on transient lock contention without taking the app down.
        LOGGER.warning("rate limit check failed closed due to database error: %s", exc)
        return True
    except Exception:
        LOGGER.exception("rate limit check failed closed due to unexpected error")
        return True


def rate_limit_rejection_response(request: Request):
    message = "Rate limit exceeded. Try again later."
    headers = {"Retry-After": "60"}
    path = request.url.path or ""
    if (
        wants_json_response(request)
        or path.startswith("/dns-record")
        or path == "/keycheck"
        or _is_dns_browser_path(path)
    ):
        return JSONResponse(
            status_code=429,
            content={"detail": {"error": "rate_limited", "message": message}},
            headers=headers,
        )
    if request.url.path == "/login":
        return PlainTextResponse(message, status_code=429, headers=headers)
    return JSONResponse(
        status_code=429,
        content={"detail": {"error": "rate_limited", "message": message}},
        headers=headers,
    )
