"""Simple in-process rate limiting for auth and DNS endpoints."""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .http_utils import wants_json_response

_LOCK = threading.Lock()
_BUCKETS: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

# path prefix -> (max_requests, window_seconds)
_DEFAULT_LIMITS = {
    "/login": (20, 60),
    "/keycheck": (60, 60),
    "/dns-record": (180, 60),
}


def _limits() -> Dict[str, Tuple[int, int]]:
    """Allow env overrides like RATE_LIMIT_LOGIN=30:60."""
    limits = dict(_DEFAULT_LIMITS)
    mapping = {
        "RATE_LIMIT_LOGIN": "/login",
        "RATE_LIMIT_KEYCHECK": "/keycheck",
        "RATE_LIMIT_DNS_RECORD": "/dns-record",
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


def _client_key(request: Request) -> str:
    client = getattr(request, "client", None)
    host = client.host if client else "unknown"
    api_key = request.headers.get("x-api-key") or ""
    if api_key:
        # Bound cardinality while still isolating keys.
        return f"key:{api_key[:16]}"
    return f"ip:{host}"


def rate_limit_exceeded(request: Request) -> bool:
    if os.getenv("API_TO_DNS_DISABLE_RATE_LIMIT", "").strip().lower() in {"1", "true", "yes"}:
        return False
    path = request.url.path or ""
    limits = _limits()
    matched = None
    for prefix, rule in limits.items():
        if path == prefix or path.startswith(prefix + "/"):
            matched = rule
            break
    if matched is None:
        return False
    max_requests, window = matched
    key = (_client_key(request), path if path in limits else next(p for p in limits if path == p or path.startswith(p + "/")))
    now = time.monotonic()
    with _LOCK:
        bucket = _BUCKETS[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= max_requests:
            return True
        bucket.append(now)
    return False


def rate_limit_rejection_response(request: Request):
    message = "Rate limit exceeded. Try again later."
    headers = {"Retry-After": "60"}
    if wants_json_response(request) or request.url.path.startswith("/dns-record") or request.url.path == "/keycheck":
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
