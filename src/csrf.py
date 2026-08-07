"""Same-origin CSRF checks for cookie-authenticated form POSTs."""

from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse

from .http_utils import api_key_from_headers, wants_json_response

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_EXEMPT_PREFIXES = (
    "/.well-known/",
    "/static/",
)


def relax_csrf_for_tests() -> bool:
    """Return True only when ``API_TO_DNS_RELAX_CSRF=1`` (test harness).

    Intentionally independent of ``API_TO_DNS_ALLOW_INSECURE_DEFAULTS`` so
    crypto placeholders never weaken CSRF or CORS.
    """
    return os.getenv("API_TO_DNS_RELAX_CSRF", "").strip().lower() in {"1", "true", "yes"}


def _host_matches(url: str, host: str) -> bool:
    if not url or not host:
        return False
    parsed = urlparse(url)
    netloc = (parsed.netloc or "").lower()
    expected = host.lower()
    return netloc == expected


def request_uses_api_key(request: Request) -> bool:
    return bool(
        api_key_from_headers(
            request.headers.get("x-api-key"),
            request.headers.get("authorization"),
        )
    )


def csrf_check_required(request: Request) -> bool:
    if request.method in _SAFE_METHODS:
        return False
    path = request.url.path or ""
    if any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES):
        return False
    if request_uses_api_key(request):
        return False
    return True


def csrf_origin_allowed(request: Request) -> bool:
    """Return True when Origin/Referer matches Host, or when checks are relaxed."""
    if not csrf_check_required(request):
        return True
    host = request.headers.get("host", "")
    origin = request.headers.get("origin")
    if origin:
        return _host_matches(origin, host)
    referer = request.headers.get("referer")
    if referer:
        return _host_matches(referer, host)
    # Browsers send Origin on cross-site POSTs. Missing both Origin and Referer
    # fails closed unless an explicit test-only override is set.
    return relax_csrf_for_tests()


def csrf_rejection_response(request: Request):
    message = "CSRF validation failed"
    if wants_json_response(request):
        return JSONResponse(status_code=403, content={"detail": {"error": "csrf_failed", "message": message}})
    return HTMLResponse(
        content=(
            "<!DOCTYPE html><html><head><title>CSRF failed</title>"
            "<script>(function(){var k='api-to-dns-theme';var s=localStorage.getItem(k);"
            "var t=(s==='light'||s==='dark')?s:(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');"
            "document.documentElement.setAttribute('data-theme',t);})();</script>"
            '<link rel="icon" type="image/svg+xml" href="/static/favicon.svg?v=2" />'
            '<link rel="stylesheet" href="/static/style.css" /></head>'
            '<body><div class="page">'
            '<a class="app-brand" href="/admin" aria-label="api-to-dns dashboard">'
            '<img class="app-brand-mark" src="/static/logo-mark.svg?v=2" alt="" />'
            '<span class="app-brand-name">api-to-dns</span></a>'
            f"<h1>Request blocked</h1>"
            f'<div class="alert error">{message}</div>'
            '<p><a class="button" href="/admin">Back</a></p></div></body></html>'
        ),
        status_code=403,
    )
