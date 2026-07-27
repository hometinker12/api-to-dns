import hashlib
import logging
import re
from typing import Optional

from fastapi import HTTPException, Request

LOGGER = logging.getLogger("api-to-dns")

_SECRETISH_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._~\-+/=]+|token[=:\s]+[^\s,;]+|secret[=:\s]+[^\s,;]+|"
    r"password[=:\s]+[^\s,;]+|api[_-]?key[=:\s]+[^\s,;]+)"
)


def wants_json_response(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "").lower() or "application/json" in request.headers.get(
        "content-type", ""
    ).lower()


def api_key_from_headers(x_api_key: Optional[str], authorization: Optional[str]) -> Optional[str]:
    api_key = x_api_key
    if not api_key and authorization:
        prefix = "Bearer "
        if authorization.startswith(prefix):
            api_key = authorization[len(prefix) :].strip()
    return api_key


def sanitize_client_error_message(exc: BaseException, *, fallback: str) -> str:
    """Return a short client-safe error string without credential-like substrings."""
    raw = (str(exc) or "").strip() or fallback
    first_line = raw.splitlines()[0].strip()[:512] or fallback
    return _SECRETISH_RE.sub("[redacted]", first_line)


def http_exception_from_dns_error(exc: Exception) -> HTTPException:
    if isinstance(exc, HTTPException):
        return exc
    LOGGER.exception("DNS operation failed: %s", exc)
    if isinstance(exc, ValueError):
        return HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "message": sanitize_client_error_message(exc, fallback="invalid request"),
            },
        )
    # Imported lazily to avoid circular imports with zone_service.
    from .zone_service import DnsProviderDisabledError

    if isinstance(exc, DnsProviderDisabledError):
        return HTTPException(
            status_code=503,
            detail={
                "error": "provider_disabled",
                "message": sanitize_client_error_message(exc, fallback="DNS provider is disabled"),
            },
        )
    if isinstance(exc, RuntimeError):
        return HTTPException(
            status_code=502,
            detail={
                "error": "dns_provider_failed",
                "message": sanitize_client_error_message(exc, fallback="DNS provider request failed"),
            },
        )
    if isinstance(exc, ImportError):
        return HTTPException(
            status_code=503,
            detail={
                "error": "dependency_unavailable",
                "message": sanitize_client_error_message(exc, fallback="Required dependency is unavailable"),
            },
        )
    return HTTPException(
        status_code=500,
        detail={
            "error": "unexpected",
            "message": "An unexpected error occurred while contacting the DNS provider",
        },
    )


def api_key_fingerprint(api_key: str) -> str:
    if not api_key:
        return ""
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"
