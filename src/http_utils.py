import hashlib
from typing import Optional

from fastapi import HTTPException, Request


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


def http_exception_from_dns_error(exc: Exception) -> HTTPException:
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, ValueError):
        return HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": str(exc) or "invalid request"},
        )
    if isinstance(exc, RuntimeError):
        return HTTPException(
            status_code=502,
            detail={"error": "dns_provider_failed", "message": str(exc)},
        )
    if isinstance(exc, ImportError):
        return HTTPException(
            status_code=503,
            detail={"error": "dependency_unavailable", "message": str(exc)},
        )
    return HTTPException(
        status_code=500,
        detail={"error": "unexpected", "message": str(exc)},
    )


def api_key_fingerprint(api_key: str) -> str:
    if not api_key:
        return ""
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"
