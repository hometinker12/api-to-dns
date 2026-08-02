"""Shared DNS hostname validation for App DNS Name and OpenSSL subjects."""

from __future__ import annotations

import re

# Single-label or FQDN hostnames. Rejects spaces, path separators, and control chars.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")
_FORBIDDEN_CHARS_RE = re.compile(r"[\x00-\x1f\x7f/\\]")


def validate_dns_hostname(name: str) -> str:
    """Return a cleaned hostname or raise ``ValueError`` when invalid."""
    cleaned = (name or "").strip().rstrip(".")
    if not cleaned:
        raise ValueError("Hostname cannot be empty.")
    if _FORBIDDEN_CHARS_RE.search(cleaned):
        raise ValueError("Hostname contains invalid control or path characters.")
    if " " in cleaned or "\t" in cleaned:
        raise ValueError("Hostname cannot contain whitespace.")
    if cleaned in {".", ".."} or ".." in cleaned:
        raise ValueError("Hostname is not a valid DNS name.")
    if not _HOSTNAME_RE.match(cleaned):
        raise ValueError("Hostname must be a valid DNS label or FQDN.")
    return cleaned
