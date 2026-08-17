"""Provider-neutral DNS RRset mutation helpers shared by public API and admin browser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .dns_record_types import (
    guard_mutation_allowed,
    normalize_mutable_record_type,
    normalize_record_values,
    validate_ttl,
)
from .zone_service import provider_dns_zone


@dataclass(frozen=True)
class DnsMutationOutcome:
    status: str
    action: str
    http_status: int
    record_name: str
    record_type: str
    values: list[str]
    dns_zone: str


@dataclass(frozen=True)
class PreparedMutation:
    record_name: str
    record_type: str
    ttl: int
    values: list[str]


class PatchMergeError(ValueError):
    """Existing record is missing TTL or values needed to merge a PATCH."""


def prepare_mutation(
    *,
    record_name: str,
    record_type: str,
    ttl: int | None = None,
    values: list[str] | None = None,
    dns_zone: str | None = None,
    require_values: bool = True,
    require_ttl: bool = False,
) -> PreparedMutation:
    """Normalize and guard a mutation before provider I/O."""
    name = (record_name or "").strip()
    if not name:
        raise ValueError("record_name is required.")
    rt = normalize_mutable_record_type(record_type)
    guard_mutation_allowed(record_name=name, record_type=rt, dns_zone=dns_zone)
    final_ttl = validate_ttl(ttl, required=require_ttl)
    final_values = normalize_record_values(rt, list(values or [])) if require_values else []
    return PreparedMutation(record_name=name, record_type=rt, ttl=final_ttl, values=final_values)


def merge_patch(
    existing: Any,
    patch_ttl: int | None,
    patch_values: list[str] | None,
) -> tuple[int, list[str]]:
    """Merge PATCH ttl/values onto an existing record. Omitted fields are preserved."""
    if existing.ttl is None or not existing.values:
        raise PatchMergeError("Could not read existing TTL and values for PATCH merge.")
    final_ttl = int(patch_ttl) if patch_ttl is not None else int(existing.ttl)
    final_values = list(patch_values) if patch_values is not None else list(existing.values)
    return final_ttl, final_values


def record_exists_at_type(
    client,
    *,
    settings: dict[str, Any],
    record_name: str,
    record_type: str,
) -> bool:
    records = client.get_record(
        record_name=record_name,
        record_type=record_type,
        dns_server=settings.get("dns_server"),
        dns_zone=provider_dns_zone(settings),
    )
    return bool(records)


def apply_rrset_mutation(
    client,
    *,
    settings: dict[str, Any],
    zone_name: str,
    record_name: str,
    record_type: str,
    ttl: int | None,
    values: list[str],
    mode: Literal["create", "replace", "delete"],
) -> DnsMutationOutcome:
    """Create, replace, or delete an RRset with shared 409/404 semantics."""
    from .schemas.dns import DnsRecordRequest

    rt_upper = record_type.strip().upper()
    provider_domain = provider_dns_zone(settings)
    exists = record_exists_at_type(
        client,
        settings=settings,
        record_name=record_name,
        record_type=rt_upper,
    )

    if mode == "create" and exists:
        return DnsMutationOutcome(
            status="error",
            action="record_already_exists",
            http_status=409,
            record_name=record_name,
            record_type=rt_upper,
            values=list(values),
            dns_zone=provider_domain,
        )

    if mode in ("replace", "delete") and not exists:
        return DnsMutationOutcome(
            status="error",
            action="not_found",
            http_status=404,
            record_name=record_name,
            record_type=rt_upper,
            values=[] if mode == "delete" else list(values),
            dns_zone=provider_domain,
        )

    if mode == "delete":
        internal = DnsRecordRequest(
            zone_name=zone_name,
            record_type="DELETE",
            record_name=record_name,
            ttl=ttl or 300,
            values=[rt_upper],
        )
        response_values: list[str] = []
        action = "deleted"
    else:
        internal = DnsRecordRequest(
            zone_name=zone_name,
            record_type=rt_upper,
            record_name=record_name,
            ttl=ttl if ttl is not None else 300,
            values=list(values),
        )
        response_values = list(values)
        action = "created" if mode == "create" else "updated"

    client.create_or_update_record(
        internal,
        dns_server=settings.get("dns_server"),
        dns_zone=provider_domain,
    )
    return DnsMutationOutcome(
        status="success",
        action=action,
        http_status=200,
        record_name=record_name,
        record_type=rt_upper,
        values=response_values,
        dns_zone=provider_domain,
    )


def apply_patch_mutation(
    client,
    *,
    settings: dict[str, Any],
    zone_name: str,
    record_name: str,
    record_type: str,
    patch_ttl: int | None,
    patch_values: list[str] | None,
) -> DnsMutationOutcome:
    """GET existing RRset, merge PATCH fields, then replace. Missing records are 404."""
    from .schemas.dns import DnsRecordRequest

    rt_upper = record_type.strip().upper()
    provider_domain = provider_dns_zone(settings)
    records = client.get_record(
        record_name=record_name,
        record_type=rt_upper,
        dns_server=settings.get("dns_server"),
        dns_zone=provider_domain,
    )
    if not records:
        return DnsMutationOutcome(
            status="error",
            action="not_found",
            http_status=404,
            record_name=record_name,
            record_type=rt_upper,
            values=list(patch_values or []),
            dns_zone=provider_domain,
        )

    final_ttl, final_values = merge_patch(records[0], patch_ttl, patch_values)
    internal = DnsRecordRequest(
        zone_name=zone_name,
        record_type=rt_upper,
        record_name=record_name,
        ttl=final_ttl,
        values=final_values,
    )
    client.create_or_update_record(
        internal,
        dns_server=settings.get("dns_server"),
        dns_zone=provider_domain,
    )
    return DnsMutationOutcome(
        status="success",
        action="updated",
        http_status=200,
        record_name=record_name,
        record_type=rt_upper,
        values=final_values,
        dns_zone=provider_domain,
    )
