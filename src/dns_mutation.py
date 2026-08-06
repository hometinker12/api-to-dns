"""Provider-neutral DNS RRset mutation helpers shared by public API and admin browser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

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
    from .models import DnsRecordRequest

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
