"""Canonical DNS record type metadata and value validation for admin browser + plugins."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

LOOKUP_RECORD_TYPES: tuple[str, ...] = (
    "A",
    "AAAA",
    "CNAME",
    "TXT",
    "MX",
    "NS",
    "SRV",
    "CAA",
    "PTR",
    "SOA",
)
PUBLIC_RECORD_TYPES: frozenset[str] = frozenset({"A", "AAAA", "CNAME", "TXT"})
MUTABLE_RECORD_TYPES: frozenset[str] = frozenset(LOOKUP_RECORD_TYPES) - {"SOA"}

MIN_TTL = 0
MAX_TTL = 2_147_483_647

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
_CAA_TAG_RE = re.compile(r"^[A-Za-z0-9]+$")


@dataclass(frozen=True)
class RecordTypeSpec:
    fields: tuple[str, ...]
    multiple: bool = True
    mutable: bool = True
    label: str = ""


RECORD_TYPE_SPECS: dict[str, RecordTypeSpec] = {
    "A": RecordTypeSpec(("address",), label="A"),
    "AAAA": RecordTypeSpec(("address",), label="AAAA"),
    "CNAME": RecordTypeSpec(("target",), multiple=False, label="CNAME"),
    "TXT": RecordTypeSpec(("value",), label="TXT"),
    "MX": RecordTypeSpec(("priority", "exchange"), label="MX"),
    "NS": RecordTypeSpec(("hostname",), label="NS"),
    "SRV": RecordTypeSpec(("priority", "weight", "port", "target"), label="SRV"),
    "CAA": RecordTypeSpec(("flags", "tag", "value"), label="CAA"),
    "PTR": RecordTypeSpec(("hostname",), label="PTR"),
    "SOA": RecordTypeSpec(("value",), multiple=False, mutable=False, label="SOA"),
}


def record_type_options() -> list[dict[str, object]]:
    """Safe metadata for the admin browser type filter and forms."""
    options: list[dict[str, object]] = [{"value": "", "label": "All records", "mutable": False}]
    for rt in LOOKUP_RECORD_TYPES:
        spec = RECORD_TYPE_SPECS[rt]
        options.append(
            {
                "value": rt,
                "label": spec.label or rt,
                "fields": list(spec.fields),
                "multiple": spec.multiple,
                "mutable": spec.mutable,
            }
        )
    return options


def normalize_lookup_record_type(record_type: str | None) -> str | None:
    if record_type is None or not str(record_type).strip():
        return None
    rt = str(record_type).strip().upper()
    if rt not in LOOKUP_RECORD_TYPES:
        raise ValueError(f"Record type must be one of {', '.join(LOOKUP_RECORD_TYPES)}; got {record_type!r}.")
    return rt


def normalize_mutable_record_type(record_type: str) -> str:
    rt = (record_type or "").strip().upper()
    if rt not in MUTABLE_RECORD_TYPES:
        raise ValueError(f"record_type must be one of {', '.join(sorted(MUTABLE_RECORD_TYPES))}; got {record_type!r}.")
    return rt


def normalize_public_record_type(record_type: str) -> str:
    rt = (record_type or "").strip().upper()
    if rt not in PUBLIC_RECORD_TYPES:
        raise ValueError(f"record_type must be one of {', '.join(sorted(PUBLIC_RECORD_TYPES))}; got {record_type!r}.")
    return rt


def lookup_record_types_to_query(record_type: str | None) -> tuple[str, ...]:
    normalized = normalize_lookup_record_type(record_type)
    if normalized:
        return (normalized,)
    return LOOKUP_RECORD_TYPES


def validate_ttl(ttl: int | None, *, required: bool = False) -> int:
    if ttl is None:
        if required:
            raise ValueError("ttl is required.")
        return 300
    try:
        value = int(ttl)
    except (TypeError, ValueError) as exc:
        raise ValueError("ttl must be an integer.") from exc
    if value < MIN_TTL or value > MAX_TTL:
        raise ValueError(f"ttl must be between {MIN_TTL} and {MAX_TTL}.")
    return value


def normalize_hostname(value: str, *, allow_at: bool = False) -> str:
    host = (value or "").strip().rstrip(".")
    if allow_at and host in {"", "@"}:
        return "@"
    if not host or not _HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid hostname: {value!r}.")
    return host


def _parse_uint(token: str, *, field: str, maximum: int = 65535) -> int:
    try:
        value = int(token)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer.") from exc
    if value < 0 or value > maximum:
        raise ValueError(f"{field} must be between 0 and {maximum}.")
    return value


def parse_mx(value: str) -> tuple[int, str]:
    parts = (value or "").strip().split()
    if len(parts) != 2:
        raise ValueError("MX value must be: priority exchange")
    return _parse_uint(parts[0], field="priority"), normalize_hostname(parts[1])


def parse_srv(value: str) -> tuple[int, int, int, str]:
    parts = (value or "").strip().split()
    if len(parts) != 4:
        raise ValueError("SRV value must be: priority weight port target")
    return (
        _parse_uint(parts[0], field="priority"),
        _parse_uint(parts[1], field="weight"),
        _parse_uint(parts[2], field="port"),
        normalize_hostname(parts[3]),
    )


def parse_caa(value: str) -> tuple[int, str, str]:
    parts = (value or "").strip().split(None, 2)
    if len(parts) != 3:
        raise ValueError("CAA value must be: flags tag value")
    flags = _parse_uint(parts[0], field="flags", maximum=255)
    tag = parts[1].strip()
    if not _CAA_TAG_RE.match(tag):
        raise ValueError(f"Invalid CAA tag: {tag!r}.")
    caa_value = parts[2].strip()
    if not caa_value:
        raise ValueError("CAA value is required.")
    if " " in caa_value and not (caa_value.startswith('"') and caa_value.endswith('"')):
        caa_value = f'"{caa_value}"'
    return flags, tag.lower(), caa_value


def is_reverse_zone(dns_zone: str) -> bool:
    z = (dns_zone or "").strip().rstrip(".").lower()
    return z.endswith(".in-addr.arpa") or z.endswith(".ip6.arpa")


def is_apex_name(record_name: str, dns_zone: str | None = None) -> bool:
    """True for @/empty and for names that resolve to the zone apex (including the zone FQDN)."""
    name = (record_name or "").strip().rstrip(".")
    if not name or name == "@":
        return True
    if not dns_zone:
        return False
    zone = dns_zone.strip().rstrip(".")
    if not zone:
        return False
    if name.lower() == zone.lower():
        return True
    # FQDN under the zone that collapses to apex (trailing zone label only).
    suffix = "." + zone.lower()
    return name.lower().endswith(suffix) and name.lower()[: -len(suffix)] == ""


def guard_mutation_allowed(
    *,
    record_name: str,
    record_type: str,
    dns_zone: str | None = None,
) -> None:
    rt = (record_type or "").strip().upper()
    if rt == "SOA":
        raise ValueError("SOA records are view-only and cannot be created, edited, or deleted.")
    if rt == "NS" and is_apex_name(record_name, dns_zone):
        raise ValueError("Apex NS records cannot be modified from the admin DNS browser.")
    if rt == "PTR" and dns_zone and not is_reverse_zone(dns_zone):
        raise ValueError("PTR records may only be managed in reverse zones (in-addr.arpa or ip6.arpa).")


def normalize_record_value(record_type: str, value: str) -> str:
    rt = (record_type or "").strip().upper()
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Record values must not be empty.")

    if rt == "A":
        addr = ipaddress.ip_address(raw)
        if addr.version != 4:
            raise ValueError(f"A record requires an IPv4 address; got {value!r}.")
        return str(addr)
    if rt == "AAAA":
        addr = ipaddress.ip_address(raw)
        if addr.version != 6:
            raise ValueError(f"AAAA record requires an IPv6 address; got {value!r}.")
        return str(addr)
    if rt == "CNAME":
        return normalize_hostname(raw)
    if rt == "TXT":
        return raw
    if rt == "MX":
        priority, exchange = parse_mx(raw)
        return f"{priority} {exchange}"
    if rt == "NS":
        return normalize_hostname(raw)
    if rt == "SRV":
        priority, weight, port, target = parse_srv(raw)
        return f"{priority} {weight} {port} {target}"
    if rt == "CAA":
        flags, tag, caa_value = parse_caa(raw)
        return f"{flags} {tag} {caa_value}"
    if rt == "PTR":
        return normalize_hostname(raw)
    if rt == "SOA":
        return raw
    raise ValueError(f"Unsupported record type: {record_type!r}.")


def normalize_record_values(record_type: str, values: list[str]) -> list[str]:
    rt = (record_type or "").strip().upper()
    if rt not in RECORD_TYPE_SPECS:
        raise ValueError(f"Unsupported record type: {record_type!r}.")
    spec = RECORD_TYPE_SPECS[rt]
    if not values:
        raise ValueError("values is required and must contain at least one entry.")
    if not spec.multiple and len(values) != 1:
        raise ValueError(f"{rt} requires exactly one value.")
    return [normalize_record_value(rt, v) for v in values]


def format_mx(priority: int, exchange: str) -> str:
    return f"{int(priority)} {normalize_hostname(str(exchange))}"


def format_srv(priority: int, weight: int, port: int, target: str) -> str:
    return f"{int(priority)} {int(weight)} {int(port)} {normalize_hostname(str(target))}"


def format_caa(flags: int, tag: str, value: str) -> str:
    return normalize_record_value("CAA", f"{flags} {tag} {value}")
