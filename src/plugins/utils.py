import ipaddress
import socket
from fnmatch import fnmatchcase

import dns.message
import dns.name
import dns.query
import dns.rdatatype

from ..dns_record_types import (
    LOOKUP_RECORD_TYPES,
    lookup_record_types_to_query,
    normalize_lookup_record_type,
    normalize_record_value,
)
from ..schemas.dns import DnsRecordInfo

__all__ = [
    "LOOKUP_RECORD_TYPES",
    "dns_relative_name",
    "format_rdata_value",
    "has_dns_glob",
    "lookup_record_types_to_query",
    "normalize_lookup_record_type",
    "ps_single_quoted",
    "query_dns_records_at_name",
    "record_existed_before_update",
    "record_name_matches",
    "tcp_endpoint_host",
    "winrm_record_type_to_api",
    "winrm_rr_type",
]


def ps_single_quoted(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def winrm_rr_type(upper_rr: str) -> str:
    """RR type string expected by DnsServer PowerShell cmdlets."""
    u = upper_rr.strip().upper()
    return "Txt" if u == "TXT" else u


def winrm_record_type_to_api(ps_type: str) -> str:
    t = ps_type.strip()
    if t.upper() == "TXT" or t == "Txt":
        return "TXT"
    return t.upper()


def dns_relative_name(zone_name: str, record_name: str) -> str:
    z = zone_name.strip().rstrip(".")
    r = record_name.strip().rstrip(".")
    if not r or r == "@" or r.lower() == z.lower():
        return "@"
    suffix = "." + z
    if r.lower().endswith(suffix.lower()):
        return r[: -len(suffix)] or "@"
    return r


def has_dns_glob(record_name: str | None) -> bool:
    return any(char in (record_name or "") for char in ("*", "?"))


def record_name_matches(pattern: str | None, record_name: str) -> bool:
    """Match a relative DNS owner name using case-insensitive ``*``/``?`` glob syntax."""
    if not pattern:
        return True
    return fnmatchcase(record_name.casefold(), pattern.casefold())


def tcp_endpoint_host(host: str) -> str:
    """Resolve *host* for dns.query.tcp; dnspython expects an IP in this code path."""
    h = (host or "").strip()
    if not h:
        return h
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve DNS server hostname {h!r}: {e}") from e
    if not infos:
        raise ValueError(f"DNS server hostname {h!r} resolved to no addresses.")
    return infos[0][4][0]


def _record_exists_at_name(
    server: str,
    zone_name: str,
    relative_name: str,
    rdtype: dns.rdatatype.RdataType,
) -> bool:
    z = zone_name.strip().rstrip(".")
    if relative_name in ("@", ""):
        qname = dns.name.from_text(z)
    else:
        qname = dns.name.from_text(f"{relative_name}.{z}")
    q = dns.message.make_query(qname, rdtype)
    try:
        resp = dns.query.tcp(q, tcp_endpoint_host(server), timeout=10)
    except Exception:
        return False
    return bool(resp.answer)


def format_rdata_value(record_type: str, rdata) -> str:
    """Canonical string form of a dnspython rdata, matching DnsRecordInfo values."""
    rt = record_type.upper()
    if rt == "A":
        return str(rdata.address)
    if rt == "AAAA":
        return str(rdata.address)
    if rt == "CNAME":
        return rdata.target.to_text(omit_final_dot=True)
    if rt == "TXT":
        parts = rdata.strings or []
        return b"".join(parts).decode("utf-8", errors="replace")
    if rt == "MX":
        return normalize_record_value("MX", f"{int(rdata.preference)} {rdata.exchange.to_text(omit_final_dot=True)}")
    if rt == "NS":
        return rdata.target.to_text(omit_final_dot=True)
    if rt == "SRV":
        return normalize_record_value(
            "SRV",
            f"{int(rdata.priority)} {int(rdata.weight)} {int(rdata.port)} {rdata.target.to_text(omit_final_dot=True)}",
        )
    if rt == "CAA":
        tag = rdata.tag.decode("utf-8") if isinstance(rdata.tag, bytes) else str(rdata.tag)
        value = rdata.value.decode("utf-8") if isinstance(rdata.value, bytes) else str(rdata.value)
        return normalize_record_value("CAA", f"{int(rdata.flags)} {tag} {value}")
    if rt == "PTR":
        return rdata.target.to_text(omit_final_dot=True)
    if rt == "SOA":
        return rdata.to_text()
    return rdata.to_text()


_format_rdata_value = format_rdata_value


def _query_record_details_at_name(
    server: str,
    zone_name: str,
    relative_name: str,
    record_type: str,
) -> DnsRecordInfo | None:
    display_name = relative_name if relative_name not in ("@", "") else "@"
    z = zone_name.strip().rstrip(".")
    if relative_name in ("@", ""):
        qname = dns.name.from_text(z)
    else:
        qname = dns.name.from_text(f"{relative_name}.{z}")
    rdtype = dns.rdatatype.from_text(record_type)
    q = dns.message.make_query(qname, rdtype)
    try:
        resp = dns.query.tcp(q, tcp_endpoint_host(server), timeout=10)
    except Exception:
        return None
    if not resp.answer:
        return None

    ttl: int | None = None
    values: list[str] = []
    for rrset in resp.answer:
        if rrset.rdtype != rdtype:
            continue
        ttl = rrset.ttl
        for rdata in rrset:
            values.append(_format_rdata_value(record_type, rdata))
    if not values or ttl is None:
        return None
    return DnsRecordInfo(
        record_name=display_name,
        record_type=record_type,
        ttl=int(ttl),
        values=values,
    )


def query_dns_records_at_name(
    server: str,
    zone_name: str,
    relative_name: str,
    record_type: str | None = None,
) -> list[DnsRecordInfo]:
    results: list[DnsRecordInfo] = []
    for rt in lookup_record_types_to_query(record_type):
        info = _query_record_details_at_name(server, zone_name, relative_name, rt)
        if info is not None:
            results.append(info)
    return results


def record_existed_before_update(
    server: str,
    zone_name: str,
    relative_name: str,
    rdtype: dns.rdatatype.RdataType,
) -> bool:
    return _record_exists_at_name(server, zone_name, relative_name, rdtype)
