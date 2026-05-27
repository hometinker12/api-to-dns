import ipaddress
import socket
from typing import List, Optional, Tuple

import dns.message
import dns.name
import dns.query
import dns.rdatatype

from ..models import DnsRecordInfo

LOOKUP_RECORD_TYPES: Tuple[str, ...] = ("A", "AAAA", "CNAME", "TXT")


def normalize_lookup_record_type(record_type: Optional[str]) -> Optional[str]:
    if record_type is None or not str(record_type).strip():
        return None
    rt = str(record_type).strip().upper()
    if rt not in LOOKUP_RECORD_TYPES:
        raise ValueError(
            f"Record type must be one of {', '.join(LOOKUP_RECORD_TYPES)}; got {record_type!r}."
        )
    return rt


def lookup_record_types_to_query(record_type: Optional[str]) -> Tuple[str, ...]:
    normalized = normalize_lookup_record_type(record_type)
    if normalized:
        return (normalized,)
    return LOOKUP_RECORD_TYPES


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
    if not r or r == "@":
        return "@"
    suffix = "." + z
    if r.lower().endswith(suffix.lower()):
        return r[: -len(suffix)] or "@"
    return r


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


def _format_rdata_value(record_type: str, rdata) -> str:
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
    return rdata.to_text()


def _query_record_details_at_name(
    server: str,
    zone_name: str,
    relative_name: str,
    record_type: str,
) -> Optional[DnsRecordInfo]:
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

    ttl: Optional[int] = None
    values: List[str] = []
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
    record_type: Optional[str] = None,
) -> List[DnsRecordInfo]:
    results: List[DnsRecordInfo] = []
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
