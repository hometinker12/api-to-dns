import ipaddress
import socket

import dns.message
import dns.name
import dns.query
import dns.rdatatype


def ps_single_quoted(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def winrm_rr_type(upper_rr: str) -> str:
    """RR type string expected by DnsServer PowerShell cmdlets."""
    u = upper_rr.strip().upper()
    return "Txt" if u == "TXT" else u


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


def record_existed_before_update(
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
