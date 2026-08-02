import base64

import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.update

from ..models import DnsRecordRequest
from .base import DNS_ZONE_DOMAIN_FIELD, DnsProviderPlugin, PluginField
from .utils import dns_relative_name, query_dns_records_at_name, record_existed_before_update, tcp_endpoint_host


class BindTsigDnsClient:
    """BIND (or any RFC 2136 server with TSIG), including Windows Server DNS with a TSIG key."""

    def __init__(self, tsig_key_name: str, tsig_secret_b64: str, tsig_algorithm: str = "hmac-sha256"):
        if not tsig_key_name or not tsig_secret_b64:
            raise ValueError("BIND DNS requires a TSIG key name and secret (base64) in the credentials fields.")
        try:
            secret = base64.b64decode(tsig_secret_b64.strip())
        except Exception as e:
            raise ValueError("TSIG secret must be valid base64 (as in BIND named.conf).") from e
        keyname = dns.name.from_text(tsig_key_name if tsig_key_name.endswith(".") else f"{tsig_key_name}.")
        algo = dns.name.from_text(tsig_algorithm if tsig_algorithm.endswith(".") else f"{tsig_algorithm}.")
        self._key = dns.tsig.Key(keyname, secret, algorithm=algo)
        self._keyring: dict[dns.name.Name, dns.tsig.Key] = {keyname: self._key}
        self._keyname = keyname

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> bool:
        if not dns_server:
            raise ValueError("DNS server host is required for BIND (set Target DNS Server in settings).")
        zone_name = (dns_zone or "").strip().rstrip(".")
        if not zone_name:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        record_type = payload.record_type.upper()
        ttl = int(payload.ttl or 300)
        relative = dns_relative_name(zone_name, payload.record_name)
        origin = dns.name.from_text(zone_name)

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            rdtype = dns.rdatatype.from_text(inner)
            existed = record_existed_before_update(dns_server, zone_name, relative, rdtype)
            if not existed:
                return False
            update = dns.update.Update(origin, keyring=self._keyring, keyname=self._keyname)
            node = relative if relative not in ("@", "") else "@"
            update.delete(node, rdtype)
            response = dns.query.tcp(update, tcp_endpoint_host(dns_server), timeout=15)
            if response.rcode() != dns.rcode.NOERROR:
                raise RuntimeError(f"DNS UPDATE failed: {dns.rcode.to_text(response.rcode())}")
            return True

        rdtype = dns.rdatatype.from_text(record_type)
        existed = record_existed_before_update(dns_server, zone_name, relative, rdtype)

        update = dns.update.Update(origin, keyring=self._keyring, keyname=self._keyname)
        node = relative if relative not in ("@", "") else "@"

        # replace() accepts (ttl, rdtype, *text_values) or (ttl, *rdata_objects) - not (ttl, rdtype, *rdata).
        if record_type == "A":
            update.replace(node, ttl, dns.rdatatype.A, *payload.values)
        elif record_type == "AAAA":
            update.replace(node, ttl, dns.rdatatype.AAAA, *payload.values)
        elif record_type == "CNAME":
            if len(payload.values) != 1:
                raise ValueError("CNAME requires exactly one value.")
            update.replace(node, ttl, dns.rdatatype.CNAME, payload.values[0])
        elif record_type == "TXT":
            update.replace(node, ttl, dns.rdatatype.TXT, *payload.values)
        else:
            raise ValueError(f"Unsupported record type for BIND: {record_type}")

        response = dns.query.tcp(update, tcp_endpoint_host(dns_server), timeout=15)
        if response.rcode() != dns.rcode.NOERROR:
            raise RuntimeError(f"DNS UPDATE failed: {dns.rcode.to_text(response.rcode())}")
        return existed

    def get_record(
        self,
        *,
        record_name: str,
        record_type: str | None = None,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ):
        if not dns_server:
            raise ValueError("DNS server host is required for BIND (set Target DNS Server in settings).")
        zone_name = (dns_zone or "").strip().rstrip(".")
        if not zone_name:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")
        relative = dns_relative_name(zone_name, record_name)
        return query_dns_records_at_name(dns_server, zone_name, relative, record_type)


def create_client(settings: dict[str, str | None]) -> BindTsigDnsClient:
    return BindTsigDnsClient(
        tsig_key_name=settings.get("dns_username") or "",
        tsig_secret_b64=settings.get("dns_password") or "",
        tsig_algorithm=settings.get("dns_tsig_algorithm") or "hmac-sha256",
    )


PLUGIN = DnsProviderPlugin(
    key="bind",
    label="BIND / RFC 2136 (TSIG)",
    heading="BIND / RFC 2136",
    help_text="Use a BIND server that accepts dynamic updates. Provide the TSIG key name, shared secret in base64, and the TSIG algorithm.",
    fields=[
        DNS_ZONE_DOMAIN_FIELD,
        PluginField("dns_server", "Target DNS Server", placeholder="bind01.example.com or 192.0.2.10"),
        PluginField("dns_username", "TSIG key name", autocomplete="off", placeholder="api-to-dns."),
        PluginField(
            "dns_password",
            "TSIG secret (base64)",
            type="password",
            autocomplete="new-password",
            preserve_on_blank=True,
        ),
        PluginField("dns_tsig_algorithm", "TSIG algorithm", placeholder="hmac-sha256", default="hmac-sha256"),
    ],
    create_client=create_client,
)
