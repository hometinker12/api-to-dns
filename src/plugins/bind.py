import base64

import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.update
import dns.xfr
import dns.zone

from ..dns_record_types import MUTABLE_RECORD_TYPES, normalize_record_values
from ..models import DnsRecordInfo, DnsRecordListResult, DnsRecordRequest
from .base import DNS_ZONE_DOMAIN_FIELD, DnsProviderPlugin, PluginField
from .utils import (
    LOOKUP_RECORD_TYPES,
    dns_relative_name,
    format_rdata_value,
    normalize_lookup_record_type,
    query_dns_records_at_name,
    record_existed_before_update,
    record_name_matches,
    tcp_endpoint_host,
)


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
            if inner not in MUTABLE_RECORD_TYPES:
                raise ValueError(f"Unsupported record type for BIND: {inner}")
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

        if record_type not in MUTABLE_RECORD_TYPES:
            raise ValueError(f"Unsupported record type for BIND: {record_type}")

        validated = normalize_record_values(record_type, list(payload.values))
        rdtype = dns.rdatatype.from_text(record_type)
        existed = record_existed_before_update(dns_server, zone_name, relative, rdtype)

        update = dns.update.Update(origin, keyring=self._keyring, keyname=self._keyname)
        node = relative if relative not in ("@", "") else "@"
        update.replace(node, ttl, rdtype, *validated)

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

    def list_records(
        self,
        *,
        name_pattern: str | None = None,
        record_type: str | None = None,
        limit: int = 100,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> DnsRecordListResult:
        if not dns_server:
            raise ValueError("DNS server host is required for BIND (set Target DNS Server in settings).")
        zone_name = (dns_zone or "").strip().rstrip(".")
        if not zone_name:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        wanted_type = normalize_lookup_record_type(record_type)
        zone = self._transfer_zone(dns_server, zone_name)

        records: list[DnsRecordInfo] = []
        truncated = False
        for name in sorted(zone.nodes, key=lambda n: n.to_text()):
            relative = name.to_text()  # relativized apex renders as "@"
            if not record_name_matches(name_pattern, relative):
                continue
            for rdataset in zone.nodes[name].rdatasets:
                rt = dns.rdatatype.to_text(rdataset.rdtype)
                if rt not in LOOKUP_RECORD_TYPES:
                    continue  # skip RRSIG/NSEC/TSIG and other non-browsable types
                if wanted_type and rt != wanted_type:
                    continue
                if len(records) >= limit:
                    truncated = True
                    break
                records.append(
                    DnsRecordInfo(
                        record_name=relative,
                        record_type=rt,
                        ttl=int(rdataset.ttl),
                        values=[format_rdata_value(rt, rdata) for rdata in rdataset],
                    )
                )
            if truncated:
                break
        return DnsRecordListResult(records=records, truncated=truncated)

    def _transfer_zone(self, dns_server: str, zone_name: str) -> dns.zone.Zone:
        """AXFR the zone using the update TSIG key; requires allow-transfer on the server."""
        try:
            xfr = dns.query.xfr(
                tcp_endpoint_host(dns_server),
                zone_name,
                keyring=self._keyring,
                keyname=self._keyname,
                timeout=30,
                lifetime=60,
            )
            return dns.zone.from_xfr(xfr)
        except dns.xfr.TransferError as e:
            rcode_text = dns.rcode.to_text(e.rcode)
            if e.rcode in (dns.rcode.REFUSED, dns.rcode.NOTAUTH):
                key_label = self._keyname.to_text().rstrip(".")
                raise ValueError(
                    f"Zone transfer (AXFR) was refused ({rcode_text}). Browse and wildcard search "
                    f'require allow-transfer {{ key "{key_label}"; }}; '
                    "on the BIND zone — see BINDCONFIG.md. Exact record names still work."
                ) from e
            raise RuntimeError(f"Zone transfer (AXFR) failed: {rcode_text}") from e


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
