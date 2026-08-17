import base64
import threading
from collections.abc import Iterator

import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.update
import dns.xfr

from ..dns_record_types import MUTABLE_RECORD_TYPES, normalize_record_values
from ..schemas.dns import DnsRecordInfo, DnsRecordListResult, DnsRecordRequest
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

# Bound AXFR memory/CPU: stop after this many answer RRsets from the wire, even if
# fewer than ``limit`` matched the browse/glob filter.
_AXFR_MAX_RRSETS_SCANNED = 5_000
# Cap concurrent BIND transfers process-wide so browse storms cannot open unbounded TCP AXFRs.
# Process-local semaphore; multi-worker uvicorn is unsupported.
_AXFR_MAX_CONCURRENT = 2
_AXFR_SLOTS = threading.BoundedSemaphore(_AXFR_MAX_CONCURRENT)


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
        records: list[DnsRecordInfo] = []
        truncated = False
        scanned = 0

        for relative, rdataset in self._iter_axfr_rrsets(dns_server, zone_name):
            scanned += 1
            if scanned > _AXFR_MAX_RRSETS_SCANNED:
                truncated = True
                break
            if not record_name_matches(name_pattern, relative):
                continue
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
        return DnsRecordListResult(records=records, truncated=truncated)

    def _iter_axfr_rrsets(self, dns_server: str, zone_name: str) -> Iterator[tuple[str, object]]:
        """Yield ``(relative_name, rrset)`` from a TSIG-signed AXFR without materializing the zone.

        Acquires a process-wide slot, streams messages, and closes the transfer early when the
        caller stops iterating (browse/glob limit or scan cap).
        """
        if not _AXFR_SLOTS.acquire(blocking=False):
            raise RuntimeError("Too many concurrent BIND zone transfers in progress; retry browse/search shortly.")
        xfr = None
        seen_soa = False
        try:
            try:
                xfr = dns.query.xfr(
                    tcp_endpoint_host(dns_server),
                    zone_name,
                    keyring=self._keyring,
                    keyname=self._keyname,
                    relativize=True,
                    timeout=30,
                    lifetime=60,
                )
                for msg in xfr:
                    for rrset in msg.answer:
                        if rrset.rdtype == dns.rdatatype.SOA:
                            if seen_soa:
                                continue  # trailing AXFR SOA
                            seen_soa = True
                        relative = rrset.name.to_text()
                        if relative in (".", ""):
                            relative = "@"
                        yield relative, rrset
            except dns.xfr.TransferError as e:
                raise self._map_transfer_error(e) from e
            except dns.tsig.PeerError as e:
                raise self._map_tsig_peer_error(e) from e
        finally:
            close = getattr(xfr, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
            _AXFR_SLOTS.release()

    def _map_transfer_error(self, e: dns.xfr.TransferError) -> Exception:
        rcode_text = dns.rcode.to_text(e.rcode)
        if e.rcode in (dns.rcode.REFUSED, dns.rcode.NOTAUTH):
            key_label = self._keyname.to_text().rstrip(".")
            return ValueError(
                f"Zone transfer (AXFR) was refused ({rcode_text}). Browse and wildcard search "
                f'require allow-transfer {{ key "{key_label}"; }}; '
                "on the BIND zone — see BINDCONFIG.md. Exact record names still work."
            )
        return RuntimeError(f"Zone transfer (AXFR) failed: {rcode_text}")

    def _map_tsig_peer_error(self, e: dns.tsig.PeerError) -> Exception:
        key_label = self._keyname.to_text().rstrip(".")
        algo_label = self._key.algorithm.to_text().rstrip(".")
        if isinstance(e, dns.tsig.PeerBadKey):
            return ValueError(
                f'BIND does not recognize TSIG key "{key_label}" ({algo_label}) (BADKEY). '
                "The key name and algorithm in this zone's settings must match a "
                f'key "{key_label}" block loaded in named.conf. Browse and wildcard '
                "search sign the zone transfer with this key — see BINDCONFIG.md. "
                "Exact record names still work."
            )
        if isinstance(e, dns.tsig.PeerBadSignature):
            return ValueError(
                f'TSIG signature was rejected for key "{key_label}" (BADSIG). '
                "Check that the base64 secret matches the BIND key block. "
                "Exact record names still work."
            )
        if isinstance(e, dns.tsig.PeerBadTime):
            return ValueError(
                f'TSIG time check failed for key "{key_label}" (BADTIME). '
                "Synchronize clocks on api-to-dns and the BIND server. "
                "Exact record names still work."
            )
        return ValueError(f"Zone transfer (AXFR) TSIG failed: {e}")


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
