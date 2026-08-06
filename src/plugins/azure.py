from ..dns_record_types import (
    LOOKUP_RECORD_TYPES,
    format_caa,
    format_mx,
    format_srv,
    normalize_hostname,
    normalize_record_values,
    parse_caa,
    parse_mx,
    parse_srv,
)
from ..models import DnsRecordInfo, DnsRecordListResult, DnsRecordRequest
from .base import DNS_ZONE_DOMAIN_FIELD, DnsProviderPlugin, PluginField
from .utils import dns_relative_name, lookup_record_types_to_query, record_name_matches


class AzureDnsClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group: str,
    ):
        if not tenant_id or not client_id or not client_secret:
            raise ValueError("Azure DNS requires tenant id, client id, and client secret in application settings.")
        if not subscription_id:
            raise ValueError("Azure DNS requires subscription id in zone settings.")
        if not resource_group:
            raise ValueError("Azure DNS requires resource group in zone settings.")
        try:
            from azure.core.exceptions import ResourceNotFoundError
            from azure.identity import ClientSecretCredential
            from azure.mgmt.dns import DnsManagementClient
            from azure.mgmt.dns.models import RecordSet
        except ImportError as e:
            raise ImportError(f"Azure SDK not installed. Install azure-identity and azure-mgmt-dns: {e}") from e

        self.credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        self.DnsManagementClient = DnsManagementClient
        self.RecordSet = RecordSet
        self.ResourceNotFoundError = ResourceNotFoundError
        self.subscription_id = subscription_id
        self.resource_group = resource_group

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> bool:
        if dns_server:
            raise ValueError("Azure DNS ignores per-server host settings; use Azure fields on the zone configuration.")

        if not dns_zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        client = self.DnsManagementClient(self.credential, self.subscription_id)
        record_set_name = payload.record_name.strip(".") or "@"
        record_type = payload.record_type.upper()

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            if inner == "SOA":
                raise ValueError("SOA records are view-only and cannot be deleted.")
            existing = self._get_existing_record_set(
                client,
                self.resource_group,
                dns_zone,
                record_set_name,
                inner,
            )
            if existing is None:
                return False
            try:
                client.record_sets.delete(
                    self.resource_group,
                    dns_zone,
                    record_set_name,
                    inner,
                )
            except self.ResourceNotFoundError:
                return False
            return True

        if record_type == "SOA":
            raise ValueError("SOA records are view-only and cannot be created or updated.")

        existing = self._get_existing_record_set(
            client,
            self.resource_group,
            dns_zone,
            record_set_name,
            record_type,
        )
        values = normalize_record_values(record_type, list(payload.values))
        record_set = self._build_record_set(record_type, values, payload.ttl or 300)

        client.record_sets.create_or_update(
            self.resource_group,
            dns_zone,
            record_set_name,
            record_type,
            record_set,
        )

        return existing is not None

    def get_record(
        self,
        *,
        record_name: str,
        record_type: str | None = None,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> list[DnsRecordInfo]:
        if dns_server:
            raise ValueError("Azure DNS ignores per-server host settings; use Azure fields on the zone configuration.")
        if not dns_zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        record_set_name = record_name.strip(".") or "@"
        display_name = record_set_name
        client = self.DnsManagementClient(self.credential, self.subscription_id)
        types_to_query = lookup_record_types_to_query(record_type)
        results: list[DnsRecordInfo] = []
        for rt in types_to_query:
            existing = self._get_existing_record_set(
                client,
                self.resource_group,
                dns_zone,
                record_set_name,
                rt,
            )
            if existing is not None:
                results.append(self._record_set_to_info(existing, display_name, rt))
        return results

    def list_records(
        self,
        *,
        name_pattern: str | None = None,
        record_type: str | None = None,
        limit: int = 100,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> DnsRecordListResult:
        if dns_server:
            raise ValueError("Azure DNS ignores per-server host settings; use Azure fields on the zone configuration.")
        if not dns_zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        requested_type = record_type.upper() if record_type else None
        result_limit = max(1, int(limit))
        client = self.DnsManagementClient(self.credential, self.subscription_id)
        records: list[DnsRecordInfo] = []
        for record_set in client.record_sets.list_by_dns_zone(self.resource_group, dns_zone):
            raw_type = str(getattr(record_set, "type", "") or "")
            rr_type = raw_type.rsplit("/", 1)[-1].upper()
            if rr_type not in LOOKUP_RECORD_TYPES or (requested_type and rr_type != requested_type):
                continue
            display_name = dns_relative_name(dns_zone, str(getattr(record_set, "name", "") or "@"))
            if not record_name_matches(name_pattern, display_name):
                continue
            records.append(self._record_set_to_info(record_set, display_name, rr_type))
            if len(records) > result_limit:
                return DnsRecordListResult(records=records[:result_limit], truncated=True)
        return DnsRecordListResult(records=records, truncated=False)

    def _record_set_to_info(self, record_set, display_name: str, record_type: str) -> DnsRecordInfo:
        ttl = int(record_set.ttl or 300)
        rt = record_type.upper()
        values: list[str] = []
        if rt == "A":
            values = [r.ipv4_address for r in (record_set.a_records or [])]
        elif rt == "AAAA":
            values = [r.ipv6_address for r in (record_set.aaaa_records or [])]
        elif rt == "CNAME":
            cname = record_set.cname_record
            if cname and cname.cname:
                values = [cname.cname.rstrip(".")]
        elif rt == "TXT":
            for txt in record_set.txt_records or []:
                if txt.value:
                    for part in txt.value:
                        values.append(part)
        elif rt == "MX":
            for mx in record_set.mx_records or []:
                values.append(format_mx(int(mx.preference), str(mx.exchange)))
        elif rt == "NS":
            for ns in record_set.ns_records or []:
                values.append(normalize_hostname(str(ns.nsdname)))
        elif rt == "SRV":
            for srv in record_set.srv_records or []:
                values.append(format_srv(int(srv.priority), int(srv.weight), int(srv.port), str(srv.target)))
        elif rt == "CAA":
            for caa in record_set.caa_records or []:
                values.append(format_caa(int(caa.flags), str(caa.tag), str(caa.value)))
        elif rt == "PTR":
            for ptr in record_set.ptr_records or []:
                values.append(normalize_hostname(str(ptr.ptrdname)))
        elif rt == "SOA":
            soa = record_set.soa_record
            if soa:
                values = [
                    (
                        f"{normalize_hostname(str(soa.host))} {str(soa.email).rstrip('.')} "
                        f"{int(soa.serial_number)} {int(soa.refresh_time)} "
                        f"{int(soa.retry_time)} {int(soa.expire_time)} {int(soa.minimum_ttl)}"
                    )
                ]
        return DnsRecordInfo(
            record_name=display_name,
            record_type=rt,
            ttl=ttl,
            values=values,
        )

    def _get_existing_record_set(
        self,
        client,
        resource_group: str,
        zone_name: str,
        record_name: str,
        record_type: str,
    ):
        try:
            return client.record_sets.get(resource_group, zone_name, record_name, record_type)
        except self.ResourceNotFoundError:
            return None

    def _build_record_set(self, record_type: str, values: list[str], ttl: int):
        if record_type == "A":
            return self.RecordSet(ttl=ttl, a_records=[{"ipv4_address": value} for value in values])
        if record_type == "AAAA":
            return self.RecordSet(ttl=ttl, aaaa_records=[{"ipv6_address": value} for value in values])
        if record_type == "CNAME":
            return self.RecordSet(ttl=ttl, cname_record={"cname": values[0]})
        if record_type == "TXT":
            return self.RecordSet(ttl=ttl, txt_records=[{"value": [value]} for value in values])
        if record_type == "MX":
            mx_records = []
            for value in values:
                priority, exchange = parse_mx(value)
                mx_records.append({"preference": priority, "exchange": exchange})
            return self.RecordSet(ttl=ttl, mx_records=mx_records)
        if record_type == "NS":
            return self.RecordSet(ttl=ttl, ns_records=[{"nsdname": value} for value in values])
        if record_type == "SRV":
            srv_records = []
            for value in values:
                priority, weight, port, target = parse_srv(value)
                srv_records.append(
                    {
                        "priority": priority,
                        "weight": weight,
                        "port": port,
                        "target": target,
                    }
                )
            return self.RecordSet(ttl=ttl, srv_records=srv_records)
        if record_type == "CAA":
            caa_records = []
            for value in values:
                flags, tag, caa_value = parse_caa(value)
                if caa_value.startswith('"') and caa_value.endswith('"') and len(caa_value) >= 2:
                    caa_value = caa_value[1:-1]
                caa_records.append({"flags": flags, "tag": tag, "value": caa_value})
            return self.RecordSet(ttl=ttl, caa_records=caa_records)
        if record_type == "PTR":
            return self.RecordSet(ttl=ttl, ptr_records=[{"ptrdname": value} for value in values])
        raise ValueError(f"Unsupported record type: {record_type}")


def create_client(settings: dict[str, str | None]) -> AzureDnsClient:
    return AzureDnsClient(
        tenant_id=settings.get("azure_tenant_id") or "",
        client_id=settings.get("azure_client_id") or "",
        client_secret=settings.get("azure_client_secret") or "",
        subscription_id=settings.get("azure_subscription_id") or "",
        resource_group=settings.get("azure_resource_group") or "",
    )


PLUGIN = DnsProviderPlugin(
    key="azure",
    label="Azure DNS (REST API)",
    heading="Azure DNS",
    help_text="Use an Azure service principal with permission to manage records in the zone. Target DNS Server and TSIG settings are not used for Azure DNS.",
    fields=[
        DNS_ZONE_DOMAIN_FIELD,
        PluginField("azure_tenant_id", "Azure tenant ID", autocomplete="off"),
        PluginField("azure_client_id", "Azure client ID (application ID)", autocomplete="off"),
        PluginField(
            "azure_client_secret",
            "Azure client secret",
            type="password",
            autocomplete="new-password",
            preserve_on_blank=True,
        ),
        PluginField("azure_subscription_id", "Default subscription ID", autocomplete="off"),
        PluginField("azure_resource_group", "Default resource group", autocomplete="off"),
    ],
    create_client=create_client,
)
