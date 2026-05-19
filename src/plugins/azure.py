from typing import Dict, List, Optional

from ..models import DnsRecordInfo, DnsRecordRequest

from .base import DnsProviderPlugin, PluginField
from .utils import lookup_record_types_to_query


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
            raise ValueError(
                "Azure DNS requires tenant id, client id, and client secret in application settings."
            )
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
            raise ImportError(
                "Azure SDK not installed. Install azure-identity and azure-mgmt-dns: "
                f"{e}"
            ) from e

        self.credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        self.DnsManagementClient = DnsManagementClient
        self.RecordSet = RecordSet
        self.ResourceNotFoundError = ResourceNotFoundError
        self.subscription_id = subscription_id
        self.resource_group = resource_group

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> bool:
        if dns_server:
            raise ValueError("Azure DNS ignores per-server host settings; use Azure fields on the zone configuration.")

        if not payload.zone_name:
            raise ValueError("zone_name is required for Azure DNS.")

        client = self.DnsManagementClient(self.credential, self.subscription_id)
        record_set_name = payload.record_name.strip(".") or "@"
        record_type = payload.record_type.upper()

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            existing = self._get_existing_record_set(
                client,
                self.resource_group,
                payload.zone_name,
                record_set_name,
                inner,
            )
            if existing is None:
                return False
            try:
                client.record_sets.delete(
                    self.resource_group,
                    payload.zone_name,
                    record_set_name,
                    inner,
                )
            except self.ResourceNotFoundError:
                return False
            return True

        existing = self._get_existing_record_set(
            client,
            self.resource_group,
            payload.zone_name,
            record_set_name,
            record_type,
        )
        record_set = self._build_record_set(record_type, payload.values, payload.ttl or 300)

        client.record_sets.create_or_update(
            self.resource_group,
            payload.zone_name,
            record_set_name,
            record_type,
            record_set,
        )

        return existing is not None

    def get_record(
        self,
        *,
        record_name: str,
        record_type: Optional[str] = None,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> List[DnsRecordInfo]:
        if dns_server:
            raise ValueError("Azure DNS ignores per-server host settings; use Azure fields on the zone configuration.")
        if not dns_zone:
            raise ValueError("Zone name is required for Azure DNS.")

        record_set_name = record_name.strip(".") or "@"
        display_name = record_set_name
        client = self.DnsManagementClient(self.credential, self.subscription_id)
        types_to_query = lookup_record_types_to_query(record_type)
        results: List[DnsRecordInfo] = []
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

    def _record_set_to_info(self, record_set, display_name: str, record_type: str) -> DnsRecordInfo:
        ttl = int(record_set.ttl or 300)
        rt = record_type.upper()
        values: List[str] = []
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

    def _build_record_set(self, record_type: str, values: List[str], ttl: int):
        if record_type == "A":
            return self.RecordSet(ttl=ttl, a_records=[{"ipv4_address": value} for value in values])
        if record_type == "AAAA":
            return self.RecordSet(ttl=ttl, aaaa_records=[{"ipv6_address": value} for value in values])
        if record_type == "CNAME":
            return self.RecordSet(ttl=ttl, cname_record={"cname": values[0]})
        if record_type == "TXT":
            return self.RecordSet(ttl=ttl, txt_records=[{"value": [value]} for value in values])
        raise ValueError(f"Unsupported record type: {record_type}")


def create_client(settings: Dict[str, Optional[str]]) -> AzureDnsClient:
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
