from typing import List, Optional
from azure.identity import DefaultAzureCredential
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet
from azure.core.exceptions import ResourceNotFoundError

from .models import DnsRecordRequest

class AzureDnsClient:
    def __init__(self):
        self.credential = DefaultAzureCredential()

    def create_or_update_record(self, payload: DnsRecordRequest, dns_server: Optional[str] = None, dns_zone: Optional[str] = None) -> bool:
        if dns_server:
            # Placeholder: stored Microsoft DNS server settings are available for a future provider.
            raise NotImplementedError("Microsoft DNS server integration is not implemented in this scaffold.")

        client = DnsManagementClient(self.credential, payload.subscription_id)
        record_set_name = payload.record_name.strip('.') or '@'
        record_type = payload.record_type.upper()

        existing = self._get_existing_record_set(
            client,
            payload.resource_group,
            payload.zone_name,
            record_set_name,
            record_type,
        )
        record_set = self._build_record_set(record_type, payload.values, payload.ttl)

        client.record_sets.create_or_update(
            payload.resource_group,
            payload.zone_name,
            record_set_name,
            record_type,
            record_set,
        )

        return existing is not None

    def _get_existing_record_set(
        self,
        client: DnsManagementClient,
        resource_group: str,
        zone_name: str,
        record_name: str,
        record_type: str,
    ):
        try:
            return client.record_sets.get(resource_group, zone_name, record_name, record_type)
        except ResourceNotFoundError:
            return None

    def _build_record_set(self, record_type: str, values: List[str], ttl: int) -> RecordSet:
        if record_type == "A":
            return RecordSet(ttl=ttl, a_records=[{"ipv4_address": value} for value in values])
        if record_type == "AAAA":
            return RecordSet(ttl=ttl, aaaa_records=[{"ipv6_address": value} for value in values])
        if record_type == "CNAME":
            return RecordSet(ttl=ttl, cname_record={"cname": values[0]})
        if record_type == "TXT":
            return RecordSet(ttl=ttl, txt_records=[{"value": [value]} for value in values])
        raise ValueError(f"Unsupported record type: {record_type}")
