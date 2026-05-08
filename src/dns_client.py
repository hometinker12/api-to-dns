from typing import List, Optional
import os

from .models import DnsRecordRequest

class AzureDnsClient:
    def __init__(self):
        # Check if Azure credentials are configured
        required_vars = ['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Azure DNS functionality requires the following environment variables: {', '.join(missing_vars)}")

        # Import Azure modules only when needed
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.dns import DnsManagementClient
            from azure.mgmt.dns.models import RecordSet
            from azure.core.exceptions import ResourceNotFoundError
        except ImportError as e:
            raise ImportError(f"Azure SDK not installed. Install azure-identity and azure-mgmt-dns to use Azure DNS functionality: {e}")

        self.credential = DefaultAzureCredential()
        self.DnsManagementClient = DnsManagementClient
        self.RecordSet = RecordSet
        self.ResourceNotFoundError = ResourceNotFoundError

    def create_or_update_record(self, payload: DnsRecordRequest, dns_server: Optional[str] = None, dns_zone: Optional[str] = None) -> bool:
        if dns_server:
            # Placeholder: stored Microsoft DNS server settings are available for a future provider.
            raise NotImplementedError("Microsoft DNS server integration is not implemented in this scaffold.")

        client = self.DnsManagementClient(self.credential, payload.subscription_id)
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
