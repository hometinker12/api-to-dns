"""Unit tests for DNS provider plugin get_record implementations."""

import json
from unittest.mock import MagicMock, patch

import dns.rdataclass
import dns.rdata
import dns.rdataset
import dns.rrset
import pytest

from src.models import DnsRecordInfo
from src.plugins.azure import AzureDnsClient
from src.plugins.bind import BindTsigDnsClient
from src.plugins.microsoft import MicrosoftWinRmDnsClient
from src.plugins.utils import normalize_lookup_record_type, query_dns_records_at_name


def test_normalize_lookup_record_type_accepts_supported_types() -> None:
    assert normalize_lookup_record_type("a") == "A"
    assert normalize_lookup_record_type(None) is None
    assert normalize_lookup_record_type("") is None


def test_normalize_lookup_record_type_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Record type must be one of"):
        normalize_lookup_record_type("MX")


def _mock_a_answer(ttl: int = 300, address: str = "192.0.2.1"):
    rdataset = dns.rdataset.from_text(dns.rdataclass.IN, "A", ttl, address)
    return dns.rrset.from_rdata("www.example.com.", ttl, rdataset[0])


@patch("src.plugins.utils.dns.query.tcp")
def test_query_dns_records_at_name_returns_all_types(mock_tcp) -> None:
    def side_effect(query, _host, timeout):
        rdtype = query.question[0].rdtype
        response = MagicMock()
        response.answer = [_mock_a_answer()] if rdtype == dns.rdatatype.A else []
        return response

    mock_tcp.side_effect = side_effect
    records = query_dns_records_at_name("127.0.0.1", "example.com", "www")
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])
    ]


@patch("src.plugins.utils.dns.query.tcp")
def test_query_dns_records_at_name_filters_by_type(mock_tcp) -> None:
    txt_rdataset = dns.rdataset.from_text(dns.rdataclass.IN, "TXT", 600, '"hello"')
    response = MagicMock()
    response.answer = [dns.rrset.from_rdata("example.com.", 600, txt_rdataset[0])]
    mock_tcp.return_value = response
    records = query_dns_records_at_name("127.0.0.1", "example.com", "@", record_type="TXT")
    assert records == [DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])]


@patch.object(AzureDnsClient, "_get_existing_record_set")
def test_azure_get_record_single_type(mock_get) -> None:
    client = AzureDnsClient(
        tenant_id="t",
        client_id="c",
        client_secret="s",
        subscription_id="sub",
        resource_group="rg",
    )
    client.DnsManagementClient = MagicMock()
    record_set = MagicMock()
    record_set.ttl = 300
    record_set.a_records = [MagicMock(ipv4_address="192.0.2.10")]
    record_set.aaaa_records = None
    record_set.cname_record = None
    record_set.txt_records = None
    mock_get.return_value = record_set
    records = client.get_record(record_name="www", record_type="A", dns_zone="example.com")
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])
    ]
    mock_get.assert_called_once()


@patch.object(AzureDnsClient, "_get_existing_record_set")
def test_azure_get_record_all_types(mock_get) -> None:
    client = AzureDnsClient(
        tenant_id="t",
        client_id="c",
        client_secret="s",
        subscription_id="sub",
        resource_group="rg",
    )
    client.DnsManagementClient = MagicMock()

    a_set = MagicMock()
    a_set.ttl = 500
    a_set.a_records = [MagicMock(ipv4_address="10.0.0.1")]
    a_set.aaaa_records = None
    a_set.cname_record = None
    a_set.txt_records = None

    cname_set = MagicMock()
    cname_set.ttl = 1000
    cname_set.a_records = None
    cname_set.aaaa_records = None
    cname_set.cname_record = MagicMock(cname="target.example.com.")
    cname_set.txt_records = None

    mock_get.side_effect = [a_set, None, cname_set, None]
    records = client.get_record(record_name="www", dns_zone="example.com")
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=500, values=["10.0.0.1"]),
        DnsRecordInfo(record_name="www", record_type="CNAME", ttl=1000, values=["target.example.com"]),
    ]


@patch.object(MicrosoftWinRmDnsClient, "_get_record_details")
def test_microsoft_get_record_single_type(mock_details) -> None:
    mock_details.return_value = DnsRecordInfo(
        record_name="www", record_type="A", ttl=300, values=["192.0.2.10"]
    )
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    records = client.get_record(
        record_name="www",
        record_type="A",
        dns_server="dc01",
        dns_zone="example.com",
    )
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])
    ]
    mock_details.assert_called_once()


@patch.object(MicrosoftWinRmDnsClient, "_get_record_details")
def test_microsoft_get_record_all_types(mock_details) -> None:
    mock_details.side_effect = [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"]),
        DnsRecordInfo(record_name="www", record_type="AAAA", ttl=300, values=["2001:db8::1"]),
        None,
        None,
    ]
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    records = client.get_record(
        record_name="www",
        dns_server="dc01",
        dns_zone="example.com",
    )
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"]),
        DnsRecordInfo(record_name="www", record_type="AAAA", ttl=300, values=["2001:db8::1"]),
    ]
    assert mock_details.call_count == 4


@patch.object(MicrosoftWinRmDnsClient, "_run_ps_with_retry")
def test_microsoft_get_record_details_parses_json(mock_run) -> None:
    payload = {"ttl": 450, "values": ["192.0.2.55", "192.0.2.56"]}
    mock_run.return_value = MagicMock(std_out=json.dumps(payload).encode(), std_err=b"")
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    info = client._get_record_details("dc01", "example.com", "www", "A")
    assert info == DnsRecordInfo(
        record_name="www", record_type="A", ttl=450, values=["192.0.2.55", "192.0.2.56"]
    )


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
@patch("src.plugins.bind.query_dns_records_at_name")
def test_bind_get_record_delegates(mock_query) -> None:
    mock_query.return_value = [
        DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])
    ]
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    records = client.get_record(
        record_name="@",
        dns_server="127.0.0.1",
        dns_zone="example.com",
    )
    assert records == [DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])]
    mock_query.assert_called_once_with("127.0.0.1", "example.com", "@", None)
