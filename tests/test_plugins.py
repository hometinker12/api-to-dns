"""Unit tests for DNS provider plugin get_record implementations."""

from unittest.mock import MagicMock, patch

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


@patch("src.plugins.utils.dns.query.tcp")
def test_query_dns_records_at_name_returns_all_types(mock_tcp) -> None:
    def side_effect(query, _host, timeout):
        rdtype = query.question[0].rdtype
        response = MagicMock()
        response.answer = [MagicMock()] if rdtype == 1 else []
        return response

    mock_tcp.side_effect = side_effect
    records = query_dns_records_at_name("127.0.0.1", "example.com", "www")
    assert records == [DnsRecordInfo(record_name="www", record_type="A")]


@patch("src.plugins.utils.dns.query.tcp")
def test_query_dns_records_at_name_filters_by_type(mock_tcp) -> None:
    response = MagicMock()
    response.answer = [MagicMock()]
    mock_tcp.return_value = response
    records = query_dns_records_at_name("127.0.0.1", "example.com", "@", record_type="TXT")
    assert records == [DnsRecordInfo(record_name="@", record_type="TXT")]


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
    mock_get.return_value = object()
    records = client.get_record(record_name="www", record_type="A", dns_zone="example.com")
    assert records == [DnsRecordInfo(record_name="www", record_type="A")]
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
    mock_get.side_effect = [object(), None, object(), None]
    records = client.get_record(record_name="www", dns_zone="example.com")
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A"),
        DnsRecordInfo(record_name="www", record_type="CNAME"),
    ]


@patch.object(MicrosoftWinRmDnsClient, "_record_exists", return_value=True)
def test_microsoft_get_record_single_type(mock_exists) -> None:
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    records = client.get_record(
        record_name="www",
        record_type="A",
        dns_server="dc01",
        dns_zone="example.com",
    )
    assert records == [DnsRecordInfo(record_name="www", record_type="A")]
    mock_exists.assert_called_once()


@patch.object(MicrosoftWinRmDnsClient, "_record_exists")
def test_microsoft_get_record_all_types(mock_exists) -> None:
    mock_exists.side_effect = [True, True, False, False]
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    records = client.get_record(
        record_name="www",
        dns_server="dc01",
        dns_zone="example.com",
    )
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A"),
        DnsRecordInfo(record_name="www", record_type="AAAA"),
    ]
    assert mock_exists.call_count == 4


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
@patch("src.plugins.bind.query_dns_records_at_name")
def test_bind_get_record_delegates(mock_query) -> None:
    mock_query.return_value = [DnsRecordInfo(record_name="@", record_type="TXT")]
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    records = client.get_record(
        record_name="@",
        dns_server="127.0.0.1",
        dns_zone="example.com",
    )
    assert records == [DnsRecordInfo(record_name="@", record_type="TXT")]
    mock_query.assert_called_once_with("127.0.0.1", "example.com", "@", None)
