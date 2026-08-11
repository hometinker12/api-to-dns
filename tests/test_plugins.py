"""Unit tests for DNS provider plugin get_record implementations."""

import json
from unittest.mock import MagicMock, patch

import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rrset
import dns.xfr
import dns.zone
import httpx
import pytest

from src.models import DnsRecordInfo, DnsRecordRequest
from src.plugins import bind as bind_mod
from src.plugins.azure import AzureDnsClient
from src.plugins.bind import BindTsigDnsClient
from src.plugins.cloudflare import CloudflareDnsClient
from src.plugins.microsoft import MicrosoftWinRmDnsClient
from src.plugins.microsoft import create_client as create_microsoft_client
from src.plugins.utils import (
    has_dns_glob,
    normalize_lookup_record_type,
    query_dns_records_at_name,
    record_name_matches,
)


def test_normalize_lookup_record_type_accepts_supported_types() -> None:
    assert normalize_lookup_record_type("a") == "A"
    assert normalize_lookup_record_type(None) is None
    assert normalize_lookup_record_type("") is None


def test_normalize_lookup_record_type_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Record type must be one of"):
        normalize_lookup_record_type("SPF")


def test_normalize_lookup_record_type_accepts_mx() -> None:
    assert normalize_lookup_record_type("MX") == "MX"


def test_relative_dns_glob_matching_is_case_insensitive() -> None:
    assert has_dns_glob("api-?")
    assert not has_dns_glob("www")
    assert record_name_matches("API-*", "api-v2")
    assert record_name_matches("?.internal", "a.internal")
    assert not record_name_matches("?.internal", "api.internal")


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
    assert records == [DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])]


@patch("src.plugins.utils.dns.query.tcp")
def test_query_dns_records_at_name_filters_by_type(mock_tcp) -> None:
    txt_rdataset = dns.rdataset.from_text(dns.rdataclass.IN, "TXT", 600, '"hello"')
    response = MagicMock()
    response.answer = [dns.rrset.from_rdata("example.com.", 600, txt_rdataset[0])]
    mock_tcp.return_value = response
    records = query_dns_records_at_name("127.0.0.1", "example.com", "@", record_type="TXT")
    assert records == [DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])]


@patch.object(AzureDnsClient, "_get_existing_record_set")
def test_azure_create_or_update_uses_dns_zone_not_payload_zone_name(mock_get) -> None:
    client = AzureDnsClient(
        tenant_id="t",
        client_id="c",
        client_secret="s",
        subscription_id="sub",
        resource_group="rg",
    )
    client.DnsManagementClient = MagicMock()
    mock_get.return_value = None
    payload = DnsRecordRequest(
        zone_name="config-key-not-domain",
        record_type="A",
        record_name="www",
        ttl=300,
        values=["192.0.2.10"],
    )
    client.create_or_update_record(payload, dns_zone="example.com")
    mock_get.assert_called_with(
        client.DnsManagementClient.return_value,
        "rg",
        "example.com",
        "www",
        "A",
    )


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
    assert records == [DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])]
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

    def side_effect(_client, _rg, _zone, _name, record_type):
        if record_type == "A":
            return a_set
        if record_type == "CNAME":
            return cname_set
        return None

    mock_get.side_effect = side_effect
    records = client.get_record(record_name="www", dns_zone="example.com")
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=500, values=["10.0.0.1"]),
        DnsRecordInfo(record_name="www", record_type="CNAME", ttl=1000, values=["target.example.com"]),
    ]


def test_azure_list_records_filters_case_insensitively_and_caps() -> None:
    from azure.mgmt.dns.operations import RecordSetsOperations

    client = AzureDnsClient(
        tenant_id="t",
        client_id="c",
        client_secret="s",
        subscription_id="sub",
        resource_group="rg",
    )

    first = MagicMock()
    first.type = "Microsoft.Network/dnszones/A"
    first.name = "Api-One"
    first.ttl = 300
    first.a_records = [MagicMock(ipv4_address="192.0.2.10")]

    second = MagicMock()
    second.type = "Microsoft.Network/dnszones/A"
    second.name = "api-two"
    second.ttl = 300
    second.a_records = [MagicMock(ipv4_address="192.0.2.20")]

    record_sets = MagicMock(spec=RecordSetsOperations)
    record_sets.list_by_dns_zone.return_value = [first, second]
    mgmt = MagicMock()
    mgmt.record_sets = record_sets
    client.DnsManagementClient = MagicMock(return_value=mgmt)

    result = client.list_records(name_pattern="API-*", record_type="A", limit=1, dns_zone="example.com")

    assert result.truncated is True
    assert result.records == [DnsRecordInfo(record_name="Api-One", record_type="A", ttl=300, values=["192.0.2.10"])]
    record_sets.list_by_dns_zone.assert_called_once_with("rg", "example.com")


@patch.object(MicrosoftWinRmDnsClient, "_get_record_details")
def test_microsoft_get_record_single_type(mock_details) -> None:
    mock_details.return_value = DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    records = client.get_record(
        record_name="www",
        record_type="A",
        dns_server="dc01",
        dns_zone="example.com",
    )
    assert records == [DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])]
    mock_details.assert_called_once()


@patch.object(MicrosoftWinRmDnsClient, "_get_record_details")
def test_microsoft_get_record_all_types(mock_details) -> None:
    def side_effect(_computer, _zone, _name, api_rr_type):
        if api_rr_type == "A":
            return DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])
        if api_rr_type == "AAAA":
            return DnsRecordInfo(record_name="www", record_type="AAAA", ttl=300, values=["2001:db8::1"])
        return None

    mock_details.side_effect = side_effect
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
    assert mock_details.call_count == 10


@patch.object(MicrosoftWinRmDnsClient, "_run_ps_with_retry")
def test_microsoft_get_record_details_parses_json(mock_run) -> None:
    payload = {"ttl": 450, "values": ["192.0.2.55", "192.0.2.56"]}
    mock_run.return_value = MagicMock(std_out=json.dumps(payload).encode(), std_err=b"")
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    info = client._get_record_details("dc01", "example.com", "www", "A")
    assert info == DnsRecordInfo(record_name="www", record_type="A", ttl=450, values=["192.0.2.55", "192.0.2.56"])


def test_microsoft_run_ps_payload_stages_long_scripts_via_tempfile() -> None:
    client = MicrosoftWinRmDnsClient(username="user", password="pass")
    session = MagicMock()
    ok = MagicMock(status_code=0, std_out=b'{"ok":true}', std_err=b"")
    session.run_ps.return_value = ok

    long_script = "$x = '" + ("a" * 5000) + "'\n$x"
    result = client._run_ps_payload(session, long_script)

    assert result is ok
    assert session.run_ps.call_count >= 2
    staged_scripts = [call.args[0] for call in session.run_ps.call_args_list]
    assert any("Set-Content" in script and ".b64" in script for script in staged_scripts)
    assert any("FromBase64String" in script and "& $ps1" in script for script in staged_scripts)
    assert not any(long_script in script for script in staged_scripts)


@patch.object(MicrosoftWinRmDnsClient, "_run_ps_with_retry")
def test_microsoft_list_records_filters_remotely_and_preserves_truncation(mock_run) -> None:
    payload = {
        "records": [
            {"record_name": "api-one", "record_type": "A", "ttl": 300, "values": ["192.0.2.10"]},
        ],
        "truncated": True,
    }
    mock_run.return_value = MagicMock(std_out=json.dumps(payload).encode(), std_err=b"")
    client = MicrosoftWinRmDnsClient(username="user", password="pass")

    result = client.list_records(
        name_pattern="api-*",
        record_type="A",
        limit=100,
        dns_server="dc01",
        dns_zone="example.com",
    )

    assert result.truncated is True
    assert result.records == [DnsRecordInfo(record_name="api-one", record_type="A", ttl=300, values=["192.0.2.10"])]
    script = mock_run.call_args.args[1]
    assert "-RRType" in script
    assert "$relative -notlike $NamePattern" in script
    assert "ForEach-Object" in script
    assert "New-Object System.Collections.ArrayList" in script
    assert "$order.Count -ge $Limit" in script
    assert "Select-Object -First ($Limit + 1)" not in script
    assert "BrowserRecordName" not in script
    assert "ConvertTo-Json" in script


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
@patch("src.plugins.bind.query_dns_records_at_name")
def test_bind_get_record_delegates(mock_query) -> None:
    mock_query.return_value = [DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])]
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    records = client.get_record(
        record_name="@",
        dns_server="127.0.0.1",
        dns_zone="example.com",
    )
    assert records == [DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])]
    mock_query.assert_called_once_with("127.0.0.1", "example.com", "@", None)


def _fake_bind_zone() -> dns.zone.Zone:
    return dns.zone.from_text(
        "$TTL 300\n"
        "@      IN SOA ns.example.com. hostmaster.example.com. (1 3600 600 86400 300)\n"
        "@      IN NS  ns.example.com.\n"
        "www    IN A   192.0.2.10\n"
        "api-v1 IN A   192.0.2.11\n"
        "api-v2 IN A   192.0.2.12\n"
        "mail   IN MX  10 mail.example.com.\n",
        origin="example.com",
        relativize=True,
    )


def _fake_axfr_rrsets():
    zone = _fake_bind_zone()
    for name in sorted(zone.nodes, key=lambda n: n.to_text()):
        for rdataset in zone.nodes[name].rdatasets:
            yield name.to_text(), rdataset


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
def test_bind_list_records_blank_browse_returns_all_rrsets() -> None:
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    with patch.object(client, "_iter_axfr_rrsets", return_value=_fake_axfr_rrsets()):
        result = client.list_records(dns_server="127.0.0.1", dns_zone="example.com")
    names = {(r.record_name, r.record_type) for r in result.records}
    assert ("www", "A") in names
    assert ("@", "SOA") in names
    assert result.truncated is False


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
def test_bind_list_records_glob_and_type_filter() -> None:
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    with patch.object(client, "_iter_axfr_rrsets", return_value=_fake_axfr_rrsets()):
        result = client.list_records(
            name_pattern="API-*",
            record_type="A",
            dns_server="127.0.0.1",
            dns_zone="example.com",
        )
    assert [r.record_name for r in result.records] == ["api-v1", "api-v2"]


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
def test_bind_list_records_caps_at_limit_and_flags_truncated() -> None:
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    with patch.object(client, "_iter_axfr_rrsets", return_value=_fake_axfr_rrsets()):
        result = client.list_records(limit=2, dns_server="127.0.0.1", dns_zone="example.com")
    assert len(result.records) == 2
    assert result.truncated is True


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
def test_bind_list_records_refused_axfr_maps_to_value_error() -> None:
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    client._keyring = {}
    client._keyname = dns.name.from_text("api-to-dns.")
    with (
        patch("src.plugins.bind.dns.query.xfr", side_effect=dns.xfr.TransferError(dns.rcode.REFUSED)),
        pytest.raises(ValueError, match="allow-transfer"),
    ):
        client.list_records(dns_server="127.0.0.1", dns_zone="example.com")


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
def test_bind_list_records_stops_iterating_after_limit() -> None:
    """Browse must close the AXFR stream after ``limit`` matches (no full-zone materialize)."""
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    yielded = {"n": 0}

    def limited_stream(*_a, **_k):
        for relative, rdataset in _fake_axfr_rrsets():
            yielded["n"] += 1
            yield relative, rdataset
            if yielded["n"] > 10:
                raise AssertionError("AXFR iterator continued after browse should have stopped")

    with patch.object(client, "_iter_axfr_rrsets", side_effect=limited_stream):
        result = client.list_records(limit=2, dns_server="127.0.0.1", dns_zone="example.com")
    assert len(result.records) == 2
    assert result.truncated is True
    # 2 kept + 1 extra scanned to learn truncation, then generator closed.
    assert yielded["n"] == 3


@patch.object(BindTsigDnsClient, "__init__", lambda self, *args, **kwargs: None)
def test_bind_list_records_concurrent_axfr_slot_busy() -> None:
    client = BindTsigDnsClient.__new__(BindTsigDnsClient)
    client._keyring = {}
    client._keyname = dns.name.from_text("api-to-dns.")
    assert bind_mod._AXFR_SLOTS.acquire(blocking=False)
    assert bind_mod._AXFR_SLOTS.acquire(blocking=False)
    try:
        with pytest.raises(RuntimeError, match="concurrent BIND zone transfers"):
            client.list_records(dns_server="127.0.0.1", dns_zone="example.com")
    finally:
        bind_mod._AXFR_SLOTS.release()
        bind_mod._AXFR_SLOTS.release()


class _CloudflareFake:
    """Records httpx requests and replays scripted responses for the Cloudflare API."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError(f"Unexpected Cloudflare request: {request.method} {request.url}")
        status, body = self._responses.pop(0)
        return httpx.Response(status_code=status, json=body)


def _cloudflare_client(responses, *, zone_id=None, proxied=False) -> tuple[CloudflareDnsClient, _CloudflareFake]:
    fake = _CloudflareFake(responses)
    transport = httpx.MockTransport(fake.handler)

    client = CloudflareDnsClient(
        api_token="test-token",
        zone_id=zone_id,
        proxied=proxied,
    )

    def factory():
        return httpx.Client(
            base_url=client._base_url,
            headers={
                "Authorization": f"Bearer {client._api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            transport=transport,
            timeout=5.0,
        )

    client._client = factory
    return client, fake


def _ok(result, *, success=True):
    return 200, {"success": success, "errors": [] if success else [{"message": "boom"}], "result": result}


def test_cloudflare_get_record_single_type() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok([{"id": "r1", "name": "www.example.com", "type": "A", "content": "192.0.2.10", "ttl": 300}]),
        ]
    )
    records = client.get_record(record_name="www", record_type="A", dns_zone="example.com")
    assert records == [DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])]

    auth_headers = {req.headers.get("authorization") for req in fake.requests}
    assert auth_headers == {"Bearer test-token"}

    zone_lookup = fake.requests[0]
    assert zone_lookup.url.path == "/client/v4/zones"
    assert zone_lookup.url.params["name"] == "example.com"

    list_call = fake.requests[1]
    assert list_call.url.path == "/client/v4/zones/z1/dns_records"
    assert list_call.url.params["name"] == "www.example.com"
    assert list_call.url.params["type"] == "A"


def test_cloudflare_list_records_pages_with_explicit_page_size_and_caps_rrsets() -> None:
    first_page = {
        "success": True,
        "errors": [],
        "result": [{"id": "r1", "name": "Api-One.example.com", "type": "A", "content": "192.0.2.10", "ttl": 300}],
        "result_info": {"page": 1, "per_page": 100, "total_pages": 2},
    }
    second_page = {
        "success": True,
        "errors": [],
        "result": [{"id": "r2", "name": "api-two.example.com", "type": "A", "content": "192.0.2.20", "ttl": 300}],
        "result_info": {"page": 2, "per_page": 100, "total_pages": 2},
    }
    client, fake = _cloudflare_client([(200, first_page), (200, second_page)], zone_id="zone-from-config")

    result = client.list_records(name_pattern="API-*", record_type="A", limit=1, dns_zone="example.com")

    assert result.truncated is True
    assert result.records == [DnsRecordInfo(record_name="Api-One", record_type="A", ttl=300, values=["192.0.2.10"])]
    assert [request.url.params["page"] for request in fake.requests] == ["1", "2"]
    assert {request.url.params["per_page"] for request in fake.requests} == {"100"}


def test_cloudflare_list_records_completes_open_rrset_across_page_after_cap() -> None:
    """Once the RRset cap is hit, keep paging to finish already-open multivalue sets."""
    first_page = {
        "success": True,
        "errors": [],
        "result": [
            {"id": "r1", "name": "api-one.example.com", "type": "A", "content": "192.0.2.10", "ttl": 300},
            {"id": "r2", "name": "api-two.example.com", "type": "A", "content": "192.0.2.20", "ttl": 300},
        ],
        "result_info": {"page": 1, "per_page": 100, "total_pages": 2},
    }
    second_page = {
        "success": True,
        "errors": [],
        "result": [
            {"id": "r3", "name": "api-one.example.com", "type": "A", "content": "192.0.2.11", "ttl": 300},
            {"id": "r4", "name": "api-three.example.com", "type": "A", "content": "192.0.2.30", "ttl": 300},
        ],
        "result_info": {"page": 2, "per_page": 100, "total_pages": 2},
    }
    client, fake = _cloudflare_client([(200, first_page), (200, second_page)], zone_id="zone-from-config")

    result = client.list_records(name_pattern="api-*", record_type="A", limit=1, dns_zone="example.com")

    assert result.truncated is True
    assert result.records == [
        DnsRecordInfo(record_name="api-one", record_type="A", ttl=300, values=["192.0.2.10", "192.0.2.11"])
    ]
    assert [request.url.params["page"] for request in fake.requests] == ["1", "2"]


def test_cloudflare_get_record_skips_zone_lookup_when_zone_id_set() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "r1", "name": "example.com", "type": "TXT", "content": '"hello"', "ttl": 600}]),
        ],
        zone_id="zone-from-config",
    )
    records = client.get_record(record_name="@", record_type="TXT", dns_zone="example.com")
    assert records == [DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])]
    assert fake.requests[0].url.path == "/client/v4/zones/zone-from-config/dns_records"


def test_cloudflare_create_txt_record_quotes_content() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok([]),
            _ok({"id": "new1"}),
        ]
    )
    payload = DnsRecordRequest(
        zone_name="example.com",
        record_type="TXT",
        record_name="_acme-challenge",
        ttl=120,
        values=["token-value"],
    )
    existed = client.create_or_update_record(payload, dns_zone="example.com")
    assert existed is False

    create_request = fake.requests[2]
    assert create_request.method == "POST"
    body = json.loads(create_request.content)
    assert body["type"] == "TXT"
    assert body["content"] == '"token-value"'


def test_cloudflare_update_txt_matches_existing_quoted_content() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok(
                [
                    {
                        "id": "r1",
                        "type": "TXT",
                        "name": "_acme-challenge.example.com",
                        "content": '"token-value"',
                        "ttl": 120,
                    }
                ]
            ),
            _ok({"id": "r1"}),
        ]
    )
    payload = DnsRecordRequest(
        zone_name="example.com",
        record_type="TXT",
        record_name="_acme-challenge",
        ttl=120,
        values=["token-value"],
    )
    existed = client.create_or_update_record(payload, dns_zone="example.com")
    assert existed is True

    put_request = fake.requests[2]
    assert put_request.method == "PUT"
    assert put_request.url.path == "/client/v4/zones/z1/dns_records/r1"
    assert json.loads(put_request.content)["content"] == '"token-value"'


def test_cloudflare_get_record_all_types_aggregates_only_present() -> None:
    # One response per LOOKUP_RECORD_TYPES entry after zone lookup.
    type_responses = {
        "A": _ok(
            [
                {"id": "a1", "type": "A", "name": "www.example.com", "content": "10.0.0.1", "ttl": 300},
                {"id": "a2", "type": "A", "name": "www.example.com", "content": "10.0.0.2", "ttl": 500},
            ]
        ),
        "CNAME": _ok(
            [
                {
                    "id": "c1",
                    "type": "CNAME",
                    "name": "www.example.com",
                    "content": "target.example.com.",
                    "ttl": 1000,
                }
            ]
        ),
    }
    from src.dns_record_types import LOOKUP_RECORD_TYPES

    responses = [_ok([{"id": "z1", "name": "example.com"}])]
    responses.extend(type_responses.get(rt, _ok([])) for rt in LOOKUP_RECORD_TYPES)
    client, fake = _cloudflare_client(responses)
    records = client.get_record(record_name="www", dns_zone="example.com")
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["10.0.0.1", "10.0.0.2"]),
        DnsRecordInfo(record_name="www", record_type="CNAME", ttl=1000, values=["target.example.com"]),
    ]


def test_cloudflare_get_record_not_found_returns_empty_list() -> None:
    from src.dns_record_types import LOOKUP_RECORD_TYPES

    responses = [_ok([{"id": "z1", "name": "example.com"}])]
    responses.extend(_ok([]) for _ in LOOKUP_RECORD_TYPES)
    client, _fake = _cloudflare_client(responses)
    assert client.get_record(record_name="missing", dns_zone="example.com") == []


def test_cloudflare_get_record_rejects_dns_server() -> None:
    client, _fake = _cloudflare_client([])
    with pytest.raises(ValueError, match="ignores per-server host settings"):
        client.get_record(record_name="@", dns_zone="example.com", dns_server="ns1.example.com")


def test_cloudflare_get_record_invalid_zone_raises_value_error() -> None:
    client, _fake = _cloudflare_client(
        [
            _ok([]),
        ]
    )
    with pytest.raises(ValueError, match="not found"):
        client.get_record(record_name="@", dns_zone="missing.example")


def test_cloudflare_create_record_posts_with_auth_and_proxied_flag() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok([]),
            _ok({"id": "new1"}),
        ],
        proxied=True,
    )
    payload = DnsRecordRequest(
        zone_name="example.com", record_type="A", record_name="www", ttl=300, values=["192.0.2.10"]
    )
    existed = client.create_or_update_record(payload, dns_zone="example.com")
    assert existed is False

    create_request = fake.requests[2]
    assert create_request.method == "POST"
    assert create_request.url.path == "/client/v4/zones/z1/dns_records"
    body = json.loads(create_request.content)
    assert body == {
        "type": "A",
        "name": "www.example.com",
        "content": "192.0.2.10",
        "ttl": 300,
        "proxied": True,
    }


def test_cloudflare_update_existing_record_uses_put_and_returns_true() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok([{"id": "r1", "type": "A", "name": "www.example.com", "content": "192.0.2.10", "ttl": 300}]),
            _ok({"id": "r1"}),
        ]
    )
    payload = DnsRecordRequest(
        zone_name="example.com", record_type="A", record_name="www", ttl=600, values=["192.0.2.10"]
    )
    existed = client.create_or_update_record(payload, dns_zone="example.com")
    assert existed is True

    put_request = fake.requests[2]
    assert put_request.method == "PUT"
    assert put_request.url.path == "/client/v4/zones/z1/dns_records/r1"
    assert json.loads(put_request.content)["ttl"] == 600


def test_cloudflare_multi_value_sync_deletes_stale_and_creates_missing() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok(
                [
                    {"id": "keep", "type": "A", "name": "www.example.com", "content": "192.0.2.10", "ttl": 300},
                    {"id": "drop", "type": "A", "name": "www.example.com", "content": "192.0.2.99", "ttl": 300},
                ]
            ),
            _ok({"id": "drop"}),
            _ok({"id": "keep"}),
            _ok({"id": "new"}),
        ]
    )
    payload = DnsRecordRequest(
        zone_name="example.com",
        record_type="A",
        record_name="www",
        ttl=300,
        values=["192.0.2.10", "192.0.2.20"],
    )
    existed = client.create_or_update_record(payload, dns_zone="example.com")
    assert existed is True

    methods = [(req.method, req.url.path) for req in fake.requests]
    assert methods == [
        ("GET", "/client/v4/zones"),
        ("GET", "/client/v4/zones/z1/dns_records"),
        ("DELETE", "/client/v4/zones/z1/dns_records/drop"),
        ("PUT", "/client/v4/zones/z1/dns_records/keep"),
        ("POST", "/client/v4/zones/z1/dns_records"),
    ]
    assert json.loads(fake.requests[4].content)["content"] == "192.0.2.20"


def test_cloudflare_delete_pseudo_payload_removes_all_matching_rows() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok(
                [
                    {"id": "r1", "type": "A", "name": "www.example.com", "content": "192.0.2.10", "ttl": 300},
                    {"id": "r2", "type": "A", "name": "www.example.com", "content": "192.0.2.20", "ttl": 300},
                ]
            ),
            _ok({"id": "r1"}),
            _ok({"id": "r2"}),
        ]
    )
    payload = DnsRecordRequest(zone_name="example.com", record_type="DELETE", record_name="www", values=["A"])
    existed = client.create_or_update_record(payload, dns_zone="example.com")
    assert existed is True
    methods = [(req.method, req.url.path) for req in fake.requests]
    assert methods[-2:] == [
        ("DELETE", "/client/v4/zones/z1/dns_records/r1"),
        ("DELETE", "/client/v4/zones/z1/dns_records/r2"),
    ]


def test_cloudflare_delete_missing_record_returns_false() -> None:
    client, _fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok([]),
        ]
    )
    payload = DnsRecordRequest(zone_name="example.com", record_type="DELETE", record_name="www", values=["A"])
    existed = client.create_or_update_record(payload, dns_zone="example.com")
    assert existed is False


def test_cloudflare_api_error_envelope_raises_runtime_error() -> None:
    client, _fake = _cloudflare_client(
        [
            (200, {"success": False, "errors": [{"message": "Invalid token"}], "result": None}),
        ]
    )
    with pytest.raises(RuntimeError, match="Invalid token"):
        client.get_record(record_name="@", dns_zone="example.com")


def test_cloudflare_missing_api_token_raises() -> None:
    with pytest.raises(ValueError, match="API token"):
        CloudflareDnsClient(api_token="")


def test_microsoft_https_validates_tls_by_default(monkeypatch) -> None:
    import sys
    import types

    captured = {}

    class FakeSession:
        def __init__(self, server, auth, **kwargs):
            captured["kwargs"] = kwargs

    stub = types.ModuleType("winrm")
    stub.Session = FakeSession
    monkeypatch.setitem(sys.modules, "winrm", stub)

    client = MicrosoftWinRmDnsClient("user", "pass", use_ssl=True, insecure_tls=False)
    client._session("dc.example.com")
    assert captured["kwargs"]["transport"] == "ssl"
    assert captured["kwargs"]["server_cert_validation"] == "validate"


def test_microsoft_https_can_opt_out_of_tls_validation(monkeypatch) -> None:
    import sys
    import types

    captured = {}

    class FakeSession:
        def __init__(self, server, auth, **kwargs):
            captured["kwargs"] = kwargs

    stub = types.ModuleType("winrm")
    stub.Session = FakeSession
    monkeypatch.setitem(sys.modules, "winrm", stub)

    client = MicrosoftWinRmDnsClient("user", "pass", use_ssl=True, insecure_tls=True)
    client._session("dc.example.com")
    assert captured["kwargs"]["server_cert_validation"] == "ignore"


def test_microsoft_create_client_defaults_insecure_tls_off() -> None:
    client = create_microsoft_client(
        {
            "dns_username": "user",
            "dns_password": "pass",
            "dns_winrm_ssl": "true",
        }
    )
    assert client.use_ssl is True
    assert client.insecure_tls is False

    opted = create_microsoft_client(
        {
            "dns_username": "user",
            "dns_password": "pass",
            "dns_winrm_ssl": "true",
            "dns_winrm_insecure_tls": "true",
        }
    )
    assert opted.insecure_tls is True


@patch.object(AzureDnsClient, "_get_existing_record_set")
def test_azure_mx_round_trip(mock_get) -> None:
    client = AzureDnsClient(
        tenant_id="t",
        client_id="c",
        client_secret="s",
        subscription_id="sub",
        resource_group="rg",
    )
    mgmt = MagicMock()
    client.DnsManagementClient = MagicMock(return_value=mgmt)
    captured: dict = {}

    def _record_set(**kwargs):
        captured.update(kwargs)
        return MagicMock(**kwargs)

    client.RecordSet = _record_set
    mock_get.return_value = None
    payload = DnsRecordRequest(
        zone_name="cfg",
        record_type="MX",
        record_name="@",
        ttl=300,
        values=["10 mail.example.com"],
    )
    client.create_or_update_record(payload, dns_zone="example.com")
    args = mgmt.record_sets.create_or_update.call_args
    assert args[0][3] == "MX"
    assert captured["mx_records"][0]["preference"] == 10
    assert captured["mx_records"][0]["exchange"] == "mail.example.com"

    existing = MagicMock()
    existing.ttl = 300
    existing.mx_records = [MagicMock(preference=10, exchange="mail.example.com.")]
    existing.a_records = None
    existing.aaaa_records = None
    existing.cname_record = None
    existing.txt_records = None
    existing.ns_records = None
    existing.srv_records = None
    existing.caa_records = None
    existing.ptr_records = None
    existing.soa_record = None
    mock_get.return_value = existing
    records = client.get_record(record_name="@", record_type="MX", dns_zone="example.com")
    assert records == [DnsRecordInfo(record_name="@", record_type="MX", ttl=300, values=["10 mail.example.com"])]


@patch("src.plugins.bind.dns.query.tcp")
@patch("src.plugins.bind.record_existed_before_update", return_value=False)
def test_bind_replace_uses_canonical_mx_text(mock_existed, mock_tcp) -> None:
    import base64

    response = MagicMock()
    response.rcode.return_value = 0
    mock_tcp.return_value = response
    client = BindTsigDnsClient(
        tsig_key_name="key.",
        tsig_secret_b64=base64.b64encode(b"01234567890123456789012345678901").decode(),
        tsig_algorithm="hmac-sha256",
    )
    payload = DnsRecordRequest(
        zone_name="cfg",
        record_type="MX",
        record_name="@",
        ttl=300,
        values=["10 mail.example.com"],
    )
    existed = client.create_or_update_record(payload, dns_server="127.0.0.1", dns_zone="example.com")
    assert existed is False
    update = mock_tcp.call_args[0][0]
    assert "mail.example.com" in update.to_text()


def test_microsoft_add_record_lines_escape_mx() -> None:
    lines = MicrosoftWinRmDnsClient._add_record_lines("MX", ["10 mail.example.com"])
    assert any("Add-DnsServerResourceRecordMX" in line for line in lines)
    assert any("MailExchange 'mail.example.com'" in line for line in lines)
    assert any("-Preference 10" in line for line in lines)
