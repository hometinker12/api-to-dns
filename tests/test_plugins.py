"""Unit tests for DNS provider plugin get_record implementations."""

import json
from unittest.mock import MagicMock, patch

import dns.rdataclass
import dns.rdata
import dns.rdataset
import dns.rrset
import httpx
import pytest

from src.models import DnsRecordInfo, DnsRecordRequest
from src.plugins.azure import AzureDnsClient
from src.plugins.bind import BindTsigDnsClient
from src.plugins.cloudflare import CloudflareDnsClient
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
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.10"])
    ]

    auth_headers = {req.headers.get("authorization") for req in fake.requests}
    assert auth_headers == {"Bearer test-token"}

    zone_lookup = fake.requests[0]
    assert zone_lookup.url.path == "/client/v4/zones"
    assert zone_lookup.url.params["name"] == "example.com"

    list_call = fake.requests[1]
    assert list_call.url.path == "/client/v4/zones/z1/dns_records"
    assert list_call.url.params["name"] == "www.example.com"
    assert list_call.url.params["type"] == "A"


def test_cloudflare_get_record_skips_zone_lookup_when_zone_id_set() -> None:
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "r1", "name": "example.com", "type": "TXT", "content": '"hello"', "ttl": 600}]),
        ],
        zone_id="zone-from-config",
    )
    records = client.get_record(record_name="@", record_type="TXT", dns_zone="example.com")
    assert records == [
        DnsRecordInfo(record_name="@", record_type="TXT", ttl=600, values=["hello"])
    ]
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
            _ok([
                {
                    "id": "r1",
                    "type": "TXT",
                    "name": "_acme-challenge.example.com",
                    "content": '"token-value"',
                    "ttl": 120,
                }
            ]),
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
    client, fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok([
                {"id": "a1", "type": "A", "name": "www.example.com", "content": "10.0.0.1", "ttl": 300},
                {"id": "a2", "type": "A", "name": "www.example.com", "content": "10.0.0.2", "ttl": 500},
            ]),
            _ok([]),
            _ok([{"id": "c1", "type": "CNAME", "name": "www.example.com", "content": "target.example.com.", "ttl": 1000}]),
            _ok([]),
        ]
    )
    records = client.get_record(record_name="www", dns_zone="example.com")
    assert records == [
        DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["10.0.0.1", "10.0.0.2"]),
        DnsRecordInfo(record_name="www", record_type="CNAME", ttl=1000, values=["target.example.com"]),
    ]


def test_cloudflare_get_record_not_found_returns_empty_list() -> None:
    client, _fake = _cloudflare_client(
        [
            _ok([{"id": "z1", "name": "example.com"}]),
            _ok([]),
            _ok([]),
            _ok([]),
            _ok([]),
        ]
    )
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
            _ok([
                {"id": "keep", "type": "A", "name": "www.example.com", "content": "192.0.2.10", "ttl": 300},
                {"id": "drop", "type": "A", "name": "www.example.com", "content": "192.0.2.99", "ttl": 300},
            ]),
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
            _ok([
                {"id": "r1", "type": "A", "name": "www.example.com", "content": "192.0.2.10", "ttl": 300},
                {"id": "r2", "type": "A", "name": "www.example.com", "content": "192.0.2.20", "ttl": 300},
            ]),
            _ok({"id": "r1"}),
            _ok({"id": "r2"}),
        ]
    )
    payload = DnsRecordRequest(
        zone_name="example.com", record_type="DELETE", record_name="www", values=["A"]
    )
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
    payload = DnsRecordRequest(
        zone_name="example.com", record_type="DELETE", record_name="www", values=["A"]
    )
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
