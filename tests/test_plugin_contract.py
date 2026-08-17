"""Structural contract tests for discovered DNS provider plugins."""

from __future__ import annotations

import base64
import inspect

import pytest

from src.dns_record_types import LOOKUP_RECORD_TYPES, normalize_record_values
from src.plugins import discover_plugins
from src.plugins.utils import dns_relative_name

EXPECTED_PLUGIN_KEYS = {"azure", "bind", "cloudflare", "microsoft"}
REQUIRED_CLIENT_METHODS = ("get_record", "list_records", "create_or_update_record")

_DUMMY_SETTINGS: dict[str, dict[str, str | None]] = {
    "azure": {
        "azure_tenant_id": "00000000-0000-0000-0000-000000000001",
        "azure_client_id": "00000000-0000-0000-0000-000000000002",
        "azure_client_secret": "dummy-secret",
        "azure_subscription_id": "00000000-0000-0000-0000-000000000003",
        "azure_resource_group": "rg-dummy",
    },
    "bind": {
        "dns_username": "test-key.",
        "dns_password": base64.b64encode(b"0123456789abcdef").decode("ascii"),
        "dns_tsig_algorithm": "hmac-sha256",
    },
    "cloudflare": {
        "cloudflare_api_token": "dummy-token",
    },
    "microsoft": {
        "dns_username": r"DOMAIN\user",
        "dns_password": "dummy-password",
    },
}

_LOOKUP_SAMPLES: dict[str, list[str]] = {
    "A": ["192.0.2.10"],
    "AAAA": ["2001:db8::1"],
    "CNAME": ["target.example.com"],
    "TXT": ["hello world"],
    "MX": ["10 mail.example.com"],
    "NS": ["ns1.example.com"],
    "SRV": ["1 2 443 target.example.com"],
    "CAA": ["0 issue letsencrypt.org"],
    "PTR": ["host.example.com"],
    "SOA": ["ns1.example.com hostmaster.example.com 1 3600 600 86400 3600"],
}


def test_discover_plugins_exposes_known_providers() -> None:
    assert set(discover_plugins()) == EXPECTED_PLUGIN_KEYS


@pytest.mark.parametrize("plugin_key", sorted(EXPECTED_PLUGIN_KEYS))
def test_discovered_plugin_client_exposes_required_methods(plugin_key: str) -> None:
    plugin = discover_plugins()[plugin_key]
    client = plugin.create_client(_DUMMY_SETTINGS[plugin_key])
    for name in REQUIRED_CLIENT_METHODS:
        method = getattr(client, name, None)
        assert callable(method), f"{plugin_key} client missing {name}"
        assert not inspect.isbuiltin(method)


def test_dns_relative_name_maps_apex_fqdn_to_at() -> None:
    assert dns_relative_name("example.com", "example.com") == "@"
    assert dns_relative_name("example.com", "Example.COM.") == "@"
    assert dns_relative_name("example.com", "@") == "@"
    assert dns_relative_name("example.com", "www.example.com") == "www"
    assert dns_relative_name("example.com", "www") == "www"


@pytest.mark.parametrize("record_type", LOOKUP_RECORD_TYPES)
def test_lookup_record_value_normalization_round_trip(record_type: str) -> None:
    sample = _LOOKUP_SAMPLES[record_type]
    normalized = normalize_record_values(record_type, sample)
    assert normalize_record_values(record_type, normalized) == normalized
