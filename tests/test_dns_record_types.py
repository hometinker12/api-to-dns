"""Tests for canonical DNS record type validation."""

import pytest

from src.dns_record_types import (
    LOOKUP_RECORD_TYPES,
    guard_mutation_allowed,
    normalize_lookup_record_type,
    normalize_record_value,
    normalize_record_values,
    parse_caa,
    parse_mx,
    parse_srv,
    validate_ttl,
)


def test_normalize_lookup_accepts_expanded_types() -> None:
    assert normalize_lookup_record_type("mx") == "MX"
    assert normalize_lookup_record_type("SOA") == "SOA"
    assert normalize_lookup_record_type(None) is None


def test_normalize_lookup_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Record type must be one of"):
        normalize_lookup_record_type("SPF")


def test_validate_ttl_bounds() -> None:
    assert validate_ttl(None) == 300
    assert validate_ttl(0) == 0
    with pytest.raises(ValueError):
        validate_ttl(-1)
    with pytest.raises(ValueError):
        validate_ttl(2_147_483_648)


def test_normalize_a_and_aaaa() -> None:
    assert normalize_record_value("A", "192.0.2.10") == "192.0.2.10"
    assert normalize_record_value("AAAA", "2001:db8::1") == "2001:db8::1"
    with pytest.raises(ValueError):
        normalize_record_value("A", "2001:db8::1")
    with pytest.raises(ValueError):
        normalize_record_value("AAAA", "192.0.2.10")


def test_parse_structured_values() -> None:
    assert parse_mx("10 mail.example.com") == (10, "mail.example.com")
    assert parse_srv("1 2 443 target.example.com") == (1, 2, 443, "target.example.com")
    assert parse_caa('0 issue "letsencrypt.org"') == (0, "issue", '"letsencrypt.org"')
    with pytest.raises(ValueError):
        parse_mx("mail.example.com")
    with pytest.raises(ValueError):
        parse_srv("1 2 target")


def test_cname_requires_single_value() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        normalize_record_values("CNAME", ["a.example.com", "b.example.com"])


def test_soa_and_apex_ns_guards() -> None:
    with pytest.raises(ValueError, match="view-only"):
        guard_mutation_allowed(record_name="@", record_type="SOA")
    with pytest.raises(ValueError, match="Apex NS"):
        guard_mutation_allowed(record_name="@", record_type="NS")
    with pytest.raises(ValueError, match="Apex NS"):
        guard_mutation_allowed(record_name="example.com", record_type="NS", dns_zone="example.com")
    with pytest.raises(ValueError, match="Apex NS"):
        guard_mutation_allowed(record_name="Example.COM.", record_type="NS", dns_zone="example.com")
    # Delegation NS under a label remains allowed.
    guard_mutation_allowed(record_name="sub", record_type="NS", dns_zone="example.com")
    with pytest.raises(ValueError, match="reverse zones"):
        guard_mutation_allowed(record_name="1", record_type="PTR", dns_zone="example.com")
    guard_mutation_allowed(record_name="1", record_type="PTR", dns_zone="2.0.192.in-addr.arpa")


def test_lookup_type_order() -> None:
    assert LOOKUP_RECORD_TYPES[0] == "A"
    assert "SOA" in LOOKUP_RECORD_TYPES
    assert LOOKUP_RECORD_TYPES.index("TXT") < LOOKUP_RECORD_TYPES.index("MX")
