"""Unit tests for the shared DNS mutation core."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.dns_mutation import (
    PatchMergeError,
    apply_patch_mutation,
    apply_rrset_mutation,
    merge_patch,
    prepare_mutation,
)
from src.schemas.dns import DnsRecordInfo


def test_prepare_mutation_normalizes_and_defaults_ttl() -> None:
    prepared = prepare_mutation(
        record_name=" www ",
        record_type="a",
        ttl=None,
        values=["192.0.2.10"],
        dns_zone="example.com",
    )
    assert prepared.record_name == "www"
    assert prepared.record_type == "A"
    assert prepared.ttl == 300
    assert prepared.values == ["192.0.2.10"]


def test_prepare_mutation_rejects_apex_ns() -> None:
    with pytest.raises(ValueError, match="Apex NS"):
        prepare_mutation(
            record_name="@",
            record_type="NS",
            values=["ns1.example.com"],
            dns_zone="example.com",
        )
    with pytest.raises(ValueError, match="Apex NS"):
        prepare_mutation(
            record_name="example.com",
            record_type="NS",
            values=["ns1.example.com"],
            dns_zone="example.com",
        )


def test_prepare_mutation_rejects_ptr_outside_reverse_zone() -> None:
    with pytest.raises(ValueError, match="reverse zones"):
        prepare_mutation(
            record_name="1",
            record_type="PTR",
            values=["host.example.com"],
            dns_zone="example.com",
        )
    prepared = prepare_mutation(
        record_name="1",
        record_type="PTR",
        values=["host.example.com"],
        dns_zone="2.0.192.in-addr.arpa",
    )
    assert prepared.record_type == "PTR"


def test_prepare_mutation_rejects_soa() -> None:
    with pytest.raises(ValueError, match="record_type must be one of"):
        prepare_mutation(
            record_name="@",
            record_type="SOA",
            values=["ns1.example.com hostmaster.example.com 1 3600 600 86400 3600"],
            dns_zone="example.com",
        )


def test_merge_patch_combinations() -> None:
    existing = DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])
    assert merge_patch(existing, 600, None) == (600, ["192.0.2.1"])
    assert merge_patch(existing, None, ["192.0.2.9"]) == (300, ["192.0.2.9"])
    assert merge_patch(existing, 900, ["192.0.2.8"]) == (900, ["192.0.2.8"])


def test_merge_patch_requires_existing_ttl_and_values() -> None:
    with pytest.raises(PatchMergeError, match="PATCH merge"):
        merge_patch(SimpleNamespace(ttl=None, values=["192.0.2.1"]), 600, None)
    with pytest.raises(PatchMergeError, match="PATCH merge"):
        merge_patch(SimpleNamespace(ttl=300, values=[]), None, ["192.0.2.1"])


def test_apply_patch_mutation_merges_and_replaces() -> None:
    fake = MagicMock()
    fake.get_record.return_value = [DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])]
    outcome = apply_patch_mutation(
        fake,
        settings={"dns_zone": "example.com"},
        zone_name="example.com",
        record_name="www",
        record_type="A",
        patch_ttl=600,
        patch_values=None,
    )
    assert outcome.status == "success"
    assert outcome.action == "updated"
    assert outcome.values == ["192.0.2.1"]
    internal = fake.create_or_update_record.call_args.args[0]
    assert internal.ttl == 600
    assert internal.values == ["192.0.2.1"]


def test_apply_patch_mutation_missing_is_404() -> None:
    fake = MagicMock()
    fake.get_record.return_value = []
    outcome = apply_patch_mutation(
        fake,
        settings={"dns_zone": "example.com"},
        zone_name="example.com",
        record_name="www",
        record_type="A",
        patch_ttl=600,
        patch_values=None,
    )
    assert outcome.http_status == 404
    assert outcome.action == "not_found"
    fake.create_or_update_record.assert_not_called()


def test_apply_rrset_mutation_create_conflict_is_409() -> None:
    fake = MagicMock()
    fake.get_record.return_value = [DnsRecordInfo(record_name="www", record_type="A", ttl=300, values=["192.0.2.1"])]
    outcome = apply_rrset_mutation(
        fake,
        settings={"dns_zone": "example.com"},
        zone_name="example.com",
        record_name="www",
        record_type="A",
        ttl=300,
        values=["192.0.2.2"],
        mode="create",
    )
    assert outcome.http_status == 409
    fake.create_or_update_record.assert_not_called()
