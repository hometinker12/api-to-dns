import pytest
from fastapi.testclient import TestClient

from src.app import app

client = TestClient(app)

@pytest.mark.parametrize(
    "payload, expected_status",
    [
        (
            {
                "subscription_id": "00000000-0000-0000-0000-000000000000",
                "resource_group": "test-rg",
                "zone_name": "example.com",
                "record_type": "A",
                "record_name": "www",
                "ttl": 300,
                "values": ["192.0.2.1"],
            },
            500,
        ),
    ],
)
def test_upsert_dns_record_validation(payload, expected_status):
    response = client.post("/dns-record", json=payload)
    assert response.status_code == expected_status
