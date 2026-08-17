"""Canonical DNS DTOs live in schemas.dns, not ORM models."""

import src.models as models
import src.schemas.dns as dns_schemas


def test_models_does_not_reexport_dns_schemas() -> None:
    for name in dns_schemas.__all__:
        assert not hasattr(models, name)
