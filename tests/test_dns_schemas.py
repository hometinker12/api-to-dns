"""Canonical DNS DTOs and one-release models re-exports."""

import src.models as models
import src.schemas.dns as dns_schemas


def test_models_reexports_match_dns_schemas() -> None:
    for name in dns_schemas.__all__:
        assert getattr(models, name) is getattr(dns_schemas, name)
