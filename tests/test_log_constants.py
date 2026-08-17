"""Canonical log constants and one-release models re-exports."""

import src.log_constants as log_constants
import src.models as models


def test_log_level_order_and_values() -> None:
    assert log_constants.LOG_LEVEL_VALUES == (
        log_constants.LOG_LEVEL_VERBOSE,
        log_constants.LOG_LEVEL_INFORMATIONAL,
        log_constants.LOG_LEVEL_WARNING,
        log_constants.LOG_LEVEL_ERROR,
    )
    assert log_constants.LOG_LEVEL_ORDER == {
        log_constants.LOG_LEVEL_VERBOSE: 0,
        log_constants.LOG_LEVEL_INFORMATIONAL: 10,
        log_constants.LOG_LEVEL_WARNING: 20,
        log_constants.LOG_LEVEL_ERROR: 30,
    }


def test_security_event_prefixes_unchanged() -> None:
    assert log_constants.SECURITY_EVENT_PREFIXES == ("auth.", "api_key.", "user.")


def test_models_reexports_match_log_constants() -> None:
    for name in log_constants.__all__:
        assert getattr(models, name) is getattr(log_constants, name)
