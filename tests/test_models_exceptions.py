"""
Behavioral Contract for models/exceptions.py

Asserts all custom exception classes store raw_data on the instance.
"""

from models.exceptions import (
    AbuseIPDBResponseValidationError,
    LLMOutputValidationError,
    SentinelAlertValidationError,
    VirusTotalResponseValidationError,
)


def test_custom_exceptions_store_raw_data():
    """Each custom exception preserves the raw payload for debugging."""
    raw = {"key": "value"}

    for exc_cls in [
        SentinelAlertValidationError,
        VirusTotalResponseValidationError,
        AbuseIPDBResponseValidationError,
        LLMOutputValidationError,
    ]:
        exc = exc_cls(message="test error", raw_data=raw)
        assert str(exc) == "test error"
        assert exc.raw_data is raw
