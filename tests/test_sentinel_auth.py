"""
Behavioral Contract for sentinel_auth.py

Valid Input:
- get_access_token: Returns a valid JWT string for the requested Azure scope.
- get_auth_headers: Returns {"Authorization": "Bearer <token>", "Content-Type": "application/json"}

Failure Modes:
- Azure Identity Error (e.g. no managed identity or CLI login): Raises DefaultAzureCredential exception.

Concurrency Invariants:
- Token caching uses `threading.Lock()` to prevent concurrent identical token requests, ensuring thread safety if used concurrently within the same process.
"""

import time

import pytest

from sentinel_auth import (_cached_tokens, _get_credential, get_access_token,
                           get_auth_headers)


def test_get_auth_headers_format(monkeypatch):
    """Asserts auth headers are correctly formatted."""

    def mock_get_token(*args, **kwargs):
        return "mock_token_value"

    monkeypatch.setattr("sentinel_auth.get_access_token", mock_get_token)

    headers = get_auth_headers()
    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer mock_token_value"
    assert headers["Content-Type"] == "application/json"


def test_get_access_token_caching(monkeypatch):
    """Asserts the token cache is utilized correctly to avoid redundant network calls."""

    class MockToken:
        def __init__(self, token, expires_on):
            self.token = token
            self.expires_on = expires_on

    call_count = 0

    def mock_get_token(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return MockToken("fresh_token", time.time() + 3600)

    from unittest.mock import MagicMock

    mock_credential = MagicMock()
    mock_credential.get_token = mock_get_token
    monkeypatch.setattr("sentinel_auth._get_credential", lambda: mock_credential)

    # Clear cache before test
    _cached_tokens.clear()

    # First call should hit the credential's get_token
    token1 = get_access_token("mock_scope")
    assert token1 == "fresh_token"
    assert call_count == 1

    # Second call should use cache
    token2 = get_access_token("mock_scope")
    assert token2 == "fresh_token"
    assert call_count == 1
