"""
Behavioral Contract for sentinel_api.py

Valid Input:
- list_incidents: Returns a list of dicts containing Sentinel incidents.
- get_incident: Returns a single dict representing the full incident object.
- list_incident_alerts: Returns a list of dicts for associated alerts.
- post_incident_comment: Posts a comment securely using a UUID to ensure idempotency. Returns dict.
- update_incident_status: Updates incident status and classification. Returns dict.

Failure Modes:
- 401 Unauthorized: Raises requests.exceptions.HTTPError (not retried).
- 412 Precondition Failed (ETag conflict): ConcurrencyConflictError is raised. `update_incident_status` automatically retries up to 3 times by re-fetching the latest ETag.
- Network Timeout / Transient (429, 503, 504): `TransientHTTPError` triggers `tenacity` retries.

Concurrency Invariants:
- `post_incident_comment` generates a local UUID to ensure that if a request is retried, duplicate comments are not created.
- `update_incident_status` handles ETag conflicts by refetching and applying changes, ensuring changes aren't silently dropped or overwritten.
"""

import pytest
import responses
from requests.exceptions import HTTPError
from sentinel_api import (
    list_incidents,
    get_incident,
    update_incident_status,
    post_incident_comment,
    ConcurrencyConflictError,
    TransientHTTPError,
    _get_base,
    API_VERSION,
)


@pytest.fixture(autouse=True)
def _reset_base_cache():
    """Reset the lazy _BASE cache between tests so env var changes take effect."""
    import sentinel_api
    sentinel_api._BASE = None
    yield
    sentinel_api._BASE = None


@responses.activate
def test_list_incidents_success():
    """Asserts successful response correctly parses into a list of dictionaries."""
    base = _get_base()
    responses.add(
        responses.GET,
        f"{base}/incidents",
        json={"value": [{"name": "inc1"}]},
        status=200,
    )
    result = list_incidents()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["name"] == "inc1"


def test_list_incidents_invalid_status():
    """Asserts ValueError is raised for invalid status filters."""
    with pytest.raises(ValueError, match="Invalid status_filter"):
        list_incidents(status_filter="Invalid")


@responses.activate
def test_update_incident_status_success():
    """Asserts status and classification update correctly without exceptions."""
    base = _get_base()
    responses.add(
        responses.GET,
        f"{base}/incidents/123",
        json={"properties": {"status": "New"}, "etag": 'W/"mock-etag"'},
        status=200,
    )
    responses.add(
        responses.PUT,
        f"{base}/incidents/123",
        json={"properties": {"status": "Closed", "classification": "TruePositive"}},
        status=200,
    )

    result = update_incident_status("123", "Closed", "TruePositive")
    assert result["properties"]["status"] == "Closed"
    assert result["properties"]["classification"] == "TruePositive"


@responses.activate
def test_update_incident_status_etag_conflict_retry():
    """Asserts a 412 ETag conflict is caught and triggers retry logic.

    This is critical in a SOC context because multiple analysts or automation
    tools may be updating the same incident concurrently. Without ETag retry,
    status changes would be silently dropped.
    """
    base = _get_base()
    # First fetch
    responses.add(
        responses.GET,
        f"{base}/incidents/123",
        json={"properties": {"status": "New"}, "etag": 'W/"old-etag"'},
        status=200,
    )
    # First PUT fails with 412
    responses.add(responses.PUT, f"{base}/incidents/123", status=412)
    # Second fetch gets new ETag
    responses.add(
        responses.GET,
        f"{base}/incidents/123",
        json={"properties": {"status": "New"}, "etag": 'W/"new-etag"'},
        status=200,
    )
    # Second PUT succeeds
    responses.add(
        responses.PUT,
        f"{base}/incidents/123",
        json={"properties": {"status": "Closed"}},
        status=200,
    )

    result = update_incident_status("123", "Closed")
    assert result["properties"]["status"] == "Closed"


@responses.activate
def test_transient_http_error_retry():
    """Asserts transient HTTP errors (e.g. 503) are retried via tenacity."""
    base = _get_base()
    responses.add(responses.GET, f"{base}/incidents/123", status=503)
    responses.add(
        responses.GET,
        f"{base}/incidents/123",
        json={"properties": {"status": "New"}},
        status=200,
    )

    result = get_incident("123")
    assert result["properties"]["status"] == "New"
    assert len(responses.calls) == 2


def test_get_base_missing_env_vars(monkeypatch):
    """Asserts EnvironmentError is raised when required env vars are missing.

    Validates that the deferred config validation still fires on first API call,
    not silently proceeding with None values in the URL.
    """
    import sentinel_api
    sentinel_api._BASE = None
    monkeypatch.delenv("SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("RESOURCE_GROUP", raising=False)
    monkeypatch.delenv("WORKSPACE_NAME", raising=False)

    with pytest.raises(EnvironmentError, match="Missing required environment variables"):
        sentinel_api._get_base()
