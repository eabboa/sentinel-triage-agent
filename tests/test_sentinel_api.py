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
from unittest.mock import patch, AsyncMock
from requests.exceptions import HTTPError
from sentinel_api import (
    list_incidents,
    get_incident,
    list_incident_alerts,
    update_incident_status,
    post_incident_comment,
    resolve_mde_machine_id,
    isolate_mde_device,
    revoke_entra_sessions,
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


# ── Existing tests ────────────────────────────────────────────────────────────

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


# ── update_incident_status: no etag branch ───────────────────────────────────

@responses.activate
def test_update_incident_status_no_etag():
    """Asserts update works when incident has no etag (If-Match not set)."""
    base = _get_base()
    responses.add(
        responses.GET,
        f"{base}/incidents/123",
        json={"properties": {"status": "New"}},  # No etag field
        status=200,
    )
    responses.add(
        responses.PUT,
        f"{base}/incidents/123",
        json={"properties": {"status": "Active"}},
        status=200,
    )

    result = update_incident_status("123", "Active")
    assert result["properties"]["status"] == "Active"
    # Verify If-Match was NOT set in the PUT request
    put_request = responses.calls[1].request
    assert "If-Match" not in put_request.headers


# ── update_incident_status: classification reason mapping ────────────────────

@responses.activate
def test_update_incident_status_classification_reasons():
    """Asserts classificationReason is correctly mapped for each classification."""
    base = _get_base()
    for classification, expected_reason in [
        ("FalsePositive", "IncorrectAlertLogic"),
        ("BenignPositive", "SuspiciousButExpected"),
        ("Undetermined", "InaccurateData"),
    ]:
        responses.reset()
        import sentinel_api
        sentinel_api._BASE = None

        responses.add(
            responses.GET,
            f"{_get_base()}/incidents/123",
            json={"properties": {"status": "New"}, "etag": 'W/"e"'},
            status=200,
        )
        responses.add(
            responses.PUT,
            f"{_get_base()}/incidents/123",
            json={"properties": {"status": "Closed", "classification": classification}},
            status=200,
        )

        result = update_incident_status("123", "Closed", classification)
        # Verify the PUT body contained the correct classificationReason
        import json
        put_body = json.loads(responses.calls[-1].request.body)
        assert put_body["properties"]["classificationReason"] == expected_reason


# ── list_incident_alerts ─────────────────────────────────────────────────────

@responses.activate
def test_list_incident_alerts_success():
    """Asserts alerts are fetched via POST and parsed correctly."""
    base = _get_base()
    responses.add(
        responses.POST,
        f"{base}/incidents/123/alerts",
        json={"value": [{"id": "alert-1"}, {"id": "alert-2"}]},
        status=200,
    )

    result = list_incident_alerts("123")
    assert len(result) == 2
    assert result[0]["id"] == "alert-1"


# ── post_incident_comment ────────────────────────────────────────────────────

@responses.activate
def test_post_incident_comment_success():
    """Asserts comment is posted with UUID-based URL."""
    base = _get_base()
    # Match any comment URL (UUID is generated)
    import re
    responses.add(
        responses.PUT,
        re.compile(rf"{re.escape(base)}/incidents/123/comments/.*"),
        json={"id": "comment-123"},
        status=200,
    )

    result = post_incident_comment("123", "Test comment")
    assert result["id"] == "comment-123"


# ── resolve_mde_machine_id ───────────────────────────────────────────────────

@responses.activate
@pytest.mark.asyncio
async def test_resolve_mde_machine_id_found():
    """Asserts machine ID is returned when device is found."""
    responses.add(
        responses.GET,
        "https://api.securitycenter.microsoft.com/api/machines",
        json={"value": [{"id": "machine-abc123"}]},
        status=200,
    )

    with patch("sentinel_api.get_mde_token", return_value="mock-token"):
        result = await resolve_mde_machine_id("workstation-1")
        assert result == "machine-abc123"


@responses.activate
@pytest.mark.asyncio
async def test_resolve_mde_machine_id_not_found():
    """Asserts None is returned when no device is found."""
    responses.add(
        responses.GET,
        "https://api.securitycenter.microsoft.com/api/machines",
        json={"value": []},
        status=200,
    )

    with patch("sentinel_api.get_mde_token", return_value="mock-token"):
        result = await resolve_mde_machine_id("unknown-host")
        assert result is None


# ── isolate_mde_device ───────────────────────────────────────────────────────

@responses.activate
@pytest.mark.asyncio
async def test_isolate_mde_device_success():
    """Asserts valid machine ID with response text returns JSON."""
    machine_id = "a" * 40  # Valid 40-char hex
    responses.add(
        responses.POST,
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        json={"status": "Isolated"},
        status=200,
    )

    with patch("sentinel_api.get_mde_token", return_value="mock-token"):
        result = await isolate_mde_device(machine_id)
        assert result["status"] == "Isolated"


@responses.activate
@pytest.mark.asyncio
async def test_isolate_mde_device_empty_response():
    """Asserts empty response body returns empty dict."""
    machine_id = "b" * 40
    responses.add(
        responses.POST,
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        body="",
        status=200,
    )

    with patch("sentinel_api.get_mde_token", return_value="mock-token"):
        result = await isolate_mde_device(machine_id)
        assert result == {}


@pytest.mark.asyncio
async def test_isolate_mde_device_invalid_id():
    """Asserts invalid machine ID format raises ValueError."""
    with pytest.raises(ValueError, match="Invalid MDE machine ID format"):
        await isolate_mde_device("not-a-valid-hex-id")


# ── revoke_entra_sessions ───────────────────────────────────────────────────

@responses.activate
@pytest.mark.asyncio
async def test_revoke_entra_sessions_success():
    """Asserts session revocation returns JSON response."""
    user_id = "user-guid-123"
    responses.add(
        responses.POST,
        f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions",
        json={"value": True},
        status=200,
    )

    with patch("sentinel_api.get_graph_token", return_value="mock-token"):
        result = await revoke_entra_sessions(user_id)
        assert result["value"] is True


@responses.activate
@pytest.mark.asyncio
async def test_revoke_entra_sessions_empty_response():
    """Asserts empty response body returns empty dict."""
    user_id = "user-guid-456"
    responses.add(
        responses.POST,
        f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions",
        body="",
        status=200,
    )

    with patch("sentinel_api.get_graph_token", return_value="mock-token"):
        result = await revoke_entra_sessions(user_id)
        assert result == {}
