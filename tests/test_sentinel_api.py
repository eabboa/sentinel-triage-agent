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

import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import responses
from requests.exceptions import HTTPError

from sentinel_api import (
    API_VERSION,
    ConcurrencyConflictError,
    TransientHTTPError,
    _get_base,
    get_incident,
    isolate_mde_device,
    list_incident_alerts,
    list_incidents,
    post_incident_comment,
    resolve_mde_machine_id,
    revoke_entra_sessions,
    update_incident_status,
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
    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
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

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
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

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
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

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
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

    with pytest.raises(
        EnvironmentError, match="Missing required environment variables"
    ):
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

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
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

        with patch(
            "sentinel_api.get_auth_headers",
            return_value={"Authorization": "Bearer mock"},
        ):
            result = update_incident_status("123", "Closed", classification)
        # Verify the PUT body contained the correct classificationReason
        import json

        body = responses.calls[-1].request.body
        assert body is not None
        put_body = json.loads(body)
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

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
        result = list_incident_alerts("123")
    assert len(result) == 2
    assert result[0]["id"] == "alert-1"


# ── pagination (nextLink) ────────────────────────────────────────────────────


@responses.activate
def test_list_incident_alerts_follows_next_link():
    """Asserts alerts spanning multiple pages are all accumulated via nextLink.

    The first page (a POST) carries a nextLink; the continuation must be a plain
    GET of that URL. Without pagination, a high-volume incident would silently
    yield only its first page of alerts, starving IOC extraction.
    """
    base = _get_base()
    next_url = "https://management.azure.com/next-page-of-alerts"
    # Page 1: POST, returns a nextLink.
    responses.add(
        responses.POST,
        f"{base}/incidents/123/alerts",
        json={"value": [{"id": "alert-1"}], "nextLink": next_url},
        status=200,
    )
    # Page 2: continuation must be a GET of the nextLink URL, no further nextLink.
    responses.add(
        responses.GET,
        next_url,
        json={"value": [{"id": "alert-2"}, {"id": "alert-3"}]},
        status=200,
    )

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
        result = list_incident_alerts("123")

    assert [a["id"] for a in result] == ["alert-1", "alert-2", "alert-3"]
    # First call POST to the alerts endpoint, continuation GET to the nextLink.
    assert responses.calls[0].request.method == "POST"
    assert responses.calls[1].request.method == "GET"
    assert responses.calls[1].request.url == next_url


@responses.activate
def test_list_incidents_respects_max_results_across_pages():
    """Asserts max_results caps the total even when Azure paginates."""
    base = _get_base()
    next_url = "https://management.azure.com/next-page-of-incidents"
    responses.add(
        responses.GET,
        f"{base}/incidents",
        json={"value": [{"name": "inc1"}, {"name": "inc2"}], "nextLink": next_url},
        status=200,
    )
    responses.add(
        responses.GET,
        next_url,
        json={"value": [{"name": "inc3"}, {"name": "inc4"}]},
        status=200,
    )

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
        result = list_incidents(max_results=3)

    # All pages fetched, but the documented max_results contract is enforced.
    assert len(result) == 3
    assert [i["name"] for i in result] == ["inc1", "inc2", "inc3"]


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

    with patch(
        "sentinel_api.get_auth_headers", return_value={"Authorization": "Bearer mock"}
    ):
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


# ── Concurrency model: blocking I/O is offloaded to a worker thread ───────────


@pytest.mark.asyncio
async def test_async_helpers_offload_blocking_request_to_worker_thread():
    """The async containment/escalation helpers run their blocking `requests`
    I/O via asyncio.to_thread, so awaiting them genuinely yields the event loop
    instead of freezing it (main.py runs up to 3 incidents concurrently).

    Verify the synchronous _request executes off the event-loop thread. This
    fails if anyone reverts to a plain blocking `_request(...)` call.
    """
    loop_thread_id = threading.get_ident()
    captured: dict[str, int] = {}

    def fake_request(method, url, *, headers=None, params=None, json=None):
        captured["thread_id"] = threading.get_ident()
        return SimpleNamespace(json=lambda: {"value": [{"id": "machine-xyz"}]})

    with (
        patch("sentinel_api._request", side_effect=fake_request),
        patch("sentinel_api.get_mde_token", return_value="mock-token"),
    ):
        result = await resolve_mde_machine_id("workstation-1")

    assert result == "machine-xyz"
    assert "thread_id" in captured  # _request actually ran
    assert captured["thread_id"] != loop_thread_id  # ...on a worker thread
