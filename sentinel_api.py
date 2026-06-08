# this script fetches and lists incidents filtered by "New", lists incident alerts granularly for IoC extraction, then agent writes comments + updates incident status.

import asyncio
import structlog
import os
import re
import uuid
from typing import Any
import requests
from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter
from dotenv import load_dotenv
from sentinel_auth import get_auth_headers, get_graph_token, get_mde_token

load_dotenv()

logger = structlog.get_logger(__name__)
DEFAULT_HTTP_TIMEOUT = 10
RETRY_ATTEMPTS = 3

class ConcurrencyConflictError(Exception):
    """Raised when an optimistic concurrency update fails due to an ETag mismatch."""

class TransientHTTPError(RequestException):
    """Raised for transient HTTP errors (429, 503, 504) to trigger tenacity retries."""

@retry(
    retry=retry_if_exception_type((TransientHTTPError, ConnectionError, Timeout)),
    wait=wait_exponential_jitter(initial=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
def _http_request(method: str, url: str, *, headers=None, params=None, json=None) -> requests.Response:
    """
    Executes an HTTP request with automatic retries on transient failures.

    Args:
        method: HTTP method (GET, POST, PUT, etc.).
        url: The target URL.
        headers: Optional HTTP headers.
        params: Optional query parameters.
        json: Optional JSON body payload.

    Returns:
        The successful requests.Response object.

    Raises:
        TransientHTTPError: On 429, 503, 504 responses (triggers tenacity retry).
        RequestException: On any other HTTP failure.
    """
    try:
        logger.info("api_call_start", method=method, url=url)
        response = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json,
            timeout=DEFAULT_HTTP_TIMEOUT,
        )
        logger.info("api_call_end", method=method, url=url, status_code=response.status_code)
        if response.status_code in (429, 503, 504):
            logger.warning("Transient HTTP %s for %s; retrying", response.status_code, url)
            raise TransientHTTPError(
                f"Transient HTTP {response.status_code} for {url}",
                response=response,
            )
        response.raise_for_status()
        return response
    except RequestException as exc:
        logger.warning("HTTP %s request to %s failed: %s", method, url, exc)
        raise


def _request(method: str, url: str, *, headers=None, params=None, json=None) -> requests.Response:
    """
    Wrapper around _http_request that provides centralized error logging after retry exhaustion.

    Args:
        method: HTTP method (GET, POST, PUT, etc.).
        url: The target URL.
        headers: Optional HTTP headers.
        params: Optional query parameters.
        json: Optional JSON body payload.

    Returns:
        The successful requests.Response object.

    Raises:
        RequestException: If the request fails after all retry attempts.
    """
    try:
        # Delegate the request execution to the retry-enabled _http_request helper.
        return _http_request(method, url, headers=headers, params=params, json=json)
    except RequestException as exc:
        # Log the ultimate failure after all tenacity retry attempts have been exhausted.
        logger.error("HTTP request to %s failed after retries: %s", url, exc)
        raise

API_VERSION = "2023-02-01" ## stable version. do not change this.

# Lazy-initialized module state — deferred from import time so that test
# fixtures can inject env vars before the first real API call.
_BASE: str | None = None


def _get_base() -> str:
    """
    Returns the Sentinel API base URL, validating config on first call.

    Returns:
        The fully constructed Azure Sentinel REST API base URL.

    Raises:
        EnvironmentError: If SUBSCRIPTION_ID, RESOURCE_GROUP, or WORKSPACE_NAME is missing.
    """
    global _BASE
    if _BASE is not None:
        return _BASE

    subscription_id = os.getenv("SUBSCRIPTION_ID")
    resource_group = os.getenv("RESOURCE_GROUP")
    workspace_name = os.getenv("WORKSPACE_NAME")

    _required = {
        "SUBSCRIPTION_ID": subscription_id,
        "RESOURCE_GROUP": resource_group,
        "WORKSPACE_NAME": workspace_name,
    }   
    _missing = []
    for env_var, value in _required.items():
        if not value:
            _missing.append(env_var)
    if _missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(_missing)}. "
            "Set them in .env or the deployment environment."
        )

    _BASE = (
        f"https://management.azure.com"
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        f"/providers/Microsoft.SecurityInsights"
    )
    return _BASE



VALID_INCIDENT_STATUSES = {"New", "Active", "Closed"}


def list_incidents(status_filter: str = "New", max_results: int = 5) -> list[dict]:
    """
    Fetches open Sentinel incidents filtered by status.

    Looks only for "New" by default — incidents no one has interacted with yet.
    max_results defaults to 5 for free-tier rate-limit protection
    (5 incidents × 3 LLM calls = 15 RPM, within Gemini free-tier limits).

    Args:
        status_filter: Incident status to filter by. Must be one of "New", "Active", "Closed".
        max_results: Maximum number of incidents to return.

    Returns:
        List of incident dicts from the Sentinel API (may be empty).

    Raises:
        ValueError: If status_filter is not a valid incident status.
        RequestException: If the API request fails.
    """
    if status_filter not in VALID_INCIDENT_STATUSES:
        raise ValueError(
            f"Invalid status_filter {status_filter!r}. Must be one of {VALID_INCIDENT_STATUSES}."
        )
    url = f"{_get_base()}/incidents"
    # query parameters for an HTTP GET request to the Azure Sentinel (Azure Resource Manager) REST API,
    # following the OData (Open Data Protocol) standard
    params = {
        "api-version": API_VERSION,
        "$filter": f"properties/status eq '{status_filter}'",
        "$orderby": "properties/createdTimeUtc desc",
        "$top": max_results,
    }

    response = _request("GET", url, headers=get_auth_headers(), params=params)
    data = response.json()
    return data.get("value", [])


def get_incident(incident_id: str) -> dict:
    """
    Fetches a single incident by its ID, including all properties and entity mappings.

    Args:
        incident_id: The Sentinel incident ID.

    Returns:
        Full incident dict including properties, etag, and entity mappings.

    Raises:
        RequestException: If the API request fails.
    """
    url = f"{_get_base()}/incidents/{incident_id}"
    params = {"api-version": API_VERSION}
    
    response = _request("GET", url, headers=get_auth_headers(), params=params)
    incident = response.json()
    incident_etag = incident.get("etag")
    if incident_etag:
        logger.debug("Fetched incident %s with ETag %s", incident_id, incident_etag)
    return incident


def list_incident_alerts(incident_id: str) -> list[dict]:
    """
    Fetches all alerts associated with an incident.

    Args:
        incident_id: The Sentinel incident ID.

    Returns:
        List of alert dicts associated with the incident.

    Raises:
        RequestException: If the API request fails.
    """
    url = f"{_get_base()}/incidents/{incident_id}/alerts"
    params = {"api-version": API_VERSION}
    
    response = _request("POST", url, headers=get_auth_headers(), params=params)
    # Note: This is a POST, not GET. The Sentinel API uses POST for listing the alerts of an incident.
    data = response.json()
    return data.get("value", [])


def post_incident_comment(incident_id: str, comment_text: str) -> dict:
    """
    Posts an analyst comment on a Sentinel incident.

    The comment_id is generated as a UUID4 locally. Azure uses it as a unique key,
    so reusing the same ID on retry prevents duplicate comments.

    Args:
        incident_id: The Sentinel incident ID.
        comment_text: The comment message body.

    Returns:
        Response JSON dict from the Sentinel comments endpoint.

    Raises:
        RequestException: If the API request fails.
    """
    comment_id = str(uuid.uuid4())
    url = f"{_get_base()}/incidents/{incident_id}/comments/{comment_id}"
    params = {"api-version": API_VERSION}
    body = {
        "properties": {
            "message": comment_text,
        }
    }
    
    response = _request("PUT", url, headers=get_auth_headers(), params=params, json=body)
    return response.json()


def fetch_incident_comments(incident_id: str) -> list[dict]:
    """
    Fetches all comments on a Sentinel incident.

    Args:
        incident_id: The Sentinel incident ID.

    Returns:
        List of comment dicts for the incident.

    Raises:
        RequestException: If the API request fails.
    """
    url = f"{_get_base()}/incidents/{incident_id}/comments"
    params = {"api-version": API_VERSION}

    response = _request("GET", url, headers=get_auth_headers(), params=params)
    return response.json().get("value", [])


@retry(
    retry=retry_if_exception_type(ConcurrencyConflictError),
    wait=wait_exponential_jitter(initial=1, max=10),
    stop=stop_after_attempt(3),
    reraise=True,
)
def update_incident_status(incident_id: str, new_status: str, classification: str | None = None) -> dict:
    """
    Updates a Sentinel incident's status with optimistic concurrency control.

    Retries automatically on ETag 412 conflicts by re-fetching the incident.

    Args:
        incident_id: The Sentinel incident ID.
        new_status: Target status — "New", "Active", or "Closed".
        classification: Required when closing. One of "TruePositive",
            "FalsePositive", "BenignPositive", "Undetermined".

    Returns:
        Updated incident dict from the Sentinel API.

    Raises:
        ConcurrencyConflictError: On ETag 412 mismatch (triggers tenacity retry).
        HTTPError: On any other HTTP failure.
    """
    # Fetch current incident to preserve all existing fields and capture its current ETag.
    existing = get_incident(incident_id)
    etag = existing.get("etag")
    headers = get_auth_headers()
    if etag:
        headers["If-Match"] = etag
    
    # Modify only the fields you need to change
    existing["properties"]["status"] = new_status
    
    if new_status == "Closed" and classification:
        existing["properties"]["classification"] = classification
        
        reason_map = {
            "TruePositive": "SuspiciousActivity",
            "FalsePositive": "IncorrectAlertLogic",
            "BenignPositive": "SuspiciousButExpected",
            "Undetermined": "InaccurateData"
        }
        existing["properties"]["classificationReason"] = reason_map.get(classification, "SuspiciousActivity")
        
        # classificationComment is optional but useful for audit trails
        existing["properties"]["classificationComment"] = (
            "Closed by Sentinel Triage Agent after analyst review and approval."
        )
    
    url = f"{_get_base()}/incidents/{incident_id}"
    params = {"api-version": API_VERSION}
    
    try:
        response = _request("PUT", url, headers=headers, params=params, json=existing)
        return response.json()
    except HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 412:
            raise ConcurrencyConflictError(
                f"Incident {incident_id} update failed due to concurrent modification."
            ) from exc
        raise


# Pattern for valid MDE machine IDs (40-character hex strings)
_MDE_MACHINE_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


async def resolve_mde_machine_id(hostname_or_ip: str) -> str | None:
    """
    Resolves a hostname or IP to an MDE machine ID via the MDE API.

    Args:
        hostname_or_ip: The device hostname or IP address to look up.

    Returns:
        The MDE machine ID string, or None if the device is not found.

    Raises:
        RequestException: If the MDE API request fails.
    """
    url = "https://api.securitycenter.microsoft.com/api/machines"
    headers = {
        "Authorization": f"Bearer {get_mde_token()}",
        "Content-Type": "application/json",
    }
    # OData filter — single-quote escaping prevents injection
    safe_value = hostname_or_ip.replace("'", "''")
    params = {
        "$filter": f"computerDnsName eq '{safe_value}' or lastIpAddress eq '{safe_value}'",
        "$top": "1",
    }
    response = _request("GET", url, headers=headers, params=params)
    data = response.json()
    machines = data.get("value", [])
    if machines:
        return machines[0].get("id")
    return None


async def isolate_mde_device(device_id: str) -> dict:
    """
    Isolates a device using the Microsoft Defender for Endpoint machine isolation API.
    
    Args:
        device_id: The Defender for Endpoint machine ID (40-character hex string).
    
    Returns:
        Response JSON from the Defender for Endpoint isolate endpoint.
        
    Raises:
        ValueError: If device_id is not a valid MDE machine ID format.
        RequestException: If the isolation request fails (caller should handle)
    """
    if not _MDE_MACHINE_ID_PATTERN.match(device_id):
        raise ValueError(
            f"Invalid MDE machine ID format: {device_id!r}. "
            "Expected 40-character hex string. Use resolve_mde_machine_id() first."
        )

    url = f"https://api.securitycenter.microsoft.com/api/machines/{device_id}/isolate"
    
    headers = {
        "Authorization": f"Bearer {get_mde_token()}",
        "Content-Type": "application/json",
    }
    
    body = {
        "Comment": "Automated isolation by Sentinel Triage Agent",
        "IsolationType": "Full",
    }
    
    response = _request("POST", url, headers=headers, json=body)
    
    # Check if the server returned any text response
    if response.text:
        # Convert the raw text response into a Python dictionary
        return response.json()
    else:
        # If the response was empty (no text), return an empty dictionary
        return {}


async def revoke_entra_sessions(user_id: str) -> dict:
    """
    Revokes all Entra ID (Azure AD) refresh tokens for a user.

    Forces the user to re-authenticate and invalidates all existing sessions.

    Args:
        user_id: The Entra ID user object ID (GUID) or UPN.

    Returns:
        Response JSON from Microsoft Graph API.

    Raises:
        RequestException: If the revocation request fails (caller should handle).
    """
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions"
    
    headers = {
        "Authorization": f"Bearer {get_graph_token()}",
        "Content-Type": "application/json",
    }
    
    body: dict[str, Any] = {}  # Graph API revokeSignInSessions expects empty body
    
    response = _request("POST", url, headers=headers, json=body)
    
    if response.text:
        return response.json()
    else:
        return {}