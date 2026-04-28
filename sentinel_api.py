# this script fetches and lists incidents filtered by "New", lists incident alerts granularly for IoC extraction, then agent writes comments + updates incident status.

import os
import uuid
import requests
from dotenv import load_dotenv
from sentinel_auth import get_auth_headers

load_dotenv()

SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")
WORKSPACE_NAME = os.getenv("WORKSPACE_NAME")
API_VERSION = "2023-02-01" ## stable version. do not change this.

# Base path used in every URL. Stored once and centralized. Change variables only from here.
_BASE = (
    f"https://management.azure.com"
    f"/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
    f"/providers/Microsoft.SecurityInsights"
)


def list_incidents(status_filter: str = "New", max_results: int = 5) -> list[dict]:
    """
    Fetches open Sentinel incidents filtered by status. Look only for New, which is no one interacted with this incident yet.
    
    max_results=5?
    Free tier rate limit protection. The Gemini free tier allows 15 RPM.
    5 incidents x 3 LLM calls each = 15 calls. This is inside the safe limits.
    """
    url = f"{_BASE}/incidents"
    params = {
        "api-version": API_VERSION,
        "$filter": f"properties/status eq '{status_filter}'",
        "$orderby": "properties/createdTimeUtc desc",
        "$top": max_results,
    }

    response = requests.get(url, headers=get_auth_headers(), params=params)
    response.raise_for_status()  # Raises HTTPError for 4xx/5xx responses
    
    data = response.json()
    return data.get("value", [])


def get_incident(incident_id: str) -> dict:
    """
    Fetches a single incident by its ID. full incident object, including all properties and entity mappings.
    """
    url = f"{_BASE}/incidents/{incident_id}"
    params = {"api-version": API_VERSION}
    
    response = requests.get(url, headers=get_auth_headers(), params=params)
    response.raise_for_status()
    return response.json()


def list_incident_alerts(incident_id: str) -> list[dict]:
    """
    Fetches all alerts associated with an incident.
    """
    url = f"{_BASE}/incidents/{incident_id}/alerts"
    params = {"api-version": API_VERSION}
    
    response = requests.post(url, headers=get_auth_headers(), params=params)
    # Note: This is a POST, not GET. The Sentinel API uses POST for listing.
    response.raise_for_status()
    
    data = response.json()
    return data.get("value", [])


def post_incident_comment(incident_id: str, comment_text: str) -> dict:
    """
    Posts an analyst comment on a Sentinel incident.
    
    The comment_id must be a valid GUID (UUID4). Azure uses it as a unique key.
    Generating it locally ensures idempotency — if your agent crashes and retries, use the same comment_id and Azure will not create a duplicate.
    """
    comment_id = str(uuid.uuid4())
    url = f"{_BASE}/incidents/{incident_id}/comments/{comment_id}"
    params = {"api-version": API_VERSION}
    body = {
        "properties": {
            "message": comment_text,
        }
    }
    
    response = requests.put(url, headers=get_auth_headers(), params=params, json=body)
    response.raise_for_status()
    return response.json()


def update_incident_status(incident_id: str, new_status: str, classification: str = None) -> dict:
    """
    Updates a Sentinel incident's status.
    
    Valid statuses: "New", "Active", "Closed"
    Valid classifications (required when closing):
        "TruePositive", "FalsePositive", "BenignPositive", "Undetermined"

    It is currently vulnerable to Race Condition, requiring ETag.
    """
    # Fetch current incident to preserve all existing fields
    existing = get_incident(incident_id)
    
    # Modify only the fields you need to change
    existing["properties"]["status"] = new_status
    
    if new_status == "Closed" and classification:
        existing["properties"]["classification"] = classification
        # classificationComment is optional but useful for audit trails
        existing["properties"]["classificationComment"] = (
            "Auto-closed by Sentinel Triage Agent after LangGraph analysis."
        )
    
    url = f"{_BASE}/incidents/{incident_id}"
    params = {"api-version": API_VERSION}
    
    response = requests.put(url, headers=get_auth_headers(), params=params, json=existing)
    response.raise_for_status()
    return response.json()