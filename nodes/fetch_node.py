"""
Fetches a Sentinel incident and its associated alerts.
"""

from sentinel_api import get_incident, list_incident_alerts
from state import TriageState


def fetch_node(state: TriageState) -> dict:
    """
    Entry point node. Reads incident_id from state (set by the caller before
    the graph is invoked), then fetches the full incident and its alerts.
    """
    incident_id = state["incident_id"]
    errors = []

    # Single canonical result with safe defaults - avoids duplicating
    # the same dict structure in both the happy path and the except block.
    result = {
        "incident_title": "Unknown",
        "incident_severity": "Unknown",
        "incident_description": "",
        "incident_status": "Unknown",
        "incident_tactics": [],
        "raw_alerts": [],
        "errors": errors,
    }

    try:
        incident = get_incident(incident_id)
        props = incident["properties"]
        result["incident_title"] = props.get("title", "Unknown")
        result["incident_severity"] = props.get("severity", "Unknown")
        result["incident_description"] = props.get("description", "")
        result["incident_status"] = props.get("status", "Unknown")
        result["incident_tactics"] = (
            props.get("additionalData", {}).get("tactics", []) or []
        )
    except Exception as e:
        # Incident fetch is fatal - record the error and return early with
        # whatever partial data we have (all defaults in this case).
        errors.append(f"Fatal fetch error: {str(e)}")
        return result

    try:
        result["raw_alerts"] = list_incident_alerts(incident_id)
    except Exception as e:
        # Alert fetch failure is non-fatal so proceed with incident-level data.
        errors.append(f"Alert fetch failed: {str(e)}")

    return result