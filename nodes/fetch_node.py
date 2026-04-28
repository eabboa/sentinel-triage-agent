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

    try:
        incident = get_incident(incident_id)
        props = incident["properties"]

        alerts = []
        try:
            alerts = list_incident_alerts(incident_id)
        except Exception as e:
            # Alert fetch failure is non-fatal so proceed with incident-level data
            errors.append(f"Alert fetch failed: {str(e)}")

        return {
            "incident_title": props.get("title", "Unknown"),
            "incident_severity": props.get("severity", "Unknown"),
            "incident_description": props.get("description", ""),
            "incident_status": props.get("status", "Unknown"),
            "incident_tactics": props.get("additionalData", {}).get("tactics", []) or [],
            "raw_alerts": alerts,
            "errors": errors,
        }

    except Exception as e:
        return {
            "incident_title": "ERROR",
            "incident_severity": "Unknown",
            "incident_description": "",
            "incident_status": "Unknown",
            "incident_tactics": [],
            "raw_alerts": [],
            "errors": [f"Fatal fetch error: {str(e)}"],
        }