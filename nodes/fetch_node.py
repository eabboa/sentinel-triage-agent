"""
Fetches a Sentinel incident and its associated alerts.
"""

from typing import Any

import structlog
from pydantic import ValidationError

from models.exceptions import SentinelAlertValidationError
from models.validation import SentinelAlert
from sentinel_api import get_incident, list_incident_alerts
from state import TriageState

logger = structlog.get_logger(__name__)


def fetch_node(state: TriageState) -> dict:
    """
    Entry point node. Reads incident_id from state (set by the caller before
    the graph is invoked), then fetches the full incident and its alerts.

    Args:
        state: The current TriageState dictionary.

    Returns:
        A dictionary containing the state updates for the fetched incident.
    """
    incident_id = state["incident_id"]
    logger.info("node_entry", node="fetch")
    errors: list[str] = []

    # Single canonical result with safe defaults - avoids duplicating
    # the same dict structure in both the happy path and the except block.
    result: dict[str, Any] = {
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
        logger.error("node_error", node="fetch", exc_info=True)
        errors.append(f"Fatal fetch error: {str(e)}")
        return result

    try:
        # 1. Fetch the raw list of dictionaries from the API
        raw_alerts_list = list_incident_alerts(incident_id)
        valid_alerts = []

        for raw_alert in raw_alerts_list:
            try:
                valid_alert = SentinelAlert.model_validate(raw_alert)
                valid_alerts.append(valid_alert.model_dump())

            except ValidationError as exc:
                logger.error(
                    "Sentinel alert validation failed. Raw input: %s", raw_alert
                )
                raise SentinelAlertValidationError(
                    message=f"Alert schema mismatch: {str(exc)}", raw_data=raw_alert
                ) from exc
        result["raw_alerts"] = valid_alerts

    except SentinelAlertValidationError as e:
        logger.error("node_error", node="fetch", exc_info=True)
        errors.append(f"Alert validation failed: {str(e)}")
    except Exception as e:
        logger.error("node_error", node="fetch", exc_info=True)
        errors.append(f"Alert fetch failed: {str(e)}")

    logger.info("node_exit", node="fetch")
    return result
