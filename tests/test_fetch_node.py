"""
Behavioral Contract for fetch_node.py

Valid Input:
- A TriageState dictionary containing at least an 'incident_id'.

Expected Output:
- Fetches incident details and alerts from Sentinel API.
- Returns dictionary updating incident_title, incident_severity, incident_description, incident_status, incident_tactics, and raw_alerts.

Failure Modes:
- get_incident failure (e.g. 404): Catches exception, adds error to 'errors' list, returns early with default/safe values.
- list_incident_alerts failure: Catches exception, adds error to 'errors' list, proceeds with incident data but empty raw_alerts.

Concurrency Invariants:
- N/A (runs synchronously per thread).
"""

import pytest
from unittest.mock import patch
from nodes.fetch_node import fetch_node

def test_fetch_node_success(empty_triage_state):
    """Asserts successful fetch updates state correctly."""
    with patch("nodes.fetch_node.get_incident") as mock_get_incident, \
         patch("nodes.fetch_node.list_incident_alerts") as mock_list_alerts:
        
        mock_get_incident.return_value = {
            "properties": {
                "title": "Suspicious Login",
                "severity": "High",
                "description": "User logged in from unknown IP",
                "status": "New",
                "additionalData": {"tactics": ["InitialAccess"]}
            }
        }
        mock_list_alerts.return_value = [{"name": "alert1"}]
        
        state = empty_triage_state.copy()
        result = fetch_node(state)
        
        assert result["incident_title"] == "Suspicious Login"
        assert result["incident_severity"] == "High"
        assert result["incident_status"] == "New"
        assert result["incident_tactics"] == ["InitialAccess"]
        assert len(result["raw_alerts"]) == 1
        assert len(result["errors"]) == 0

def test_fetch_node_incident_failure(empty_triage_state):
    """Asserts an error fetching the incident degrades gracefully without crashing."""
    with patch("nodes.fetch_node.get_incident", side_effect=Exception("API down")):
        state = empty_triage_state.copy()
        result = fetch_node(state)
        
        assert result["incident_title"] == "Unknown"
        assert len(result["raw_alerts"]) == 0
        assert "Fatal fetch error: API down" in result["errors"][0]

def test_fetch_node_alerts_failure(empty_triage_state):
    """Asserts an error fetching alerts preserves the incident data."""
    with patch("nodes.fetch_node.get_incident") as mock_get_incident, \
         patch("nodes.fetch_node.list_incident_alerts", side_effect=Exception("Alerts down")):
        
        mock_get_incident.return_value = {
            "properties": {
                "title": "Suspicious Login"
            }
        }
        
        state = empty_triage_state.copy()
        result = fetch_node(state)
        
        assert result["incident_title"] == "Suspicious Login"
        assert len(result["raw_alerts"]) == 0
        assert "Alert fetch failed: Alerts down" in result["errors"][0]
