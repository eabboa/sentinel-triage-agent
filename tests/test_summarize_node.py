"""
Behavioral Contract for summarize_node.py

Valid Input:
- TriageState with incident_title, incident_severity, incident_tactics,
  incident_description, and raw_alerts.

Expected Output:
- A condensed_summary string containing the incident metadata and first 5 alerts.
- Descriptions longer than 500 characters are truncated with "[truncated]".

Failure Modes:
- N/A (pure formatting logic, no external calls).
"""

from nodes.summarize_node import summarize_node, MAX_DESCRIPTION_CHARS


def test_summarize_node_basic(empty_triage_state):
    """Asserts condensed summary contains incident metadata."""
    state = empty_triage_state.copy()
    state["incident_title"] = "Brute Force Attack"
    state["incident_severity"] = "High"
    state["incident_tactics"] = ["CredentialAccess"]
    state["incident_description"] = "Multiple failed logins detected."
    state["raw_alerts"] = []

    result = summarize_node(state)
    summary = result["condensed_summary"]

    assert "Brute Force Attack" in summary
    assert "High" in summary
    assert "CredentialAccess" in summary
    assert "Multiple failed logins detected." in summary


def test_summarize_node_truncation(empty_triage_state):
    """Asserts descriptions exceeding MAX_DESCRIPTION_CHARS are truncated."""
    state = empty_triage_state.copy()
    state["incident_title"] = "Test"
    state["incident_severity"] = "Low"
    state["incident_tactics"] = []
    state["incident_description"] = "A" * (MAX_DESCRIPTION_CHARS + 100)
    state["raw_alerts"] = []

    result = summarize_node(state)
    assert "[truncated]" in result["condensed_summary"]


def test_summarize_node_no_truncation(empty_triage_state):
    """Asserts short descriptions are not truncated."""
    state = empty_triage_state.copy()
    state["incident_title"] = "Test"
    state["incident_severity"] = "Low"
    state["incident_tactics"] = []
    state["incident_description"] = "Short description."
    state["raw_alerts"] = []

    result = summarize_node(state)
    assert "[truncated]" not in result["condensed_summary"]
    assert "Short description." in result["condensed_summary"]


def test_summarize_node_alert_capping(empty_triage_state):
    """Asserts only the first 5 alerts are included in the summary."""
    state = empty_triage_state.copy()
    state["incident_title"] = "Test"
    state["incident_severity"] = "Low"
    state["incident_tactics"] = []
    state["incident_description"] = "Test"
    state["raw_alerts"] = [
        {"properties": {"alertDisplayName": f"Alert {i}", "severity": "High",
                         "description": f"Desc {i}", "tactics": [], "entities": []}}
        for i in range(7)
    ]

    result = summarize_node(state)
    summary = result["condensed_summary"]

    assert "7 total, showing first 5" in summary
    assert "Alert 0" in summary
    assert "Alert 4" in summary
    # Alert 5 and 6 should NOT be in the summary
    assert "Alert 5" not in summary
    assert "Alert 6" not in summary
