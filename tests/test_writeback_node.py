"""
Behavioral Contract for writeback_node.py

Valid Input:
- TriageState dictionary containing triage results.

Expected Output:
- `writeback_node`: Posts a comment.
- `close_review_node`: Triggers `update_incident_status` if approved.

Failure Modes:
- Any API failure is caught and appended to the errors list instead of crashing.

Concurrency Invariants:
- Comment posting uses UUID to guarantee idempotency under retry conditions.
"""

import pytest
from unittest.mock import patch
from nodes.writeback_node import writeback_node, close_review_node, _format_comment


# ── Existing tests ────────────────────────────────────────────────────────────

def test_writeback_node_success(empty_triage_state):
    """Asserts comment is successfully posted."""
    state = empty_triage_state.copy()

    with patch("nodes.writeback_node.fetch_incident_comments", return_value=[]), \
         patch("nodes.writeback_node.post_incident_comment") as mock_post:
        result = writeback_node(state)
        assert result["comment_posted"] is True
        mock_post.assert_called_once()

def test_close_review_node_approved(empty_triage_state):
    """Asserts incident is closed only if approved."""
    state = empty_triage_state.copy()
    state["close_approved"] = True

    with patch("nodes.writeback_node.update_incident_status") as mock_update:
        result = close_review_node(state)
        assert result["incident_closed"] is True
        mock_update.assert_called_once()

def test_close_review_node_rejected(empty_triage_state):
    """Asserts incident remains open if review is rejected."""
    state = empty_triage_state.copy()
    state["close_approved"] = False

    with patch("nodes.writeback_node.update_incident_status") as mock_update:
        result = close_review_node(state)
        assert result["incident_closed"] is False
        mock_update.assert_not_called()


# ── _format_comment: entity lines ────────────────────────────────────────────

def test_format_comment_full_state(empty_triage_state):
    """Asserts _format_comment renders entity lines, CTI lines, MITRE table, and review tag."""
    state = empty_triage_state.copy()
    state["classification"] = "BenignPositive"
    state["triage_summary"] = "Authorized pentest activity."
    state["mitre_analysis"] = "Execution tactic detected."
    state["entities"] = {
        "ips": ["8.8.8.8"],
        "urls": ["http://evil.com/payload"],
        "hashes": ["abc123deadbeef"],
        "usernames": ["admin@corp.local"],
    }
    state["cti_results"] = {
        "ip_reports": [{"ioc": "8.8.8.8", "abuse_score": 85, "usage_type": "Hosting", "country": "US"}],
        "url_reports": [{"ioc": "http://evil.com/payload", "malicious": 5}],
    }
    state["mitre_techniques"] = [
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter",
         "tactic": "Execution", "confidence": 90},
    ]
    state["kql_queries"] = ["SigninLogs | limit 10"]

    comment = _format_comment(state)

    # Entity lines
    assert "**IPs:** 8.8.8.8" in comment
    assert "**URLs:** http://evil.com/payload" in comment
    assert "**Hashes:** abc123deadbeef" in comment
    assert "**Users:** admin@corp.local" in comment
    # CTI lines
    assert "🔴" in comment  # abuse_score 85 > 50
    assert "Hosting" in comment
    # MITRE table
    assert "T1059" in comment
    assert "✅ Verified" in comment
    # BenignPositive review tag
    assert "Pending Analyst Review" in comment


def test_format_comment_no_entities(empty_triage_state):
    """Asserts empty entities renders fallback text."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {}
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    assert "No entities extracted." in comment
    assert "No CTI results available." in comment
    assert "No specific MITRE techniques mapped." in comment


def test_format_comment_unverified_mitre_technique(empty_triage_state):
    """Asserts unverified MITRE techniques show ⚠️ flag."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {}
    state["mitre_techniques"] = [
        {"technique_id": "T9999", "name": "Custom Tech",
         "tactic": "Execution", "confidence": 60, "unverified": True},
    ]

    comment = _format_comment(state)
    assert "⚠️ Unverified" in comment


# ── _format_comment: CTI score thresholds ────────────────────────────────────

def test_format_comment_high_abuse_score(empty_triage_state):
    """Asserts abuse_score > 50 renders 🔴 flag."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {
        "ip_reports": [{"ioc": "1.2.3.4", "abuse_score": 80, "usage_type": "ISP", "country": "DE"}],
    }
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    assert "🔴" in comment


def test_format_comment_medium_abuse_score(empty_triage_state):
    """Asserts abuse_score 11-50 renders 🟡 flag."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {
        "ip_reports": [{"ioc": "1.2.3.4", "abuse_score": 25, "usage_type": "ISP", "country": "DE"}],
    }
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    assert "🟡" in comment


def test_format_comment_low_abuse_score(empty_triage_state):
    """Asserts abuse_score <= 10 renders 🟢 flag."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {
        "ip_reports": [{"ioc": "1.2.3.4", "abuse_score": 5, "usage_type": "ISP", "country": "DE"}],
    }
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    assert "🟢" in comment


def test_format_comment_url_high_detections(empty_triage_state):
    """Asserts url malicious > 3 renders 🔴 flag."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {
        "url_reports": [{"ioc": "http://evil.com", "malicious": 5}],
    }
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    assert "🔴" in comment


def test_format_comment_url_low_detections(empty_triage_state):
    """Asserts url malicious 1-3 renders 🟡 flag."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {
        "url_reports": [{"ioc": "http://maybe.com", "malicious": 2}],
    }
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    assert "🟡" in comment


def test_format_comment_url_zero_detections(empty_triage_state):
    """Asserts url malicious 0 renders 🟢 flag."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {
        "url_reports": [{"ioc": "http://safe.com", "malicious": 0}],
    }
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    assert "🟢" in comment


def test_format_comment_cti_error_results_excluded(empty_triage_state):
    """Asserts CTI results with 'error' key are excluded from the comment."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    state["cti_results"] = {
        "ip_reports": [{"ioc": "1.2.3.4", "error": "HTTP 503"}],
        "url_reports": [{"ioc": "http://fail.com", "error": "timeout"}],
    }
    state["mitre_techniques"] = []

    comment = _format_comment(state)
    # Error results should be filtered out, so no CTI lines
    assert "No CTI results available." in comment


# ── writeback_node: failure branch ───────────────────────────────────────────

def test_writeback_node_comment_failure(empty_triage_state):
    """Asserts comment post failure is captured as error, comment_posted is False."""
    state = empty_triage_state.copy()

    with patch("nodes.writeback_node.post_incident_comment", side_effect=Exception("API down")):
        result = writeback_node(state)
        assert result["comment_posted"] is False
        found_comment_error = False
        for error_message in result["errors"]:
            if "Comment post failed" in error_message:
                found_comment_error = True
                break
        assert found_comment_error


# ── close_review_node: failure branch ────────────────────────────────────────

def test_close_review_node_api_failure(empty_triage_state):
    """Asserts update_incident_status failure is captured as error, incident_closed is False."""
    state = empty_triage_state.copy()
    state["close_approved"] = True

    with patch("nodes.writeback_node.update_incident_status", side_effect=Exception("Timeout")):
        result = close_review_node(state)
        assert result["incident_closed"] is False
        found_close_error = False
        for error_message in result["errors"]:
            if "Close approval failed" in error_message:
                found_close_error = True
                break
        assert found_close_error
