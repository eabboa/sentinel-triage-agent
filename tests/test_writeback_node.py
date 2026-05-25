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
from nodes.writeback_node import writeback_node, close_review_node

def test_writeback_node_success(empty_triage_state):
    """Asserts comment is successfully posted."""
    state = empty_triage_state.copy()
    
    with patch("nodes.writeback_node.post_incident_comment") as mock_post:
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
