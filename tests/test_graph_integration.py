"""
Behavioral Contract for LangGraph Integration

This tests the graph routing logic, interrupt behavior, and checkpoint state
management — NOT the node implementations themselves (those are unit-tested
separately).

Valid Input:
- Initial state containing 'incident_id' and enough fields for conditional edges.

Expected Output:
- The graph executes nodes in order per the defined edge topology.
- Pauses at interrupt_after=["writeback"].
- Resumes correctly after human state injection via graph.update_state().
- Checkpointer serializes and deserializes state across the interrupt boundary.

Failure Modes:
- N/A (routing logic is deterministic).

Concurrency Invariants:
- thread_id in the config isolates checkpoints per incident, preventing state
  contamination between concurrent invocations sharing the same MemorySaver.
"""

import pytest
import uuid
from typing import cast
from unittest.mock import patch, AsyncMock, MagicMock
from langgraph.checkpoint.memory import MemorySaver


@pytest.mark.asyncio
async def test_graph_hitl_interrupt_and_resume():
    """Asserts the full graph lifecycle: pre-HITL run → interrupt → human input → resume → completion.

    This validates that the MemorySaver checkpointer correctly serializes state at the
    writeback interrupt point and that graph.update_state() correctly injects human
    decisions into the checkpoint before resumption.
    """
    # Mock ALL node functions BEFORE building the graph so the graph captures mock references.
    with patch("nodes.fetch_node.get_incident", return_value={"properties": {"title": "Test", "severity": "High", "description": "desc", "status": "New", "additionalData": {"tactics": []}}}), \
         patch("nodes.fetch_node.list_incident_alerts", return_value=[]), \
         patch("nodes.summarize_node.summarize_node", return_value={"condensed_summary": "Test summary"}), \
         patch("nodes.extract_node.extract_node", new_callable=AsyncMock, return_value={"entities": {}}), \
         patch("nodes.analyst_node.retrieve_similar_mismatches", new_callable=AsyncMock, return_value={"documents": []}), \
         patch("nodes.analyst_node.ChatGoogleGenerativeAI") as MockLLM, \
         patch("nodes.writeback_node.post_incident_comment", return_value={}), \
         patch("nodes.writeback_node.update_incident_status", return_value={}), \
         patch("nodes.learning_node.embed_and_store", new_callable=AsyncMock):

        # Configure the mocked LLM chain to return a valid AnalystVerdict
        from nodes.analyst_node import AnalystVerdict, MitreTechnique
        mock_verdict = AnalystVerdict(
            classification="FalsePositive",
            is_true_positive=False,
            triage_summary="Benign activity.",
            mitre_analysis="No threat.",
            mitre_techniques=[],
            confidence=99,
            recommended_action="Close.",
        )
        mock_structured_llm = AsyncMock()
        mock_structured_llm.ainvoke = AsyncMock(return_value=mock_verdict)
        mock_instance = MagicMock()
        mock_instance.with_structured_output.return_value = mock_structured_llm
        MockLLM.return_value = mock_instance

        # Also mock the KQL node's LLM
        with patch("nodes.kql_node.ChatGoogleGenerativeAI") as MockKQLLLM:
            mock_kql_response = AsyncMock()
            mock_kql_response.content = '{"queries": []}'
            mock_kql_llm_instance = MagicMock()
            mock_kql_llm_instance.ainvoke = AsyncMock(return_value=mock_kql_response)
            MockKQLLLM.return_value = mock_kql_llm_instance

            # Build graph INSIDE the patch context
            from graph import build_graph
            graph, checkpointer = build_graph()

            thread_id = str(uuid.uuid4())
            config = {"configurable": {"thread_id": thread_id}}

            initial_state = {
                "incident_id": "test_123",
                "incident_title": "",
                "incident_severity": "",
                "incident_description": "",
                "incident_status": "",
                "incident_tactics": [],
                "raw_alerts": [],
                "condensed_summary": "",
                "entities": {},
                "cti_results": {},
                "is_true_positive": False,
                "classification": "",
                "confidence": 0,
                "triage_summary": "",
                "mitre_analysis": "",
                "mitre_techniques": [],
                "kql_queries": [],
                "comment_posted": False,
                "incident_closed": False,
                "close_approved": False,
                "containment_approved": False,
                "escalation_triggered": False,
                "escalation_summary": "",
                "human_classification": None,
                "human_classification_reason": None,
                "errors": [],
            }

            # Phase 1: Pre-HITL execution — should pause after writeback
            state1 = await graph.ainvoke(initial_state, config=config)

            snapshot = graph.get_state(config)
            # Graph should be paused after writeback, waiting for human review
            assert snapshot.next, "Graph should be paused at the HITL interrupt point"

            # Phase 2: Inject human decisions
            graph.update_state(config, {"close_approved": True})

            # Phase 3: Resume graph
            state2 = await graph.ainvoke(None, config=config)

            # Verify completion
            snapshot2 = graph.get_state(config)
            assert snapshot2.next == (), "Graph should have completed after HITL resume"


@pytest.mark.asyncio
async def test_graph_hitl_rejection_no_closure():
    """Asserts that when the analyst rejects closure, the incident is NOT closed.

    This is a critical SOC safety invariant: no autonomous closure without explicit
    human approval. If close_approved remains False, close_review_node must not
    call update_incident_status.
    """
    with patch("nodes.fetch_node.get_incident", return_value={"properties": {"title": "Test", "severity": "High", "description": "desc", "status": "New", "additionalData": {"tactics": []}}}), \
         patch("nodes.fetch_node.list_incident_alerts", return_value=[]), \
         patch("nodes.summarize_node.summarize_node", return_value={"condensed_summary": "Test summary"}), \
         patch("nodes.extract_node.extract_node", new_callable=AsyncMock, return_value={"entities": {}}), \
         patch("nodes.analyst_node.retrieve_similar_mismatches", new_callable=AsyncMock, return_value={"documents": []}), \
         patch("nodes.analyst_node.ChatGoogleGenerativeAI") as MockLLM, \
         patch("nodes.writeback_node.post_incident_comment", return_value={}), \
         patch("nodes.writeback_node.update_incident_status") as mock_update_status, \
         patch("nodes.learning_node.embed_and_store", new_callable=AsyncMock):

        from nodes.analyst_node import AnalystVerdict
        mock_verdict = AnalystVerdict(
            classification="TruePositive",
            is_true_positive=True,
            triage_summary="Malicious.",
            mitre_analysis="Attack.",
            mitre_techniques=[],
            confidence=50,
            recommended_action="Investigate.",
        )
        mock_structured_llm = AsyncMock()
        mock_structured_llm.ainvoke = AsyncMock(return_value=mock_verdict)
        mock_instance = MagicMock()
        mock_instance.with_structured_output.return_value = mock_structured_llm
        MockLLM.return_value = mock_instance

        with patch("nodes.kql_node.ChatGoogleGenerativeAI") as MockKQLLLM:
            mock_kql_response = AsyncMock()
            mock_kql_response.content = '{"queries": []}'
            mock_kql_llm_instance = MagicMock()
            mock_kql_llm_instance.ainvoke = AsyncMock(return_value=mock_kql_response)
            MockKQLLLM.return_value = mock_kql_llm_instance

            from graph import build_graph
            graph, _ = build_graph()

            thread_id = str(uuid.uuid4())
            config = {"configurable": {"thread_id": thread_id}}

            initial_state = {
                "incident_id": "test_reject",
                "incident_title": "",
                "incident_severity": "",
                "incident_description": "",
                "incident_status": "",
                "incident_tactics": [],
                "raw_alerts": [],
                "condensed_summary": "",
                "entities": {},
                "cti_results": {},
                "is_true_positive": False,
                "classification": "",
                "confidence": 0,
                "triage_summary": "",
                "mitre_analysis": "",
                "mitre_techniques": [],
                "kql_queries": [],
                "comment_posted": False,
                "incident_closed": False,
                "close_approved": False,
                "containment_approved": False,
                "escalation_triggered": False,
                "escalation_summary": "",
                "human_classification": None,
                "human_classification_reason": None,
                "errors": [],
            }

            await graph.ainvoke(initial_state, config=config)

            # Analyst REJECTS closure
            graph.update_state(config, {"close_approved": False})

            state2 = await graph.ainvoke(None, config=config)

            snapshot = graph.get_state(config)
            assert snapshot.next == ()

            # The critical assertion: update_incident_status must NOT have been called
            mock_update_status.assert_not_called()


# ── Routing function unit tests ───────────────────────────────────────────────

from graph import _next_after_extract, _next_after_analyst, _next_after_writeback, escalation_node
from state import TriageState


def test_next_after_extract_with_entities():
    """Entities with IPs routes to 'enrich'."""
    state = cast(TriageState, {"entities": {"ips": ["8.8.8.8"], "hashes": [], "urls": []}})
    assert _next_after_extract(state) == "enrich"


def test_next_after_extract_with_hashes():
    """Entities with hashes routes to 'enrich'."""
    state = cast(TriageState, {"entities": {"ips": [], "hashes": ["abc123"], "urls": []}})
    assert _next_after_extract(state) == "enrich"


def test_next_after_extract_with_urls():
    """Entities with URLs routes to 'enrich'."""
    state = cast(TriageState, {"entities": {"ips": [], "hashes": [], "urls": ["http://evil.com"]}})
    assert _next_after_extract(state) == "enrich"


def test_next_after_extract_no_entities():
    """Empty entities routes directly to 'analyst'."""
    state = cast(TriageState, {"entities": {}})
    assert _next_after_extract(state) == "analyst"


def test_next_after_analyst_escalation():
    """TruePositive + confidence > 90 routes to 'escalation'."""
    state = cast(TriageState, {"classification": "TruePositive", "confidence": 95})
    assert _next_after_analyst(state) == "escalation"


def test_next_after_analyst_writeback():
    """FalsePositive + confidence > 95 routes directly to 'writeback'."""
    state = cast(TriageState, {"classification": "FalsePositive", "confidence": 99})
    assert _next_after_analyst(state) == "writeback"


def test_next_after_analyst_kql():
    """Default case routes to 'kql'."""
    state = cast(TriageState, {"classification": "TruePositive", "confidence": 50})
    assert _next_after_analyst(state) == "kql"


def test_next_after_writeback_containment():
    """containment_approved=True routes to 'containment'."""
    state = cast(TriageState, {"containment_approved": True})
    assert _next_after_writeback(state) == "containment"


def test_next_after_writeback_close_review():
    """containment_approved=False routes to 'close_review'."""
    state = cast(TriageState, {"containment_approved": False})
    assert _next_after_writeback(state) == "close_review"


def test_escalation_node():
    """Escalation node returns escalation_triggered and summary."""
    result = escalation_node(cast(TriageState, {}))
    assert result["escalation_triggered"] is True
    assert "escalation" in result["escalation_summary"].lower()

