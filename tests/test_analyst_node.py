"""
Behavioral Contract for analyst_node.py

Valid Input:
- A TriageState dictionary containing 'condensed_summary', 'cti_results', and 'entities'.

Expected Output:
- Validates the LLM output strictly against the `AnalystVerdict` Pydantic model.
- Returns a dictionary matching the state requirements containing classification, confidence, etc.
- Retrieves and provides similar past mismatches via ChromaDB for RAG correction.

Failure Modes:
- LLM response fails Pydantic validation: The pipeline catches the ValidationError/ParseError
  and returns a safe fallback dictionary with classification='Undetermined' instead of an
  unhandled AttributeError or KeyError.
- LLM completely times out/fails: Handled identically to validation failure; returns safe fallback.
- ChromaDB unavailable: retrieve_similar_mismatches still calls initialize_chroma(), which
  will throw. The blanket except in analyst_node catches this and returns Undetermined.

Concurrency Invariants:
- N/A.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from nodes.analyst_node import analyst_node, AnalystVerdict, MitreTechnique


@pytest.mark.asyncio
async def test_analyst_node_success(empty_triage_state, valid_analyst_verdict):
    """Asserts correct Pydantic structured output mapping to state when LLM returns valid data."""
    state = empty_triage_state.copy()
    state["condensed_summary"] = "Test summary with suspicious activity from 8.8.8.8"
    state["cti_results"] = {"ip_reports": [{"ioc": "8.8.8.8", "verdict": "malicious"}]}
    state["incident_tactics"] = ["Execution"]

    # The LLM pipeline in analyst_node is:
    #   ChatGoogleGenerativeAI(...).with_structured_output(AnalystVerdict)
    # This creates a RunnableSequence. We need to mock the final ainvoke on that chain.
    # The cleanest way is to mock the entire _invoke_llm inner function's return value
    # by patching the chain at the point where it's called.

    # Mock ChromaDB RAG retrieval to return empty results
    mock_rag = AsyncMock(return_value={"documents": []})

    # Create a mock structured LLM chain that returns our valid verdict directly
    mock_structured_llm = AsyncMock()
    mock_structured_llm.ainvoke = AsyncMock(return_value=valid_analyst_verdict)

    with patch("nodes.analyst_node.retrieve_similar_mismatches", mock_rag), \
         patch("nodes.analyst_node.ChatGoogleGenerativeAI") as MockLLMClass:

        # Make the constructor return a mock, and .with_structured_output() return our mock chain
        mock_instance = MagicMock()
        mock_instance.with_structured_output.return_value = mock_structured_llm
        MockLLMClass.return_value = mock_instance

        result = await analyst_node(state)

        assert result["classification"] == "TruePositive"
        assert result["confidence"] == 95
        assert result["is_true_positive"] is True
        assert len(result["mitre_techniques"]) == 1
        assert result["mitre_techniques"][0]["technique_id"] == "T1059"


@pytest.mark.asyncio
async def test_analyst_node_validation_failure_fallback(empty_triage_state):
    """Asserts LLM structured output validation failure yields a safe Undetermined state.

    In a SOC context, an Undetermined classification is explicitly designed to prevent
    autonomous closure of an incident that the LLM could not confidently triage.
    """
    state = empty_triage_state.copy()
    state["condensed_summary"] = "Some incident"

    mock_rag = AsyncMock(return_value={"documents": []})

    # Simulate the LLM chain throwing a validation error
    mock_structured_llm = AsyncMock()
    mock_structured_llm.ainvoke = AsyncMock(
        side_effect=Exception("Pydantic ValidationError: field required")
    )

    with patch("nodes.analyst_node.retrieve_similar_mismatches", mock_rag), \
         patch("nodes.analyst_node.ChatGoogleGenerativeAI") as MockLLMClass:

        mock_instance = MagicMock()
        mock_instance.with_structured_output.return_value = mock_structured_llm
        MockLLMClass.return_value = mock_instance

        result = await analyst_node(state)

        assert result["classification"] == "Undetermined"
        assert result["confidence"] == 0
        assert "Analyst node failed" in result["triage_summary"]
        assert len(result["errors"]) > 0


@pytest.mark.asyncio
async def test_analyst_node_chromadb_unavailable_degrades_gracefully():
    """Asserts ChromaDB connection failure degrades to Undetermined instead of crashing.

    Previously (DEFECT-001), retrieve_similar_mismatches() was called outside the
    try/except block, causing a ChromaDB outage to crash the entire triage pipeline.
    After the fix, the call is inside the try block and the node returns a safe
    Undetermined fallback.
    """
    state = {
        "incident_id": "test_id",
        "condensed_summary": "Some incident",
        "cti_results": {},
        "entities": {},
        "incident_tactics": [],
    }

    mock_rag = AsyncMock(side_effect=ValueError("Could not connect to Chroma server"))

    with patch("nodes.analyst_node.retrieve_similar_mismatches", mock_rag):
        result = await analyst_node(state)

        assert result["classification"] == "Undetermined"
        assert result["confidence"] == 0
        assert "Could not connect to Chroma server" in result["triage_summary"]
        assert len(result["errors"]) > 0

