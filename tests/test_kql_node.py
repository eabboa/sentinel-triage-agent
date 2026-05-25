"""
Behavioral Contract for kql_node.py

Valid Input:
- TriageState dictionary containing 'incident_title', 'incident_tactics', 'entities', 'triage_summary', and 'classification'.

Expected Output:
- Returns syntactically valid KQL queries mapped to Sentinel schemas.
- Excludes output if classification is 'FalsePositive'.

Failure Modes:
- LLM generation failure: Caught and returns a fallback KQL string indicating the failure without crashing.

Concurrency Invariants:
- N/A.
"""

import pytest
from unittest.mock import patch, AsyncMock
from nodes.kql_node import kql_node

@pytest.mark.asyncio
async def test_kql_node_skip_false_positive(empty_triage_state):
    """Asserts KQL generation is skipped for false positives."""
    state = empty_triage_state.copy()
    state["classification"] = "FalsePositive"
    
    result = await kql_node(state)
    assert "No hunting queries generated" in result["kql_queries"][0]

@pytest.mark.asyncio
async def test_kql_node_success(empty_triage_state):
    """Asserts successful generation parses into KQL queries."""
    state = empty_triage_state.copy()
    state["classification"] = "TruePositive"
    state["incident_tactics"] = ["InitialAccess"]
    
    mock_llm_response = AsyncMock()
    mock_llm_response.content = '''
    ```json
    {
      "queries": [
        {
          "title": "Hunt Query",
          "table": "SigninLogs",
          "purpose": "Find stuff",
          "kql": "SigninLogs | limit 10"
        }
      ]
    }
    ```
    '''
    
    with patch("nodes.kql_node.ChatGoogleGenerativeAI.ainvoke", return_value=mock_llm_response):
        result = await kql_node(state)
        assert len(result["kql_queries"]) == 1
        assert "SigninLogs | limit 10" in result["kql_queries"][0]

@pytest.mark.asyncio
async def test_kql_node_escaping(empty_triage_state):
    """Asserts injected entity values do not break KQL string generation."""
    # Since the LLM handles string generation, the test asserts the prompt parser
    # safely returns queries even if the LLM output contains escaped quotes.
    state = empty_triage_state.copy()
    state["classification"] = "TruePositive"
    
    mock_llm_response = AsyncMock()
    mock_llm_response.content = '''{"queries": [{"title": "T", "table": "T", "purpose": "P", "kql": "Table | where ip == \\"8.8.8.8\\""}]}'''
    
    with patch("nodes.kql_node.ChatGoogleGenerativeAI.ainvoke", return_value=mock_llm_response):
        result = await kql_node(state)
        assert 'where ip == "8.8.8.8"' in result["kql_queries"][0]
