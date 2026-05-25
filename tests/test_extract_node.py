"""
Behavioral Contract for extract_node.py

Valid Input:
- A TriageState dictionary containing 'condensed_summary'.

Expected Output:
- Returns a dict with 'entities' containing 'ips', 'internal_ips', 'urls', 'hashes', 'usernames', 'hostnames', 'domains'.
- Uses regex for structural IOCs (IPs, hashes, URLs) and LLM for contextual ones.

Failure Modes:
- LLM extraction failure (e.g., malformed JSON response, 503): Gracefully falls back to regex-only results. The LLM fields default to empty lists, avoiding AttributeError or JSONDecodeError crashes.

Concurrency Invariants:
- N/A (Stateless async processing).
"""

import pytest
from unittest.mock import patch, AsyncMock
from nodes.extract_node import extract_node

@pytest.mark.asyncio
async def test_extract_node_success(empty_triage_state):
    """Asserts valid IOC extraction combining regex and LLM outputs."""
    summary = "User admin@corp.local logged in from 8.8.8.8 and downloaded http://evil.com/malware.exe with hash 11111111111111111111111111111111. Internal traffic from 10.0.0.5."
    state = empty_triage_state.copy()
    state["condensed_summary"] = summary
    
    mock_llm_response = AsyncMock()
    mock_llm_response.content = '{"usernames": ["admin@corp.local"], "hostnames": [], "domains": ["evil.com"]}'
    
    with patch("nodes.extract_node.ChatGoogleGenerativeAI.ainvoke", return_value=mock_llm_response):
        result = await extract_node(state)
        
        entities = result["entities"]
        assert "8.8.8.8" in entities["ips"]
        assert "10.0.0.5" in entities["internal_ips"]
        assert "http://evil.com/malware.exe" in entities["urls"]
        assert "11111111111111111111111111111111" in entities["hashes"]
        assert "admin@corp.local" in entities["usernames"]
        assert "evil.com" in entities["domains"]

@pytest.mark.asyncio
async def test_extract_node_llm_failure_fallback(empty_triage_state):
    """Asserts LLM failure (invalid JSON) gracefully degrades to regex-only extraction."""
    summary = "Activity from 8.8.8.8"
    state = empty_triage_state.copy()
    state["condensed_summary"] = summary
    
    mock_llm_response = AsyncMock()
    mock_llm_response.content = 'THIS IS NOT VALID JSON'
    
    with patch("nodes.extract_node.ChatGoogleGenerativeAI.ainvoke", return_value=mock_llm_response):
        result = await extract_node(state)
        
        entities = result["entities"]
        assert "8.8.8.8" in entities["ips"]
        assert isinstance(entities["usernames"], list)
        assert len(entities["usernames"]) == 0
