"""
Behavioral Contract for extract_node.py

Valid Input:
- A TriageState dictionary containing 'condensed_summary' and 'raw_alerts'.

Expected Output:
- Returns a dict with 'entities' containing 'ips', 'internal_ips', 'urls', 'hashes', 'usernames', 'hostnames', 'domains'.
- Uses structured entity fields from ALL raw_alerts for IPs, hashes, URLs.
- Uses regex on condensed_summary as fallback coverage.
- Uses LLM for contextual entities (usernames, hostnames, domains).

Failure Modes:
- LLM extraction failure (e.g., malformed JSON response, 503): Gracefully falls back to regex-only results. The LLM fields default to empty lists, avoiding AttributeError or JSONDecodeError crashes.

Concurrency Invariants:
- N/A (Stateless async processing).
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from nodes.extract_node import extract_node

@pytest.mark.asyncio
async def test_extract_node_success(empty_triage_state):
    """Asserts valid IOC extraction combining regex and LLM outputs."""
    summary = "User admin@corp.local logged in from 8.8.8.8 and downloaded http://evil.com/malware.exe with hash 11111111111111111111111111111111. Internal traffic from 10.0.0.5."
    state = empty_triage_state.copy()
    state["condensed_summary"] = summary
    
    mock_llm_response = AsyncMock()
    mock_llm_response.content = '{"usernames": ["admin@corp.local"], "hostnames": [], "domains": ["evil.com"]}'

    mock_llm_instance = MagicMock()
    mock_llm_instance.ainvoke = AsyncMock(return_value=mock_llm_response)

    with patch("langchain_google_genai.ChatGoogleGenerativeAI", return_value=mock_llm_instance):
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

    mock_llm_instance = MagicMock()
    mock_llm_instance.ainvoke = AsyncMock(return_value=mock_llm_response)

    with patch("langchain_google_genai.ChatGoogleGenerativeAI", return_value=mock_llm_instance):
        result = await extract_node(state)
        
        entities = result["entities"]
        assert "8.8.8.8" in entities["ips"]
        assert isinstance(entities["usernames"], list)
        assert len(entities["usernames"]) == 0

@pytest.mark.asyncio
async def test_extract_node_raw_alerts_beyond_cap(empty_triage_state):
    """Asserts IOCs from alerts beyond the summarize_node 5-alert cap are extracted."""
    state = empty_triage_state.copy()
    # condensed_summary has NO IOCs — simulates the cap discarding later alerts
    state["condensed_summary"] = "Generic incident with no inline indicators."
    # raw_alerts contains 7 alerts; alerts 6 and 7 have unique IOCs
    state["raw_alerts"] = [
        {"properties": {"alertDisplayName": f"Alert {i}", "description": "noise", "entities": []}}
        for i in range(5)
    ] + [
        {
            "properties": {
                "alertDisplayName": "Alert 5 - lateral movement",
                "description": "Connection to 192.168.1.50 observed",
                "entities": [
                    {"Type": "ip", "Address": "45.33.32.156"},
                    {"Type": "host", "HostName": "SRV-DC-01"},
                ],
            }
        },
        {
            "properties": {
                "alertDisplayName": "Alert 6 - malware hash",
                "description": "Payload downloaded",
                "entities": [
                    {"Type": "filehash", "Value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                    {"Type": "ip", "Address": "10.0.0.99"},
                ],
            }
        },
    ]

    mock_llm_response = AsyncMock()
    mock_llm_response.content = '{"usernames": [], "hostnames": [], "domains": []}'

    mock_llm_instance = MagicMock()
    mock_llm_instance.ainvoke = AsyncMock(return_value=mock_llm_response)

    with patch("langchain_google_genai.ChatGoogleGenerativeAI", return_value=mock_llm_instance):
        result = await extract_node(state)

        entities = result["entities"]
        # Public IP from alert 6's structured entity — beyond the 5-alert cap
        assert "45.33.32.156" in entities["ips"]
        # Internal IP from alert 7's structured entity
        assert "10.0.0.99" in entities["internal_ips"]
        # Hash from alert 7's structured entity
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in entities["hashes"]


