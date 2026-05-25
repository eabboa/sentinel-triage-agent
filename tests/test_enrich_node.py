"""
Behavioral Contract for enrich_node.py

Valid Input:
- A TriageState dictionary containing 'entities' (ips, urls, hashes).

Expected Output:
- Asynchronously fetches threat intel for each entity using VirusTotal and AbuseIPDB.
- Returns a dict with 'cti_results' containing strictly successful lookups grouped by type.
- Identifies internal_ips as lateral movement candidates.

Failure Modes:
- CTI provider transient failure (429, 503, timeout): Tenacity retries the request. If all retries fail, it degrades gracefully. The failed entity is excluded from 'cti_results' to prevent LLM hallucinations, and an error string is appended to the state's 'errors' list.
- Empty entity list: Returns an empty cti_results structure without making any external calls.

Concurrency Invariants:
- Uses asyncio.gather to concurrently process multiple IOCs without race conditions or state cross-contamination.
- aiolimiter ensures VirusTotal rate limits are strictly respected even when concurrently bursting.
"""

import pytest
import aioresponses
from nodes.enrich_node import enrich_node, close_session

@pytest.fixture
async def cleanup_session():
    yield
    await close_session()

@pytest.mark.asyncio
async def test_enrich_node_success(empty_triage_state, cleanup_session):
    """Asserts concurrent IOC enrichment yields correct results without cross-contamination."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": ["8.8.8.8", "1.1.1.1"], "urls": [], "hashes": [], "internal_ips": []}
    
    with aioresponses.aioresponses() as m:
        # Mock successful AbuseIPDB responses
        m.get('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose=true', 
              payload={"data": {"abuseConfidenceScore": 100, "totalReports": 50}})
        m.get('https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=90&verbose=true', 
              payload={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
              
        result = await enrich_node(state)
        
        cti = result["cti_results"]
        assert len(cti["ip_reports"]) == 2
        
        # Verify specific results match specific IPs (no cross-contamination)
        report_8 = next(r for r in cti["ip_reports"] if r["ioc"] == "8.8.8.8")
        assert report_8["verdict"] == "malicious"
        
        report_1 = next(r for r in cti["ip_reports"] if r["ioc"] == "1.1.1.1")
        assert report_1["verdict"] == "clean"

@pytest.mark.asyncio
async def test_enrich_node_failure_graceful_degradation(empty_triage_state, cleanup_session):
    """Asserts an API failure strips the result from CTI payload and adds to errors list."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": ["8.8.8.8"], "urls": [], "hashes": [], "internal_ips": []}
    
    with aioresponses.aioresponses() as m:
        # Mock repeated 503 failures
        m.get('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose=true', 
              status=503, repeat=True)
              
        result = await enrich_node(state)
        
        # Must be empty to avoid LLM hallucination
        assert len(result["cti_results"]["ip_reports"]) == 0
        assert len(result["errors"]) > 0
        assert "503" in result["errors"][0]

@pytest.mark.asyncio
async def test_enrich_node_empty_entities(empty_triage_state, cleanup_session):
    """Asserts empty entities return default structure without KeyError."""
    state = empty_triage_state.copy()
    state["entities"] = {}
    
    result = await enrich_node(state)
    assert "ip_reports" in result["cti_results"]
    assert len(result["cti_results"]["ip_reports"]) == 0
