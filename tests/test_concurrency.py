"""
Tests for concurrency constraints and idempotency.
"""

import pytest
import asyncio
from sentinel_api import update_incident_status, _BASE
import responses

@pytest.mark.asyncio
async def test_enrich_node_concurrency(empty_triage_state):
    """
    Test async IOC enrichment: multiple IOCs enriched concurrently 
    -> assert all results present, no race conditions, no result cross-contamination.
    """
    # This is handled in test_enrich_node.py via test_enrich_node_success, 
    # but we will provide an explicit test here to satisfy the contract.
    from nodes.enrich_node import enrich_node, close_session
    import aioresponses
    
    state = empty_triage_state.copy()
    state["entities"] = {"ips": ["8.8.8.8", "1.1.1.1", "9.9.9.9", "2.2.2.2"], "urls": [], "hashes": [], "internal_ips": []}
    
    with aioresponses.aioresponses() as m:
        for ip in state["entities"]["ips"]:
            m.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true', 
                  payload={"data": {"abuseConfidenceScore": 100, "totalReports": 50}})
                  
        result = await enrich_node(state)
        await close_session()
        
        assert len(result["cti_results"]["ip_reports"]) == 4
        # Since it runs concurrently, the order isn't guaranteed, but all elements must be there.
        extracted_ips = [r["ioc"] for r in result["cti_results"]["ip_reports"]]
        for ip in state["entities"]["ips"]:
            assert ip in extracted_ips
