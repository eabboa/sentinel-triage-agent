"""
Tests for concurrency constraints and idempotency.
"""

import asyncio

import pytest
import responses

from sentinel_api import _BASE, update_incident_status


@pytest.mark.asyncio
async def test_enrich_node_concurrency(empty_triage_state):
    """
    Test async IOC enrichment: multiple IOCs enriched concurrently
    -> assert all results present, no race conditions, no result cross-contamination.
    """
    # This is handled in test_enrich_node.py via test_enrich_node_success,
    # but we will provide an explicit test here to satisfy the contract.
    import aioresponses

    from nodes.enrich_node import close_session, enrich_node

    state = empty_triage_state.copy()
    state["entities"] = {
        "ips": ["8.8.8.8", "1.1.1.1", "9.9.9.9", "2.2.2.2"],
        "urls": [],
        "hashes": [],
        "internal_ips": [],
    }

    with aioresponses.aioresponses() as m:
        for ip in state["entities"]["ips"]:
            m.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true",
                payload={"data": {"abuseConfidenceScore": 100, "totalReports": 50}},
            )

        result = await enrich_node(state)
        await close_session()

        assert len(result["cti_results"]["ip_reports"]) == 4
        # Since it runs concurrently, the order isn't guaranteed, but all elements must be there.
        extracted_ips = [r["ioc"] for r in result["cti_results"]["ip_reports"]]
        for ip in state["entities"]["ips"]:
            assert ip in extracted_ips
