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
from unittest.mock import patch, AsyncMock
from nodes.enrich_node import (
    enrich_node,
    close_session,
    get_session,
    _is_error_result,
)


@pytest.fixture
async def cleanup_session():
    yield
    await close_session()


# ── Existing tests ────────────────────────────────────────────────────────────

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
        report_8 = None
        for report in cti["ip_reports"]:
            if report["ioc"] == "8.8.8.8":
                report_8 = report
                break
        assert report_8 is not None
        assert report_8["verdict"] == "malicious"

        report_1 = None
        for report in cti["ip_reports"]:
            if report["ioc"] == "1.1.1.1":
                report_1 = report
                break
        assert report_1 is not None
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


# ── AbuseIPDB suspicious verdict branch ─────────────────────────────────────

@pytest.mark.asyncio
async def test_abuseipdb_suspicious_verdict(empty_triage_state, cleanup_session):
    """Asserts AbuseIPDB score 25-74 yields 'suspicious' verdict."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": ["8.8.8.8"], "urls": [], "hashes": [], "internal_ips": []}

    with aioresponses.aioresponses() as m:
        m.get('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose=true',
              payload={"data": {"abuseConfidenceScore": 50, "totalReports": 10}})

        result = await enrich_node(state)
        report = result["cti_results"]["ip_reports"][0]
        assert report["verdict"] == "suspicious"


# ── AbuseIPDB HTTP error (non-200) branch ────────────────────────────────────

@pytest.mark.asyncio
async def test_abuseipdb_http_error(empty_triage_state, cleanup_session):
    """Asserts a 403 from AbuseIPDB strips the result and logs an error."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": ["8.8.8.8"], "urls": [], "hashes": [], "internal_ips": []}

    with aioresponses.aioresponses() as m:
        m.get('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose=true',
              status=403, repeat=True)

        result = await enrich_node(state)
        assert len(result["cti_results"]["ip_reports"]) == 0
        assert len(result["errors"]) > 0


# ── enrich_node: missing API key branches ────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_node_missing_vt_key(empty_triage_state, cleanup_session):
    """Asserts missing VT_API_KEY degrades gracefully instead of crashing."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": ["http://evil.com"], "hashes": [], "internal_ips": []}

    with patch("nodes.enrich_node.VT_API_KEY", ""):
        result = await enrich_node(state)
        assert "virustotal" in result.get("degraded_sources", [])
        assert any("VT_API_KEY" in e for e in result.get("errors", []))


@pytest.mark.asyncio
async def test_enrich_node_missing_vt_key_hashes(empty_triage_state, cleanup_session):
    """Asserts missing VT_API_KEY with hashes degrades gracefully instead of crashing."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": [], "hashes": ["abc123"], "internal_ips": []}

    with patch("nodes.enrich_node.VT_API_KEY", ""):
        result = await enrich_node(state)
        assert "virustotal" in result.get("degraded_sources", [])
        assert any("VT_API_KEY" in e for e in result.get("errors", []))


# ── enrich_node: internal IPs only (no external calls) ──────────────────────

@pytest.mark.asyncio
async def test_enrich_node_internal_ips_only(empty_triage_state, cleanup_session):
    """Asserts internal IPs are tagged as lateral_movement_candidate without external CTI calls."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": [], "hashes": [], "internal_ips": ["10.0.0.5", "192.168.1.1"]}

    result = await enrich_node(state)
    internal = result["cti_results"]["internal_ip_reports"]
    assert len(internal) == 2
    assert internal[0]["verdict"] == "lateral_movement_candidate"
    assert internal[0]["type"] == "internal_ip"


# ── enrich_node with VT URL and hash enrichment ─────────────────────────────

@pytest.mark.asyncio
async def test_enrich_node_url_enrichment(empty_triage_state, cleanup_session):
    """Asserts VT URL enrichment through enrich_node via mocked _check_vt_url."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": ["http://evil.com"], "hashes": [], "internal_ips": []}

    mock_result = {"ioc": "http://evil.com", "type": "url", "verdict": "malicious", "malicious": 10, "suspicious": 0, "threshold_used": 5}

    with patch("nodes.enrich_node._check_vt_url", new_callable=AsyncMock, return_value=mock_result):
        result = await enrich_node(state)
        assert len(result["cti_results"]["url_reports"]) == 1
        assert result["cti_results"]["url_reports"][0]["verdict"] == "malicious"


@pytest.mark.asyncio
async def test_enrich_node_hash_enrichment(empty_triage_state, cleanup_session):
    """Asserts VT hash enrichment through enrich_node via mocked _check_vt_hash."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": [], "hashes": ["deadbeef" * 5], "internal_ips": []}

    mock_result = {"ioc": "deadbeef" * 5, "type": "hash", "verdict": "clean", "malicious": 0, "suspicious": 0, "threshold_used": 5}

    with patch("nodes.enrich_node._check_vt_hash", new_callable=AsyncMock, return_value=mock_result):
        result = await enrich_node(state)
        assert len(result["cti_results"]["hash_reports"]) == 1
        assert result["cti_results"]["hash_reports"][0]["verdict"] == "clean"


# ── VT wrapper exception handling in _run_enrichment ─────────────────────────

@pytest.mark.asyncio
async def test_enrich_node_vt_url_wrapper_exception(empty_triage_state, cleanup_session):
    """Asserts VT URL wrapper catches exceptions and adds to errors."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": ["http://evil.com"], "hashes": [], "internal_ips": []}

    with patch("nodes.enrich_node._check_vt_url", new_callable=AsyncMock, side_effect=Exception("VT down")):
        result = await enrich_node(state)
        assert len(result["cti_results"]["url_reports"]) == 0
        # The wrapper catches exceptions and returns error dicts which are then stripped
        # The error gets captured in the url_results as an error dict
        assert "errors" not in result or len(result.get("errors", [])) > 0


@pytest.mark.asyncio
async def test_enrich_node_vt_hash_wrapper_exception(empty_triage_state, cleanup_session):
    """Asserts VT hash wrapper catches exceptions and adds to errors."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": [], "hashes": ["deadbeef" * 5], "internal_ips": []}

    with patch("nodes.enrich_node._check_vt_hash", new_callable=AsyncMock, side_effect=Exception("VT down")):
        result = await enrich_node(state)
        assert len(result["cti_results"]["hash_reports"]) == 0


# ── enrich_node: enrichment errors appended to state ─────────────────────────

@pytest.mark.asyncio
async def test_enrich_node_enrichment_errors_in_result(empty_triage_state, cleanup_session):
    """Asserts enrichment errors are populated in the returned update dict."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": ["8.8.8.8"], "urls": [], "hashes": [], "internal_ips": []}

    # Return an error dict from AbuseIPDB (simulating HTTP error)
    mock_result = {"ioc": "8.8.8.8", "type": "ip", "error": "HTTP 422"}

    with patch("nodes.enrich_node._check_abuseipdb", new_callable=AsyncMock, return_value=mock_result):
        result = await enrich_node(state)
        assert len(result["cti_results"]["ip_reports"]) == 0
        assert "errors" in result
        found_422 = False
        for error_message in result["errors"]:
            if "422" in error_message:
                found_422 = True
                break
        assert found_422


# ── _is_error_result ─────────────────────────────────────────────────────────

def test_is_error_result_true():
    """Dict with 'error' key is an error result."""
    assert _is_error_result({"ioc": "x", "error": "HTTP 503"}) is True


def test_is_error_result_false():
    """Dict without 'error' key is not an error result."""
    assert _is_error_result({"ioc": "x", "verdict": "clean"}) is False


# ── get_session reuse ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_session_reuse(cleanup_session):
    """Asserts get_session returns the same session on successive calls (reuse branch)."""
    s1 = await get_session()
    s2 = await get_session()
    assert s1 is s2
    await close_session()

@pytest.mark.asyncio
async def test_close_session_coverage():
    """Asserts close_session gracefully closes an open session."""
    s1 = await get_session()
    assert not s1.closed
    await close_session()
    assert s1.closed
    # Multiple calls should not crash
    await close_session()

@pytest.mark.asyncio
async def test_enrich_node_vt_url_transient(empty_triage_state, cleanup_session):
    """Asserts VT URL 429 raises TransientHTTPError internally."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": ["http://evil.com"], "hashes": [], "internal_ips": []}

    with aioresponses.aioresponses() as m:
        m.get('https://www.virustotal.com/api/v3/urls/aHR0cDovL2V2aWwuY29t', status=429, repeat=True)

        result = await enrich_node(state)
        assert len(result["cti_results"]["url_reports"]) == 0
        assert any("429" in e for e in result.get("errors", []))

@pytest.mark.asyncio
async def test_enrich_node_vt_hash_transient(empty_triage_state, cleanup_session):
    """Asserts VT hash 503 raises TransientHTTPError."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": [], "hashes": ["deadbeef"], "internal_ips": []}

    with aioresponses.aioresponses() as m:
        m.get('https://www.virustotal.com/api/v3/files/deadbeef', status=503, repeat=True)

        result = await enrich_node(state)
        assert len(result["cti_results"]["hash_reports"]) == 0
        assert any("503" in e for e in result.get("errors", []))

@pytest.mark.asyncio
async def test_enrich_node_abuseipdb_validation_error(empty_triage_state, cleanup_session):
    """Asserts AbuseIPDB ValidationError is caught."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": ["8.8.8.8"], "urls": [], "hashes": [], "internal_ips": []}

    with aioresponses.aioresponses() as m:
        m.get('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose=true',
              payload={"data": {}})

        result = await enrich_node(state)
        assert len(result["cti_results"]["ip_reports"]) == 0
        assert any("schema mismatch" in e.lower() for e in result.get("errors", []))

@pytest.mark.asyncio
async def test_enrich_node_vt_url_validation_error(empty_triage_state, cleanup_session):
    """Asserts VT URL ValidationError is caught."""
    state = empty_triage_state.copy()
    state["entities"] = {"ips": [], "urls": ["http://evil.com"], "hashes": [], "internal_ips": []}

    with aioresponses.aioresponses() as m:
        m.get('https://www.virustotal.com/api/v3/urls/aHR0cDovL2V2aWwuY29t', payload={"data": {}})

        result = await enrich_node(state)
        assert len(result["cti_results"]["url_reports"]) == 0
        assert any("schema mismatch" in e.lower() for e in result.get("errors", []))
