"""
Behavioral Contract for containment_node.py

Valid Input:
- TriageState containing 'containment_approved': True and 'entities' with hostnames/internal IPs.

Expected Output:
- Resolves valid hostnames/IPs to MDE machine IDs and triggers isolation.
- Returns empty dict and appends no errors on success.

Failure Modes:
- Invalid hostname formats are rejected via regex before any API call is made.
- If machine ID resolution fails, it skips isolation for that device, logs an error, and continues to the next.
- If isolation API fails, logs error, appends to errors list, and continues.

Concurrency Invariants:
- Awaits sequentially.
"""

from unittest.mock import AsyncMock, patch

import pytest

from nodes.containment_node import containment_node


@pytest.mark.asyncio
async def test_containment_node_unapproved(empty_triage_state):
    """Asserts containment does not run if unapproved."""
    state = empty_triage_state.copy()
    state["containment_approved"] = False

    with patch("nodes.containment_node.resolve_mde_machine_id") as mock_resolve:
        result = await containment_node(state)
        assert len(result.get("errors", [])) == 0
        mock_resolve.assert_not_called()


@pytest.mark.asyncio
async def test_containment_node_success(empty_triage_state):
    """Asserts containment isolates valid hostnames."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"hostnames": ["valid-host"], "internal_ips": ["10.0.0.1"]}

    with (
        patch(
            "nodes.containment_node.resolve_mde_machine_id", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "nodes.containment_node.isolate_mde_device", new_callable=AsyncMock
        ) as mock_isolate,
    ):

        mock_resolve.side_effect = ["valid-machine-id-1", "valid-machine-id-2"]
        mock_isolate.return_value = {"status": "Isolated"}

        result = await containment_node(state)
        assert len(result.get("errors", [])) == 0
        assert mock_resolve.call_count == 2
        assert mock_isolate.call_count == 2


@pytest.mark.asyncio
async def test_containment_node_injection_prevention(empty_triage_state):
    """Asserts path traversal and malicious hostnames are rejected."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"hostnames": ["../../etc/passwd", "host; rm -rf /"]}

    with patch(
        "nodes.containment_node.resolve_mde_machine_id", new_callable=AsyncMock
    ) as mock_resolve:
        result = await containment_node(state)
        assert len(result["errors"]) == 2
        assert "Rejected unsafe isolation target" in result["errors"][0]
        mock_resolve.assert_not_called()


@pytest.mark.asyncio
async def test_containment_node_machine_not_found(empty_triage_state):
    """Asserts unresolvable hostname logs warning and skips isolation."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"hostnames": ["unknown-host"], "internal_ips": []}

    with (
        patch(
            "nodes.containment_node.resolve_mde_machine_id", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "nodes.containment_node.isolate_mde_device", new_callable=AsyncMock
        ) as mock_isolate,
    ):

        mock_resolve.return_value = None  # Device not found
        result = await containment_node(state)

        found_not_found_error = False
        for error_message in result["errors"]:
            if "not found" in error_message:
                found_not_found_error = True
                break
        assert found_not_found_error
        mock_isolate.assert_not_called()


@pytest.mark.asyncio
async def test_containment_node_isolation_api_failure(empty_triage_state):
    """Asserts isolation API failure is captured as error and continues."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"hostnames": ["valid-host"], "internal_ips": []}

    with (
        patch(
            "nodes.containment_node.resolve_mde_machine_id", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "nodes.containment_node.isolate_mde_device", new_callable=AsyncMock
        ) as mock_isolate,
    ):

        mock_resolve.return_value = "machine-id-123"
        mock_isolate.side_effect = Exception("MDE API timeout")

        result = await containment_node(state)
        found_isolation_error = False
        for error_message in result["errors"]:
            if "MDE isolation failed" in error_message:
                found_isolation_error = True
                break
        assert found_isolation_error


@pytest.mark.asyncio
async def test_containment_node_no_valid_targets(empty_triage_state):
    """Asserts empty hostnames and internal_ips skips isolation entirely."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"hostnames": [], "internal_ips": []}

    with patch(
        "nodes.containment_node.resolve_mde_machine_id", new_callable=AsyncMock
    ) as mock_resolve:
        result = await containment_node(state)
        assert len(result["errors"]) == 0
        mock_resolve.assert_not_called()
