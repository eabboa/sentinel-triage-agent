"""
Behavioral Contract for containment_node.py

Valid Input:
- TriageState containing 'containment_approved': True and 'entities' with
  hostnames/internal IPs (device isolation) and/or usernames (session revocation).

Expected Output:
- Resolves valid hostnames/IPs to MDE machine IDs and triggers isolation.
- Revokes Entra ID sessions for valid user identities (UPNs / object-ID GUIDs).
- Returns empty dict and appends no errors on success.

Failure Modes:
- Invalid hostname formats are rejected via regex before any API call is made.
- Non-revocable user identities (bare usernames, SAM names) are rejected before
  any Graph call and recorded in errors.
- If machine ID resolution fails, it skips isolation for that device, logs an error, and continues to the next.
- If isolation or revocation API fails, logs error, appends to errors list, and continues.

Concurrency Invariants:
- Awaits sequentially.
"""

from unittest.mock import AsyncMock, patch

import pytest

from nodes.containment_node import containment_node, preview_containment_targets


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


# ── Entra ID session revocation ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_containment_node_revokes_valid_users(empty_triage_state):
    """Asserts valid UPNs and object-ID GUIDs have their sessions revoked."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {
        "usernames": ["alice@corp.com", "11111111-2222-3333-4444-555555555555"]
    }

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        mock_revoke.return_value = {"value": True}

        result = await containment_node(state)
        assert len(result.get("errors", [])) == 0
        assert mock_revoke.call_count == 2
        mock_revoke.assert_any_await("alice@corp.com")
        mock_revoke.assert_any_await("11111111-2222-3333-4444-555555555555")


@pytest.mark.asyncio
async def test_containment_node_skips_non_revocable_identities(empty_triage_state):
    """Asserts SAM names and bare usernames are rejected before any Graph call."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"usernames": ["CORP\\bob", "plainname", "../../etc/passwd"]}

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        result = await containment_node(state)
        assert len(result["errors"]) == 3
        assert all("non-revocable user identity" in e for e in result["errors"])
        mock_revoke.assert_not_called()


@pytest.mark.asyncio
async def test_containment_node_revocation_api_failure(empty_triage_state):
    """Asserts a revocation API failure is captured as error and continues."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"usernames": ["alice@corp.com", "bob@corp.com"]}

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        # First user fails, second succeeds — the loop must not abort early.
        mock_revoke.side_effect = [Exception("Graph API timeout"), {"value": True}]

        result = await containment_node(state)
        assert mock_revoke.call_count == 2
        revocation_errors = [
            e for e in result["errors"] if "Entra session revocation failed" in e
        ]
        assert len(revocation_errors) == 1
        assert "alice@corp.com" in revocation_errors[0]


@pytest.mark.asyncio
async def test_containment_node_isolation_and_revocation_together(empty_triage_state):
    """Asserts a mixed incident runs BOTH device isolation and session revocation."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {
        "hostnames": ["valid-host"],
        "internal_ips": [],
        "usernames": ["alice@corp.com"],
    }

    with (
        patch(
            "nodes.containment_node.resolve_mde_machine_id", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "nodes.containment_node.isolate_mde_device", new_callable=AsyncMock
        ) as mock_isolate,
        patch(
            "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
        ) as mock_revoke,
    ):
        mock_resolve.return_value = "machine-id-123"
        mock_isolate.return_value = {"status": "Isolated"}
        mock_revoke.return_value = {"value": True}

        result = await containment_node(state)
        assert len(result.get("errors", [])) == 0
        mock_isolate.assert_awaited_once()
        mock_revoke.assert_awaited_once_with("alice@corp.com")


@pytest.mark.asyncio
async def test_containment_node_unapproved_skips_revocation(empty_triage_state):
    """Asserts revocation does not run when containment is unapproved."""
    state = empty_triage_state.copy()
    state["containment_approved"] = False
    state["entities"] = {"usernames": ["alice@corp.com"]}

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        result = await containment_node(state)
        assert len(result.get("errors", [])) == 0
        mock_revoke.assert_not_called()


@pytest.mark.asyncio
async def test_containment_node_rejects_percent_encoded_upn(empty_triage_state):
    """Security regression: percent-encoded path separators must NOT be revoked.

    `victim%2f..%2fattacker@corp.com` would otherwise smuggle '/' into the Graph
    URL path, and `a%23@corp.com` would truncate the action suffix as a fragment.
    """
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {
        "usernames": ["victim%2f..%2fattacker@corp.com", "a%23@corp.com"]
    }

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        result = await containment_node(state)
        mock_revoke.assert_not_called()
        assert len(result["errors"]) == 2
        assert all("non-revocable user identity" in e for e in result["errors"])


@pytest.mark.asyncio
async def test_containment_node_rejects_trailing_newline_identity(empty_triage_state):
    """Asserts a trailing newline does not slip past validation (\\A...\\Z anchors)."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {
        "usernames": [
            "alice@corp.com\n",
            "11111111-2222-3333-4444-555555555555\n",
        ]
    }

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        result = await containment_node(state)
        mock_revoke.assert_not_called()
        assert len(result["errors"]) == 2


@pytest.mark.asyncio
async def test_containment_node_dedupes_usernames(empty_triage_state):
    """Asserts a username repeated across alerts is revoked exactly once."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"usernames": ["alice@corp.com", "alice@corp.com"]}

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        mock_revoke.return_value = {"value": True}
        result = await containment_node(state)
        assert len(result.get("errors", [])) == 0
        assert mock_revoke.call_count == 1


@pytest.mark.asyncio
async def test_containment_node_accepts_uppercase_guid(empty_triage_state):
    """Asserts object-ID GUIDs are accepted case-insensitively (hex a-fA-F)."""
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {"usernames": ["AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"]}

    with patch(
        "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
    ) as mock_revoke:
        mock_revoke.return_value = {"value": True}
        result = await containment_node(state)
        assert len(result.get("errors", [])) == 0
        mock_revoke.assert_awaited_once_with("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")


@pytest.mark.asyncio
async def test_containment_node_aggregates_errors_from_both_loops(empty_triage_state):
    """Asserts failures from BOTH isolation and revocation land in one error list.

    Both loops must run to completion and append into the single append-only list.
    """
    state = empty_triage_state.copy()
    state["containment_approved"] = True
    state["entities"] = {
        "hostnames": ["valid-host"],
        "usernames": ["alice@corp.com"],
    }

    with (
        patch(
            "nodes.containment_node.resolve_mde_machine_id", new_callable=AsyncMock
        ) as mock_resolve,
        patch(
            "nodes.containment_node.isolate_mde_device", new_callable=AsyncMock
        ) as mock_isolate,
        patch(
            "nodes.containment_node.revoke_entra_sessions", new_callable=AsyncMock
        ) as mock_revoke,
    ):
        mock_resolve.return_value = "machine-id-123"
        mock_isolate.side_effect = Exception("MDE API timeout")
        mock_revoke.side_effect = Exception("Graph API timeout")

        result = await containment_node(state)
        assert mock_isolate.await_count == 1
        assert mock_revoke.await_count == 1
        assert any("MDE isolation failed" in e for e in result["errors"])
        assert any("Entra session revocation failed" in e for e in result["errors"])


def test_preview_containment_targets_returns_only_validated():
    """preview_containment_targets surfaces exactly what the node will act on."""
    entities = {
        "hostnames": ["valid-host", "../../etc/passwd"],
        "internal_ips": ["10.0.0.1"],
        "usernames": ["alice@corp.com", "CORP\\bob", "victim%2f..%2fx@corp.com"],
    }
    isolation, revocation = preview_containment_targets(entities)
    assert isolation == ["valid-host", "10.0.0.1"]
    assert revocation == ["alice@corp.com"]
