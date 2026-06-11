import asyncio
import json
import time
from unittest.mock import AsyncMock, mock_open, patch

import aiohttp
import pytest
from aioresponses import aioresponses

import nodes.mitre_enrich_node
from nodes.mitre_enrich_node import (
    _download_stix_data,
    _ensure_stix_data,
    _parse_stix_json,
    _safe_mtime_age,
    mitre_enrich_node,
)

_VALID_BUNDLE = {
    "objects": [
        {
            "type": "attack-pattern",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1234"}
            ],
            "kill_chain_phases": [{"phase_name": "persistence"}],
            "name": "Mock Technique",
            "description": "Mock description",
            "x_mitre_data_sources": ["Mock Source"],
        }
    ]
}


@pytest.fixture(autouse=True)
def mock_stix_data():
    """Provides a small mock STIX dataset to avoid network calls during tests."""
    nodes.mitre_enrich_node._stix_cache.clear()
    nodes.mitre_enrich_node._stix_cache_time = 0.0
    nodes.mitre_enrich_node._stix_failure_time = 0.0
    nodes.mitre_enrich_node._stix_download_lock = asyncio.Lock()

    nodes.mitre_enrich_node._stix_cache["T1078"] = {
        "tactics": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
        ],
        "name": "Valid Accounts",
        "description": "Adversaries may obtain and abuse credentials...",
        "data_sources": [
            "Active Directory: Active Directory Object Modification",
            "User Account: User Account Modification",
        ],
    }
    nodes.mitre_enrich_node._stix_cache["T1078.001"] = {
        "tactics": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
        ],
        "name": "Default Accounts",
        "description": "Adversaries may obtain and abuse credentials of a default account...",
        "data_sources": ["User Account: User Account Modification"],
    }
    nodes.mitre_enrich_node._stix_cache["T1059"] = {
        "tactics": ["Execution"],
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands...",
        "data_sources": ["Command: Command Execution"],
    }
    nodes.mitre_enrich_node._stix_cache_time = time.time()

    yield
    nodes.mitre_enrich_node._stix_cache.clear()
    nodes.mitre_enrich_node._stix_cache_time = 0.0
    nodes.mitre_enrich_node._stix_failure_time = 0.0


@pytest.fixture
def empty_stix_cache():
    """Clears the (autouse-populated) cache so download/parse paths are exercised."""
    nodes.mitre_enrich_node._stix_cache.clear()
    nodes.mitre_enrich_node._stix_cache_time = 0.0
    nodes.mitre_enrich_node._stix_failure_time = 0.0
    yield


async def test_valid_technique_extraction():
    """Test extracting a valid technique ID from the analyst output."""
    state = {"mitre_techniques": [{"technique_id": "T1078", "confidence": 100}]}
    result = await mitre_enrich_node(state)  # type: ignore
    enrichments = result.get("mitre_enrichment", [])

    assert len(enrichments) == 1
    assert enrichments[0]["technique_id"] == "T1078"
    assert enrichments[0]["name"] == "Valid Accounts"
    assert enrichments[0]["tactic"] == "Defense Evasion"
    assert len(enrichments[0]["data_sources"]) == 2


async def test_sub_technique_extraction():
    """Test extracting a sub-technique ID from the incident title."""
    state = {
        "incident_title": "Suspicious Default Accounts (T1078.001) usage detected."
    }
    result = await mitre_enrich_node(state)  # type: ignore
    enrichments = result.get("mitre_enrichment", [])

    assert len(enrichments) == 1
    assert enrichments[0]["technique_id"] == "T1078.001"
    assert enrichments[0]["name"] == "Default Accounts"


async def test_multiple_technique_extraction():
    """Test extracting multiple distinct IDs from raw alerts (nested properties)."""
    state = {
        "raw_alerts": [
            {
                "properties": {
                    "alertDisplayName": "T1078 Valid Accounts Activity",
                    "description": "Also saw T1059 command execution",
                }
            }
        ]
    }
    result = await mitre_enrich_node(state)  # type: ignore
    enrichments = result.get("mitre_enrichment", [])

    assert len(enrichments) == 2
    tech_ids = [e["technique_id"] for e in enrichments]
    assert "T1078" in tech_ids
    assert "T1059" in tech_ids


async def test_unknown_technique_flagged_into_errors():
    """An ID not present in the bundle is reported as a warning, not fabricated."""
    state = {"incident_description": "User executed technique T9999"}
    result = await mitre_enrich_node(state)  # type: ignore

    assert result.get("mitre_enrichment", []) == []
    errors = result.get("errors", [])
    assert any("T9999" in e for e in errors)
    # Source was up, so this is a per-ID warning — not a degraded source.
    assert "degraded_sources" not in result


async def test_boundary_anchored_extraction():
    """ID-shaped substrings inside larger tokens must not be extracted."""
    state = {
        "incident_title": "HOST1234 contacted SERVERT1059 — true id is T1078",
    }
    result = await mitre_enrich_node(state)  # type: ignore
    enrichments = result.get("mitre_enrichment", [])

    tech_ids = [e["technique_id"] for e in enrichments]
    assert tech_ids == ["T1078"]  # neither T1234 nor T1059 leaked from substrings


async def test_deduplication():
    """Test that the same technique ID appearing multiple times is only queried once."""
    state = {
        "incident_title": "Activity T1078",
        "incident_description": "Repeated T1078",
        "raw_alerts": [{"properties": {"alertDisplayName": "T1078"}}],
        "mitre_techniques": [{"technique_id": "T1078"}],
    }
    result = await mitre_enrich_node(state)  # type: ignore
    enrichments = result.get("mitre_enrichment", [])

    assert len(enrichments) == 1
    assert enrichments[0]["technique_id"] == "T1078"


async def test_no_techniques_skips_bundle():
    """When no IDs are present the node returns empty enrichment without touching the bundle."""
    state = {
        "incident_title": "Benign sign-in",
        "incident_description": "no techniques here",
    }
    with patch(
        "nodes.mitre_enrich_node._ensure_stix_data", new_callable=AsyncMock
    ) as mock_ensure:
        result = await mitre_enrich_node(state)  # type: ignore
    mock_ensure.assert_not_awaited()
    assert result == {"mitre_enrichment": []}


async def test_source_down_sets_degraded_sources():
    """A whole-bundle outage is surfaced via degraded_sources, not fabricated data."""
    state = {"mitre_techniques": [{"technique_id": "T1078"}]}
    with patch(
        "nodes.mitre_enrich_node._ensure_stix_data",
        new_callable=AsyncMock,
        return_value=({}, "STIX Download Failed: Network timeout or client error"),
    ):
        result = await mitre_enrich_node(state)  # type: ignore

    assert result.get("mitre_enrichment", []) == []
    assert result.get("degraded_sources") == ["mitre_attack"]
    assert any("STIX Download Failed" in e for e in result.get("errors", []))


async def test_stale_fallback_enriches_but_flags_degraded():
    """Stale-but-usable bundle data still enriches, while flagging degradation."""
    state = {"mitre_techniques": [{"technique_id": "T1078"}]}
    stale = {
        "T1078": {
            "name": "Valid Accounts",
            "tactics": ["Persistence"],
            "data_sources": [],
        }
    }
    with patch(
        "nodes.mitre_enrich_node._ensure_stix_data",
        new_callable=AsyncMock,
        return_value=(
            stale,
            "STIX bundle is stale (refresh deferred after recent failure)",
        ),
    ):
        result = await mitre_enrich_node(state)  # type: ignore

    assert len(result.get("mitre_enrichment", [])) == 1
    assert result["mitre_enrichment"][0]["technique_id"] == "T1078"
    assert result.get("degraded_sources") == ["mitre_attack"]


async def test_ensure_stix_data_download_and_parse(empty_stix_cache):
    """Test downloading and parsing STIX data when cache is empty and file does not exist."""
    mock_stix = {
        "objects": [
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1234"}
                ],
                "kill_chain_phases": [{"phase_name": "persistence"}],
                "name": "Mock Technique",
                "description": "Mock description",
                "x_mitre_data_sources": ["Mock Source"],
            }
        ]
    }

    with (
        patch("os.path.exists", return_value=False),
        patch(
            "nodes.mitre_enrich_node._download_stix_data", new_callable=AsyncMock
        ) as mock_download,
        patch("builtins.open", mock_open(read_data=json.dumps(mock_stix))),
    ):
        stix_data, error = await _ensure_stix_data()

        mock_download.assert_awaited_once()
        assert error is None
        assert "T1234" in stix_data
        assert stix_data["T1234"]["name"] == "Mock Technique"
        assert stix_data["T1234"]["tactics"] == ["Persistence"]


async def test_ensure_stix_data_revoked_technique_skipped(empty_stix_cache):
    """Revoked/deprecated attack-patterns are not enriched."""
    mock_stix = {
        "objects": [
            {
                "type": "attack-pattern",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1086"}
                ],
                "kill_chain_phases": [{"phase_name": "execution"}],
                "name": "PowerShell (deprecated)",
            }
        ]
    }
    with (
        patch("os.path.exists", return_value=False),
        patch("nodes.mitre_enrich_node._download_stix_data", new_callable=AsyncMock),
        patch("builtins.open", mock_open(read_data=json.dumps(mock_stix))),
    ):
        stix_data, error = await _ensure_stix_data()

    # Empty parse is treated as a (self-healing) failure, never a success.
    assert stix_data == {}
    assert error is not None
    assert "T1086" not in stix_data


async def test_ensure_stix_data_download_failure(empty_stix_cache):
    """Download failure with no on-disk file returns an empty dict and an error."""
    with (
        patch("os.path.exists", return_value=False),
        patch(
            "nodes.mitre_enrich_node._download_stix_data",
            side_effect=aiohttp.ClientError("Network error"),
        ),
    ):
        stix_data, error = await _ensure_stix_data()
        assert stix_data == {}
        assert error == "STIX Download Failed: Network timeout or client error"


async def test_ensure_stix_data_parse_failure(empty_stix_cache):
    """Parse failure on a fresh cache file is caught and reported."""
    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.getmtime", return_value=time.time()),
        patch("os.remove"),
        patch("builtins.open", side_effect=json.JSONDecodeError("File error", "", 0)),
    ):
        stix_data, error = await _ensure_stix_data()
        assert stix_data == {}
        assert "Corrupted or missing JSON" in error


async def test_ensure_stix_data_stale_fallback(empty_stix_cache):
    """A failed refresh falls back to the stale on-disk bundle (graceful degradation)."""
    mock_stix = {
        "objects": [
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1234"}
                ],
                "kill_chain_phases": [{"phase_name": "persistence"}],
                "name": "Stale Technique",
                "description": "Stale description",
                "x_mitre_data_sources": ["Stale Source"],
            }
        ]
    }
    # File exists but is older than the TTL → refresh attempted; download fails.
    old_mtime = time.time() - (nodes.mitre_enrich_node.CACHE_TTL + 3600)
    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.getmtime", return_value=old_mtime),
        patch(
            "nodes.mitre_enrich_node._download_stix_data",
            side_effect=aiohttp.ClientError("Network error"),
        ),
        patch("builtins.open", mock_open(read_data=json.dumps(mock_stix))),
    ):
        stix_data, error = await _ensure_stix_data()

    assert "T1234" in stix_data  # stale data served
    assert error is not None  # but flagged as degraded


# ── _download_stix_data ───────────────────────────────────────────────────────


async def test_download_stix_data_writes_file(tmp_path, monkeypatch):
    """The downloader streams the body to the cache file via a temp + os.replace."""
    target = tmp_path / "enterprise-attack.json"
    monkeypatch.setattr(nodes.mitre_enrich_node, "STIX_CACHE_FILE", str(target))
    payload = json.dumps(_VALID_BUNDLE).encode()

    with aioresponses() as m:
        m.get(nodes.mitre_enrich_node.STIX_URL, status=200, body=payload)
        await _download_stix_data()

    assert target.read_bytes() == payload
    assert not (tmp_path / "enterprise-attack.json.tmp").exists()


async def test_download_stix_data_size_limit(tmp_path, monkeypatch):
    """Exceeding MAX_DOWNLOAD_SIZE raises ValueError and cleans up the temp file."""
    target = tmp_path / "enterprise-attack.json"
    monkeypatch.setattr(nodes.mitre_enrich_node, "STIX_CACHE_FILE", str(target))
    monkeypatch.setattr(nodes.mitre_enrich_node, "MAX_DOWNLOAD_SIZE", 4)

    with aioresponses() as m:
        m.get(nodes.mitre_enrich_node.STIX_URL, status=200, body=b"abcdefghij")
        with pytest.raises(ValueError):
            await _download_stix_data()

    assert not target.exists()
    assert not (tmp_path / "enterprise-attack.json.tmp").exists()


# ── _safe_mtime_age / _parse_stix_json hardening ──────────────────────────────


def test_safe_mtime_age_missing_file_returns_none():
    assert _safe_mtime_age("/no/such/file/anywhere.json") is None


def test_parse_stix_json_non_dict_root_raises(tmp_path):
    p = tmp_path / "bundle.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        _parse_stix_json(str(p))


def test_parse_stix_json_skips_and_guards(tmp_path):
    """Non-dict objects, non-attack-patterns, missing IDs, and None phases are handled."""
    bundle = {
        "objects": [
            "not-a-dict",
            {"type": "course-of-action"},
            {
                "type": "attack-pattern",
                "external_references": [{"source_name": "other", "external_id": "X"}],
                "name": "no mitre id",
            },
            {
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1000"}
                ],
                "kill_chain_phases": [
                    {},
                    {"phase_name": None},
                    {"phase_name": "execution"},
                ],
                "name": "ok",
            },
        ]
    }
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    result = _parse_stix_json(str(p))

    assert list(result.keys()) == ["T1000"]
    assert result["T1000"]["tactics"] == ["Execution"]  # empty/None phases dropped


# ── _ensure_stix_data degraded branches ───────────────────────────────────────


async def test_ensure_stix_data_recent_failure_no_file(empty_stix_cache):
    """A cached recent failure with nothing on disk degrades immediately."""
    nodes.mitre_enrich_node._stix_failure_time = time.time()
    with (
        patch("os.path.exists", return_value=False),
        patch(
            "nodes.mitre_enrich_node._download_stix_data", new_callable=AsyncMock
        ) as mock_download,
    ):
        stix_data, error = await _ensure_stix_data()

    mock_download.assert_not_awaited()  # negative cache prevents a retry storm
    assert stix_data == {}
    assert "recently" in error.lower()


async def test_ensure_stix_data_size_limit_no_file(empty_stix_cache):
    """A size-limit failure with no on-disk file returns empty + error."""
    with (
        patch("os.path.exists", return_value=False),
        patch(
            "nodes.mitre_enrich_node._download_stix_data",
            side_effect=ValueError("too big"),
        ),
    ):
        stix_data, error = await _ensure_stix_data()
    assert stix_data == {}
    assert "too big" in error


async def test_ensure_stix_data_oserror_stale_fallback(empty_stix_cache):
    """A disk/OS download error with a stale file falls back to that file, degraded."""
    old_mtime = time.time() - (nodes.mitre_enrich_node.CACHE_TTL + 3600)
    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.getmtime", return_value=old_mtime),
        patch(
            "nodes.mitre_enrich_node._download_stix_data",
            side_effect=OSError("disk full"),
        ),
        patch("builtins.open", mock_open(read_data=json.dumps(_VALID_BUNDLE))),
    ):
        stix_data, error = await _ensure_stix_data()

    assert "T1234" in stix_data
    assert "I/O error" in error
