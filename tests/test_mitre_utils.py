"""
Behavioral Contract for mitre_utils.py

Valid Input:
- normalize_tactic: Raw tactic strings from Sentinel (e.g., "InitialAccess", "credentialaccess").
- validate_and_enrich_techniques: List of technique dicts from LLM output + incident tactics list.

Expected Output:
- normalize_tactic: Standardized MITRE ATT&CK tactic names.
- validate_and_enrich_techniques: Verified/enriched technique list + non-fatal warnings.

Failure Modes:
- Invalid technique ID format: Attempts name-based resolution, discards if unresolvable.
- Technique not in catalog: Preserved with 'unverified' flag.
"""

from nodes.mitre_utils import (TECHNIQUE_ID_PATTERN, _resolve_id_by_name,
                               normalize_tactic,
                               validate_and_enrich_techniques)

# ── normalize_tactic ──────────────────────────────────────────────────────────


def test_normalize_tactic_empty():
    """Empty string returns 'Unknown'."""
    assert normalize_tactic("") == "Unknown"


def test_normalize_tactic_sentinel_format():
    """Sentinel's PascalCase format is normalized."""
    assert normalize_tactic("InitialAccess") == "Initial Access"
    assert normalize_tactic("CredentialAccess") == "Credential Access"
    assert normalize_tactic("LateralMovement") == "Lateral Movement"


def test_normalize_tactic_lowercase():
    """Lowercase with no separators is normalized."""
    assert normalize_tactic("execution") == "Execution"


def test_normalize_tactic_unknown_falls_through():
    """Unknown tactic strings get title-cased as fallback."""
    assert normalize_tactic("some_custom_tactic") == "Some_Custom_Tactic"


# ── _resolve_id_by_name ──────────────────────────────────────────────────────


def test_resolve_id_by_name_found():
    """Known technique name resolves to (id, official_name)."""
    result = _resolve_id_by_name("Brute Force")
    assert result is not None
    assert result[0] == "T1110"
    assert result[1] == "Brute Force"


def test_resolve_id_by_name_case_insensitive():
    """Name resolution is case-insensitive."""
    result = _resolve_id_by_name("brute force")
    assert result is not None
    assert result[0] == "T1110"


def test_resolve_id_by_name_not_found():
    """Unknown technique name returns None."""
    assert _resolve_id_by_name("Totally Made Up Technique") is None


# ── validate_and_enrich_techniques ────────────────────────────────────────────


def test_validate_known_technique():
    """Valid catalog technique is verified with official name and tactic."""
    techs = [{"technique_id": "T1078", "name": "Valid Accounts", "confidence": 90}]
    verified, warnings = validate_and_enrich_techniques(techs, ["InitialAccess"])

    assert len(verified) == 1
    assert verified[0]["technique_id"] == "T1078"
    assert verified[0]["name"] == "Valid Accounts"
    assert verified[0]["tactic"] == "Initial Access"
    assert "unverified" not in verified[0]
    assert len(warnings) == 0


def test_validate_invalid_id_name_resolved():
    """Invalid ID format but known name auto-corrects the ID."""
    techs = [{"technique_id": "INVALID", "name": "Brute Force", "confidence": 80}]
    verified, warnings = validate_and_enrich_techniques(techs, [])

    assert len(verified) == 1
    assert verified[0]["technique_id"] == "T1110"
    assert len(warnings) == 0


def test_validate_invalid_id_name_unresolved():
    """Invalid ID + unknown name discards the technique with a warning."""
    techs = [{"technique_id": "INVALID", "name": "Made Up", "confidence": 50}]
    verified, warnings = validate_and_enrich_techniques(techs, [])

    assert len(verified) == 0
    assert len(warnings) == 1
    assert "Discarded" in warnings[0]


def test_validate_duplicate_techniques():
    """Duplicate technique IDs are deduplicated."""
    techs = [
        {"technique_id": "T1078", "name": "Valid Accounts", "confidence": 90},
        {"technique_id": "T1078", "name": "Valid Accounts", "confidence": 85},
    ]
    verified, warnings = validate_and_enrich_techniques(techs, [])

    assert len(verified) == 1


def test_validate_unknown_catalog_technique():
    """Valid ID format but not in catalog is preserved with unverified flag."""
    techs = [
        {
            "technique_id": "T9999",
            "name": "Custom Tech",
            "confidence": 60,
            "tactic": "Execution",
        }
    ]
    verified, warnings = validate_and_enrich_techniques(techs, [])

    assert len(verified) == 1
    assert verified[0]["unverified"] is True
    assert verified[0]["name"] == "Custom Tech"


def test_validate_non_dict_item():
    """Non-dict entries in the list are silently skipped."""
    techs = ["not a dict", 42, None]
    verified, warnings = validate_and_enrich_techniques(techs, [])  # type: ignore[arg-type]

    assert len(verified) == 0
    assert len(warnings) == 0


def test_validate_name_autocorrect():
    """Known ID with incorrect name auto-corrects to official name."""
    techs = [
        {"technique_id": "T1078", "name": "Valids Accountz (typo)", "confidence": 90}
    ]
    verified, warnings = validate_and_enrich_techniques(techs, [])

    assert len(verified) == 1
    assert verified[0]["name"] == "Valid Accounts"  # auto-corrected


def test_validate_tactic_not_in_incident():
    """Technique whose tactic isn't in incident_tactics is still verified (with debug log)."""
    techs = [{"technique_id": "T1110", "name": "Brute Force", "confidence": 80}]
    # Incident has InitialAccess, but T1110 maps to Credential Access
    verified, warnings = validate_and_enrich_techniques(techs, ["InitialAccess"])

    assert len(verified) == 1
    assert verified[0]["tactic"] == "Credential Access"


def test_validate_underscore_id_formatting():
    """Technique IDs with underscores are normalized to dots."""
    techs = [
        {"technique_id": "T1078_001", "name": "Default Accounts", "confidence": 70}
    ]
    verified, warnings = validate_and_enrich_techniques(techs, [])

    assert len(verified) == 1
    assert verified[0]["technique_id"] == "T1078.001"
