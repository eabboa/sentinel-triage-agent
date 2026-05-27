"""
Shared fixtures for all test modules.

CRITICAL: The os.environ mutations MUST happen at the module scope (import time),
not inside fixtures. sentinel_api.py validates SUBSCRIPTION_ID, RESOURCE_GROUP, and
WORKSPACE_NAME at module-level import. If these variables are missing when Python
first imports sentinel_api, the import itself raises EnvironmentError — before any
pytest fixture has a chance to run.
"""

import os

# ── Module-level env var injection ──────────────────────────────────────────────
# These must be set BEFORE any sentinel_api import occurs during test collection.
_TEST_ENV_VARS = {
    "VT_API_KEY": "mock_vt_key",
    "ABUSEIPDB_API_KEY": "mock_abuseipdb_key",
    "GOOGLE_API_KEY": "mock_google_key",
    "SUBSCRIPTION_ID": "mock_sub",
    "RESOURCE_GROUP": "mock_rg",
    "WORKSPACE_NAME": "mock_ws",
    "CHROMA_HOST": "localhost",
    "CHROMA_PORT": "8000",
}

for key, value in _TEST_ENV_VARS.items():
    if not os.environ.get(key):
        os.environ[key] = value

# ── Now safe to import application modules ──────────────────────────────────────
import pytest
from state import TriageState
from models.validation import AnalystVerdict, MitreTechnique


@pytest.fixture
def empty_triage_state() -> TriageState:
    """Returns a completely empty TriageState instance with safe defaults."""
    return {
        "incident_id": "test_id",
        "incident_title": "",
        "incident_severity": "",
        "incident_description": "",
        "incident_status": "",
        "incident_tactics": [],
        "raw_alerts": [],
        "condensed_summary": "",
        "entities": {},
        "cti_results": {},
        "is_true_positive": False,
        "classification": "",
        "confidence": 0,
        "triage_summary": "",
        "mitre_analysis": "",
        "mitre_techniques": [],
        "kql_queries": [],
        "comment_posted": False,
        "incident_closed": False,
        "close_approved": False,
        "containment_approved": False,
        "escalation_triggered": False,
        "escalation_summary": "",
        "human_classification": None,
        "human_classification_reason": None,
        "errors": [],
    }


@pytest.fixture
def valid_analyst_verdict() -> AnalystVerdict:
    """Returns a valid Pydantic AnalystVerdict model instance."""
    return AnalystVerdict(
        classification="TruePositive",
        is_true_positive=True,
        triage_summary="Valid malicious activity detected.",
        mitre_analysis="Matched Execution tactic.",
        mitre_techniques=[
            MitreTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                confidence=90,
                tactic="Execution",
            )
        ],
        confidence=95,
        recommended_action="Isolate host.",
    )
