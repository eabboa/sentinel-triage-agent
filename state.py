"""
Defines the LangGraph state using TypedDict.
"""

from typing import TypedDict, Optional


class TriageState(TypedDict):
    # ── Input (fetch_node.py) ───────────────────────────────────────────────────
    incident_id: str
    incident_title: str
    incident_severity: str       # "High", "Medium", "Low", "Informational"
    incident_description: str
    incident_status: str
    incident_tactics: list[str]  # MITRE ATT&CK tactics from Sentinel (e.g., ["InitialAccess"])
    raw_alerts: list[dict]       # Raw alert objects from list_incident_alerts()

    # ── Extraction (summarize_node.py + extract_node.py) ────────────────────────
    condensed_summary: str       # Pre-processed, token-efficient summary for the LLM
    entities: dict               # {"ips": [...], "urls": [...], "hashes": [...],
                                 #  "usernames": [...], "hostnames": [...]}

    # ── Enrichment (enrich_node.py) ────────────────────────────────────────────
    cti_results: dict            # {"ip_reports": [...], "url_reports": [...], "hash_reports": [...]}

    # ── Analysis (analyst_node.py) ─────────────────────────────────────────────
    is_true_positive: bool
    classification: str          # "TruePositive", "FalsePositive", "BenignPositive"
    confidence: int              # 0-100 confidence score from the analyst LLM
    triage_summary: str          # Human-readable, explaining the verdict
    mitre_analysis: str          # MITRE ATT&CK tactic/technique analysis

    # ── Hunting (kql_node.py) ──────────────────────────────────────────────────
    kql_queries: list[str]       # Syntactically valid KQL hunting queries

    # ── Write-back (writeback_node.py) ──────────────────────────────────────────
    comment_posted: bool
    incident_closed: bool
    close_approved: bool
    containment_approved: bool       # Set to True to trigger MDE device isolation
    
    # ── Human review ───────────────────────────────────────────────────────────
    human_classification: Optional[str]  # Human-provided classification after review
    
    # ── Error tracking ─────────────────────────────────────────────────────────
    errors: list[str]            # Non-fatal errors encountered during processing