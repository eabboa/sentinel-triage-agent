"""
Generates syntactically valid KQL hunting queries for analyst follow-up.

1. Provide the LLM with an explicit table schema map in the prompt.
2. Instruct it to ONLY use tables from the provided map.
3. Include the canonical column names for each table in the prompt.
4. Gate table selection based on the incident tactics.

This does not solve hallucination completely. But it tunes out.
"""

import json
import os
import structlog

from state import TriageState

logger = structlog.get_logger(__name__)


# ── Schema Map: The KQL Reliability Layer ─────────────────────────────────────
# Columns listed are the most commonly queried. 
# NOTE: This schema MUST be updated 
# according to the specific tables and columns available in the connected data connectors.

SENTINEL_TABLE_SCHEMA = {
    "SecurityAlert": {
        "description": "Microsoft Sentinel-generated security alerts",
        "key_columns": ["AlertName", "Severity", "Entities", "ExtendedProperties",
                        "ProviderName", "TimeGenerated", "SystemAlertId"],
        "use_for_tactics": ["*"],  # Available for all tactic types
    },
    "SecurityIncident": {
        "description": "Microsoft Sentinel incidents",
        "key_columns": ["IncidentNumber", "Title", "Severity", "Status",
                        "Owner", "Labels", "TimeGenerated"],
        "use_for_tactics": ["*"],
    },
    "SigninLogs": {
        "description": "Azure AD interactive sign-in events",
        "key_columns": ["UserPrincipalName", "IPAddress", "Location",
                        "ResultType", "ResultDescription", "AppDisplayName",
                        "DeviceDetail", "TimeGenerated"],
        "use_for_tactics": ["InitialAccess", "CredentialAccess", "Persistence"],
    },
    "AuditLogs": {
        "description": "Azure AD audit events (user/group changes, app registrations)",
        "key_columns": ["OperationName", "InitiatedBy", "TargetResources",
                        "Result", "TimeGenerated"],
        "use_for_tactics": ["Persistence", "PrivilegeEscalation", "DefenseEvasion"],
    },
    "SecurityEvent": {
        "description": "Windows Security Event Log (requires Azure Monitor Agent)",
        "key_columns": ["EventID", "Account", "Computer", "SubjectUserName",
                        "TargetUserName", "LogonType", "IpAddress", "TimeGenerated"],
        "use_for_tactics": ["LateralMovement", "CredentialAccess", "Execution"],
    },
    "OfficeActivity": {
        "description": "Microsoft 365 activity (SharePoint, OneDrive, Exchange, Teams)",
        "key_columns": ["Operation", "UserId", "ClientIP", "ObjectId",
                        "OfficeWorkload", "TimeGenerated"],
        "use_for_tactics": ["Collection", "Exfiltration", "InitialAccess"],
    },
}


def _select_relevant_tables(tactics: list[str]) -> dict:
    """
    Returns only the table schemas relevant to the detected tactics.

    Args:
        tactics: A list of MITRE ATT&CK tactics detected in the incident.

    Returns:
        A dictionary of relevant table schemas.
    """
    relevant = {}
    for table, schema in SENTINEL_TABLE_SCHEMA.items():
        if "*" in schema["use_for_tactics"]:
            relevant[table] = schema
        elif any(t in schema["use_for_tactics"] for t in tactics):
            relevant[table] = schema
    return relevant


KQL_PROMPT_TEMPLATE = """
You are a Microsoft Sentinel KQL expert. Generate hunting queries for the incident below.

INCIDENT:
{incident_title}

ENTITIES TO HUNT FOR:
{entities}

MITRE ATT&CK TACTICS DETECTED:
{tactics}

TRIAGE SUMMARY:
{triage_summary}

CRITICAL RULES:
1. ONLY use tables from the APPROVED TABLE SCHEMA below. Do NOT invent table names.
2. ONLY use columns listed in the schema for each table. Do NOT invent column names.
3. Every query must include a time filter: | where TimeGenerated > ago(7d)
4. Queries must be self-contained. No variables, no functions defined outside the query.
5. Use 'let' statements within the query only if needed for readability.
6. Do NOT use tables not present in the schema.

APPROVED TABLE SCHEMA:
{table_schema}

Return ONLY valid JSON with this schema. No markdown:
{{
  "queries": [
    {{
      "title": "Short descriptive title",
      "table": "TableName",
      "purpose": "What this query hunts for",
      "kql": "Full KQL query string (single line, escaped properly)"
    }}
  ]
}}

Generate 3 targeted queries.
"""


async def kql_node(state: TriageState) -> dict:
    """
    Generates schema-validated KQL hunting queries.

    Args:
        state: The current TriageState dictionary.

    Returns:
        A dictionary containing the state updates for generated KQL queries.

    Raises:
        ValueError: If GOOGLE_API_KEY is not set.
    """
    logger.info("node_entry", node="kql")
    # Skip KQL generation for false positives
    if state.get("classification") == "FalsePositive":
        logger.info("node_exit", node="kql")
        return {"kql_queries": ["# No hunting queries generated - classified as FalsePositive"]}

    if not os.getenv("GOOGLE_API_KEY"):
        raise ValueError("NO API KEY: GOOGLE_API_KEY")

    from langchain_google_genai import ChatGoogleGenerativeAI

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash-lite",  # Lite model
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        temperature=0,
        max_retries=0,
    )

    tactics = state.get("incident_tactics", [])
    relevant_tables = _select_relevant_tables(tactics)

    prompt = KQL_PROMPT_TEMPLATE.format(
        incident_title=state.get("incident_title", "Unknown"),
        entities=json.dumps(state.get("entities", {}), indent=2),
        tactics=", ".join(tactics) or "None",
        triage_summary=state.get("triage_summary", ""),
        table_schema=json.dumps(relevant_tables, indent=2),
    )

    from throttle import gemini_rate_limiter
    from llm_utils import llm_retry

    @llm_retry
    async def _invoke_llm():
        async with gemini_rate_limiter:
            logger.info("llm_call_start", node="kql")
            return await llm.ainvoke(prompt)

    try:
        response = await _invoke_llm()
        metadata = getattr(response, "response_metadata", None)
        if isinstance(metadata, dict):
            usage_dict = metadata.get("usage_metadata", {})
            output_tokens = usage_dict.get("candidates_token_count") or usage_dict.get("completion_tokens", 0)
        else:
            output_tokens = 0
        logger.info("llm_call_end", node="kql", output_tokens=output_tokens)
        
        clean = response.content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        result = json.loads(clean)
        
        queries = [
            f"// {q['title']}\n// Purpose: {q['purpose']}\n{q['kql']}"
            for q in result.get("queries", [])
        ]
        
        logger.info("node_exit", node="kql")
        return {"kql_queries": queries}

    except Exception as e:
        logger.error("node_error", node="kql", exc_info=True)
        return {"kql_queries": [f"// KQL generation failed: {str(e)}"]}