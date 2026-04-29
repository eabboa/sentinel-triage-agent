"""
Generates syntactically valid KQL hunting queries for analyst follow-up.

THE CRITICAL PROBLEM: LLMs hallucinate KQL.
They invent table names, reference columns that do not exist, and mix up
table schemas across different Sentinel data connectors. A query with
`DeviceProcessEvents` will fail if Defender for Endpoint is not connected.
A query referencing `SigninLogs` will fail if Azure AD Diagnostics is not enabled.

THE SOLUTION: Schema-Aware Prompting + Table Existence Gating.
1. Provide the LLM with an explicit table schema map in the prompt.
2. Instruct it to ONLY use tables from the provided map.
3. Include the canonical column names for each table in the prompt.
4. Gate table selection based on the incident tactics.

This does not solve hallucination completely. But it tunes out.
"""

import json
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from state import TriageState


# ── Schema Map: The KQL Reliability Layer ─────────────────────────────────────
# Columns listed are the most commonly queried.
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
    """Returns only the table schemas relevant to the detected tactics."""
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
    """Generates schema-validated KQL hunting queries."""
    # Skip KQL generation for false positives
    if state.get("classification") == "FalsePositive":
        return {"kql_queries": ["# No hunting queries generated — classified as FalsePositive"]}

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash-lite",  # Lite model
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        temperature=0,
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

    from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception
    from throttle import gemini_rate_limiter

    def _is_retryable_error(e: Exception) -> bool:
        err_str = str(e).upper()
        return "429" in err_str or "503" in err_str or "RESOURCE_EXHAUSTED" in err_str or "UNAVAILABLE" in err_str

    @retry(
        wait=wait_exponential(multiplier=2, min=5, max=60),
        stop=stop_after_attempt(5),
        retry=retry_if_exception(_is_retryable_error)
    )
    async def _invoke_llm():
        await gemini_rate_limiter.acquire()
        return await llm.ainvoke(prompt)

    try:
        response = await _invoke_llm()
        clean = response.content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        result = json.loads(clean)
        
        queries = [
            f"// {q['title']}\n// Purpose: {q['purpose']}\n{q['kql']}"
            for q in result.get("queries", [])
        ]
        return {"kql_queries": queries}

    except Exception as e:
        return {"kql_queries": [f"// KQL generation failed: {str(e)}"]}