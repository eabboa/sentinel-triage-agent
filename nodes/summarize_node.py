"""
Condenses the raw incident data before passing it to the LLM.
"""

from state import TriageState

MAX_DESCRIPTION_CHARS = 500
MAX_ALERT_CHARS = 300


def summarize_node(state: TriageState) -> dict:
    """
    Builds a condensed, token-efficient summary from the raw incident data.
    """
    # Truncate the incident description to avoid blowing the context window
    description = state["incident_description"][:MAX_DESCRIPTION_CHARS]
    if len(state["incident_description"]) > MAX_DESCRIPTION_CHARS:
        description += "... [truncated]"

    # Extract key fields from each alert; discard raw log lines
    alert_summaries = []
    for alert in state["raw_alerts"][:5]:  # Cap at 5 alerts to limit tokens
        props = alert.get("properties", {})
        summary = {
            "display_name": props.get("alertDisplayName", "N/A"),
            "severity": props.get("severity", "N/A"),
            "description": props.get("description", "N/A")[:MAX_ALERT_CHARS],
            "tactics": props.get("tactics", []),
            "entities": props.get("entities", []),
        }
        alert_summaries.append(str(summary))

    condensed = f"""
INCIDENT: {state["incident_title"]}
SEVERITY: {state["incident_severity"]}
TACTICS: {", ".join(state["incident_tactics"]) or "None detected"}
DESCRIPTION: {description}

ASSOCIATED ALERTS ({len(state["raw_alerts"])} total, showing first 5):
{chr(10).join(alert_summaries) or "No alerts attached."}
""".strip()

    return {"condensed_summary": condensed}