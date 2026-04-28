"""
The LLM-powered reasoning node. The "brain" of the pipeline.
We use strictly, JSON output to prevent LLM from prose and babbling.
"""

import json
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from state import TriageState


ANALYST_PROMPT_TEMPLATE = """
You are a Tier 2 SOC analyst performing incident triage in Microsoft Sentinel.

INCIDENT SUMMARY:
{condensed_summary}

CTI ENRICHMENT RESULTS:
{cti_results}

DETECTED MITRE ATT&CK TACTICS:
{tactics}

TASK:
1. Analyze whether this incident represents a genuine threat.
2. Correlate the CTI results with the MITRE ATT&CK tactics.
3. Determine the classification.
4. Explain your reasoning clearly for a Tier 1 analyst who will read this.

CLASSIFICATION RULES:
- TruePositive: Confirmed malicious activity. At least one IOC is confirmed malicious
  by CTI AND the behavior matches the detected tactics.
- FalsePositive: Alert fired incorrectly. IOCs are clean, behavior is explainable
  as legitimate activity, detection rule likely needs tuning.
- BenignPositive: Alert fired correctly (the rule worked), but the activity is
  authorized or expected (e.g., a pentest, a known admin behavior, a whitelisted scanner).

Return ONLY valid JSON with this exact schema. No preamble, no markdown, no explanation outside the JSON:
{{
  "classification": "TruePositive" | "FalsePositive" | "BenignPositive",
  "is_true_positive": true | false,
  "triage_summary": "3 sentence explanation of the verdict.",
  "mitre_analysis": "How the detected tactics map to the observed behavior. 3 sentence explanation. Each sentence under 15 words.",
  "confidence": "CONFIDENCE SCORING: Start at 50. Add 20 for definitive CTI confirmation or verified clean status. Add 20 for multi-stage MITRE correlation. Subtract 20 for mixed or missing CTI. Subtract 10 for isolated events lacking context. Cap between 0-100, where 90-100 is Definitive, 70-89 is Probable, 40-69 is Ambiguous, and 0-39 is Insufficient Data. Output exact integer.",
  "recommended_action": "Brief next step for the Tier 2 analyst. 3 sentence explanation."
}}
"""


def analyst_node(state: TriageState) -> dict:
    """
    Sends the condensed incident context to the LLM for structured triage analysis.
    """
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",  # Use the full flash model, not lite.
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        temperature=0,  # deterministic and consistent classification
    )

    prompt = ANALYST_PROMPT_TEMPLATE.format(
        condensed_summary=state.get("condensed_summary", "No summary available."),
        cti_results=json.dumps(state.get("cti_results", {}), indent=2),
        tactics=", ".join(state.get("incident_tactics", [])) or "None detected by Sentinel",
    )

    try:
        response = llm.invoke(prompt)
        clean = response.content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        result = json.loads(clean)

        return {
            "classification": result.get("classification", "Undetermined"),
            "is_true_positive": result.get("is_true_positive", False),
            "triage_summary": result.get("triage_summary", "Analysis failed."),
            "mitre_analysis": result.get("mitre_analysis", "No MITRE analysis available."),
        }

    except Exception as e:
        return {
            "classification": "Undetermined",
            "is_true_positive": False,
            "triage_summary": f"Analyst node failed: {str(e)}",
            "mitre_analysis": "N/A",
        }