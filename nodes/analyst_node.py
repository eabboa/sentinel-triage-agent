"""
The LLM-powered reasoning node. The "brain" of the pipeline.
We use strictly, JSON output to prevent LLM from prose and babbling.
"""

import asyncio
import json
import os
from typing import Literal, Optional
import logging
import chromadb

logger = logging.getLogger(__name__)
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, ValidationError
from models.exceptions import LLMOutputValidationError
from sentence_transformers import SentenceTransformer
from state import TriageState
from nodes.mitre_utils import MITRE_CATALOG

mitre_catalog_str = json.dumps(MITRE_CATALOG, indent=2)


# Global variables for ChromaDB and embedding model
chroma_client = None
collection = None
embedding_model = None


def initialize_chroma():
    """Initialize ChromaDB client and collection."""
    global chroma_client, collection, embedding_model
    if chroma_client is None:
        host = os.environ.get("CHROMA_HOST", "localhost")
        port = int(os.environ.get("CHROMA_PORT", "8000"))
        chroma_client = chromadb.HttpClient(host=host, port=port)
        collection = chroma_client.get_or_create_collection(name="triage_corrections")
        embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


async def retrieve_similar_mismatches(condensed_summary: str, top_k: int = 3):
    """Retrieve top-k similar historical mismatches."""
    if chroma_client is None or embedding_model is None or collection is None:
        initialize_chroma()

    assert embedding_model is not None, "embedding_model not initialized"
    assert collection is not None, "collection not initialized"

    # Embed the query
    query_embedding = embedding_model.encode(condensed_summary).tolist()

    # Query the collection
    results = await asyncio.get_running_loop().run_in_executor(
        None,
        lambda: collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k
        )
    )

    return results


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    confidence: int
    tactic: Optional[str] = None


class AnalystVerdict(BaseModel):
    classification: Literal["TruePositive", "FalsePositive", "BenignPositive"]
    is_true_positive: bool
    triage_summary: str
    mitre_analysis: str
    mitre_techniques: list[MitreTechnique]
    confidence: int
    recommended_action: str

ANALYST_SYSTEM_PROMPT = """
You are a Tier 2 SOC analyst performing incident triage in Microsoft Sentinel.

Your goal is to evaluate the provided incident summary and CTI enrichment results to determine if an alert is a True Positive, False Positive, or Benign Positive.

CTI RESULT INTERPRETATION:
Each CTI result includes a pre-computed "verdict" field. Use this as your authoritative
signal. Raw counts (malicious, suspicious) are supporting context only.
  - "verdict": "malicious"    → IOC confirmed malicious at configured engine threshold.
  - "verdict": "suspicious"   → Weak signal (2-4 engines). Escalate, do not auto-close.
  - "verdict": "clean"        → 0-1 engine detections. Treat as not malicious.
  - "verdict": "not_found_in_vt" → Hash has no VirusTotal history. Treat as unknown,
    not clean. Novel malware is often absent from VT. Correlate with other signals.
  - No verdict field present  → IP/URL/hash lookup failed or returned an error.
    Treat this IOC as UNKNOWN - apply a 0 point confidence modifier. Do NOT infer
    threat signals from the absence of a result (e.g. timeout is not IP blocking scanners).

TASK:
1. Analyze whether this incident represents a genuine threat.
2. Correlate the CTI verdicts with the MITRE ATT&CK tactics.
3. Map the Sentinel `incident_tactics` (why) to specific `mitre_techniques` (how) based on alert entities and descriptions.
4. Determine the classification.
5. Explain your reasoning clearly for a Tier 2 analyst who will read this.

KILL CHAIN SEVERITY LOGIC:
- If multiple tactics represent progression through the kill chain (e.g., Initial Access -> Credential Access -> Lateral Movement), severity and confidence should be elevated.
- If INTERNAL IPs (RFC 1918) are present in the data, treat them as lateral movement indicators.
  Relevant techniques include: T1021 (Remote Services), T1570 (Lateral Tool Transfer),
  T1550 (Use Alternate Authentication Material), T1563 (Remote Service Session Hijacking).
  Even without external CTI verdicts, internal-to-internal traffic between unexpected hosts is
  a strong signal of post-compromise activity. Weight this in your confidence score.

MITRE ATT&CK MAPPING GUIDELINES:
Map the detected incident tactics to precise and standard MITRE ATT&CK technique IDs and names.
You must choose from the provided reference catalog below to prevent hallucination.
Ensure the techniques correspond logically to the observed incident behavior. Do not invent fake technique IDs or guess name pairings, as your output will be verified programmatically against the official MITRE framework catalog.

REFERENCE CATALOG:
""" + mitre_catalog_str + """

CLASSIFICATION RULES:
- TruePositive: Confirmed malicious activity. At least one IOC verdict is "malicious"
  AND the behavior matches the detected tactics.
- FalsePositive: Alert fired incorrectly. All IOC verdicts are "clean", behavior is
  explainable as legitimate activity, detection rule likely needs tuning.
- BenignPositive: Alert fired correctly (the rule worked), but the activity is
  authorized or expected (e.g., a pentest, a known admin behavior, a whitelisted scanner).

LEARNING FROM PAST MISTAKES:
You may be provided with a section labeled 'FEW-SHOT EXAMPLES OF PAST MISTAKES' in the
incident data. These are historical cases where you classified an incident incorrectly
and a human analyst corrected you. Each example contains:
  - "Incident Context": The original incident summary (similar to what you are analyzing now).
  - "Incorrect LLM Reasoning": Your previous flawed triage reasoning for that incident.
  - "Human Correction Reason": The analyst's explanation of WHY your classification was wrong.
    This often contains out-of-band context you could not have known (e.g., authorized pentests,
    expected service account behavior, environment-specific whitelists).
  - "Correct Label": The correct classification the analyst provided.

When these examples are present:
1. Identify the analytical error in the "Incorrect LLM Reasoning" by contrasting it with
   the "Human Correction Reason". Understand the root cause of the mistake.
2. Check if the CURRENT incident shares the same pattern, context, or entities that caused
   the historical misclassification.
3. If the current incident matches a known correction pattern, apply the corrected reasoning.
   Do NOT repeat the same analytical error.
4. If the current incident is superficially similar but contextually different, explain why
   the historical correction does not apply.

Return ONLY valid JSON with this exact schema. No preamble, no markdown, no explanation outside the JSON:
{
  "classification": "TruePositive" | "FalsePositive" | "BenignPositive",
  "is_true_positive": true | false,
  "triage_summary": "3 sentence explanation of the verdict.",
  "mitre_analysis": "How the detected tactics map to the observed behavior. 3 sentence explanation. Each sentence under 15 words.",
  "mitre_techniques": [{"technique_id": "TXXXX", "name": "", "confidence": 90, "tactic": ""}],
  "confidence": "CONFIDENCE SCORING: Start at 50. Add/subtract based on CTI verdicts only (not raw counts). +25 if any IOC verdict is 'malicious'. +10 if any IOC verdict is 'suspicious'. -10 if all IOC verdicts are 'clean'. Apply 0 modifier for missing/failed lookups (treat as neutral unknown, not clean). Add 20 for multi-stage MITRE correlation. Subtract 10 for isolated events lacking context. Cap between 0-100, where 90-100 is Definitive, 70-89 is Probable, 40-69 is Ambiguous, and 0-39 is Insufficient Data. Output exact integer.",
  "recommended_action": "Brief next step for the Tier 2 analyst. 3 sentence explanation."
}
"""

USER_DATA_TEMPLATE = """
UNTRUSTED INCIDENT DATA FOR ANALYSIS:
--------------------------------------
INCIDENT SUMMARY:
{condensed_summary}

CTI ENRICHMENT RESULTS:
{cti_results}

INTERNAL IPs (Lateral Movement Candidates - no external CTI available):
{internal_ips}

DETECTED MITRE ATT&CK TACTICS: {tactics}

{few_shot_examples}
--------------------------------------
Evaluate the data above according to your system instructions.
"""


async def analyst_node(state: TriageState) -> dict:
    """
    Sends the condensed incident context to the LLM for structured triage analysis.
    Includes RAG-retrieved few-shot examples of past mistakes.
    """
    if not os.getenv("GOOGLE_API_KEY"):
        raise ValueError("NO API KEY: GOOGLE_API_KEY")

    # Strictly enforce the output schema with Pydantic validation
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",  # Use a powerful model for production
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        temperature=0,  # deterministic and consistent classification
        max_retries=0,  # Disabled internal retries to let tenacity handle backoff with jitter
    ).with_structured_output(AnalystVerdict)

    condensed_summary = state.get("condensed_summary", "No summary available.")

    from throttle import gemini_rate_limiter
    from llm_utils import llm_retry

    try:
        # Retrieve similar historical mismatches — inside try so ChromaDB
        # outages degrade to empty few-shot context instead of crashing.
        results = await retrieve_similar_mismatches(condensed_summary, top_k=3)

        # Format few-shot examples
        few_shot_examples = ""
        if results['documents']:
            few_shot_examples = "FEW-SHOT EXAMPLES OF PAST MISTAKES:\n"
            for i, doc in enumerate(results['documents'][0], 1):
                few_shot_examples += f"Example {i}:\n{doc}\n\n"

        messages = [
            SystemMessage(content=ANALYST_SYSTEM_PROMPT),
            HumanMessage(content=USER_DATA_TEMPLATE.format(
                condensed_summary=condensed_summary,
                cti_results=json.dumps(state.get("cti_results", {}), indent=2),
                internal_ips=json.dumps(
                    state.get("entities", {}).get("internal_ips", []), indent=2
                ) or "None detected",
                tactics=", ".join(state.get("incident_tactics", [])) or "None detected by Sentinel",
                few_shot_examples=few_shot_examples,
            ))
        ]

        @llm_retry
        async def _invoke_llm():
            async with gemini_rate_limiter:
                return await llm.ainvoke(messages)

        response = await _invoke_llm()
        verdict = getattr(response, "output_parsed", None) or getattr(response, "parsed_output", None) or response
        verdict_dict = {}
        if isinstance(verdict, AnalystVerdict):
            # The happy path: LangChain already validated it into an object
            verdict_dict = verdict.model_dump()
            
        elif isinstance(verdict, dict):
            # The dangerous path: We got a dictionary. We MUST validate it manually.
            try:
                validated_verdict = AnalystVerdict.model_validate(verdict)
                verdict_dict = validated_verdict.model_dump()
            except ValidationError as exc:
                # We use logger.error so the exact hallucinated dictionary is printed to your console
                logger.error("LLM output failed schema validation. Raw output: %s", verdict)
                raise LLMOutputValidationError(
                    message=f"LLM hallucinated invalid schema: {str(exc)}",
                    raw_data=verdict
                ) from exc
                
        else:
            # We got something completely unrecognizable (like a plain string)
            logger.error("LLM returned unrecognizable output type. Raw output: %s", verdict)
            raise LLMOutputValidationError(
                message="LLM returned non-dict and non-model output.",
                raw_data=verdict
            )

        # Programmatically validate and enrich MITRE techniques
        suggested_techs = verdict_dict.get("mitre_techniques", [])
        incident_tactics = state.get("incident_tactics", [])
        from nodes.mitre_utils import validate_and_enrich_techniques
        verified_techs, warnings = validate_and_enrich_techniques(suggested_techs, incident_tactics)
        
        verdict_dict["mitre_techniques"] = verified_techs
        if warnings:
            verdict_dict["errors"] = warnings
            
        return verdict_dict

    except Exception as e:
        return {
            "classification": "Undetermined",
            "is_true_positive": False,
            "triage_summary": f"Analyst node failed: {str(e)}",
            "mitre_analysis": "N/A",
            "confidence": 0,
            "recommended_action": "N/A",
            "errors": [f"Analyst node failed: {str(e)}"]
        }
