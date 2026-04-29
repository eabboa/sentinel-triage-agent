"""
The LLM-powered reasoning node. The "brain" of the pipeline.
We use strictly, JSON output to prevent LLM from prose and babbling.
"""

import asyncio
import json
import os
from typing import Literal

import chromadb
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from state import TriageState


# Global variables for ChromaDB and embedding model
chroma_client = None
collection = None
embedding_model = None


def initialize_chroma():
    """Initialize ChromaDB client and collection."""
    global chroma_client, collection, embedding_model
    if chroma_client is None:
        # Use persistent directory
        persist_dir = os.path.join(os.getcwd(), "chroma_db")
        chroma_client = chromadb.PersistentClient(path=persist_dir)
        collection = chroma_client.get_or_create_collection(name="triage_corrections")
        embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


async def retrieve_similar_mismatches(condensed_summary: str, top_k: int = 3):
    """Retrieve top-k similar historical mismatches."""
    if chroma_client is None:
        initialize_chroma()

    # Embed the query
    query_embedding = embedding_model.encode(condensed_summary).tolist()

    # Query the collection
    results = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k
        )
    )

    return results


class AnalystVerdict(BaseModel):
    classification: Literal["TruePositive", "FalsePositive", "BenignPositive"]
    is_true_positive: bool
    triage_summary: str
    mitre_analysis: str
    confidence: int
    recommended_action: str


ANALYST_PROMPT_TEMPLATE = """
You are a Tier 2 SOC analyst performing incident triage in Microsoft Sentinel.

INCIDENT SUMMARY:
{condensed_summary}

CTI ENRICHMENT RESULTS:
{cti_results}

DETECTED MITRE ATT&CK TACTICS:
{tactics}

{few_shot_examples}

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
  "confidence": "CONFIDENCE SCORING: Start at 50. If CTI data is missing, empty, or failed to fetch, apply a 0 point modifier to confidence (treat as a neutral unknown). Only subtract points if there is contradictory evidence. Add points only for verified clean or verified malicious results from the CTI payload. Add 20 for multi-stage MITRE correlation. Subtract 10 for isolated events lacking context. Cap between 0-100, where 90-100 is Definitive, 70-89 is Probable, 40-69 is Ambiguous, and 0-39 is Insufficient Data. Output exact integer.",
  "recommended_action": "Brief next step for the Tier 2 analyst. 3 sentence explanation."
}}
"""


async def analyst_node(state: TriageState) -> dict:
    """
    Sends the condensed incident context to the LLM for structured triage analysis.
    Includes RAG-retrieved few-shot examples of past mistakes.
    """
    # Strictly enforce the output schema with Pydantic validation
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",  # Use the full flash model, not lite.
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        temperature=0,  # deterministic and consistent classification
        max_retries=3,  # Added max_retries to handle intermittent 503s
    ).with_structured_output(AnalystVerdict)

    # Retrieve similar historical mismatches
    condensed_summary = state.get("condensed_summary", "No summary available.")
    results = await retrieve_similar_mismatches(condensed_summary, top_k=3)

    # Format few-shot examples
    few_shot_examples = ""
    if results['documents']:
        few_shot_examples = "FEW-SHOT EXAMPLES OF PAST MISTAKES:\n"
        for i, doc in enumerate(results['documents'][0], 1):
            few_shot_examples += f"Example {i}:\n{doc}\n\n"

    prompt = ANALYST_PROMPT_TEMPLATE.format(
        condensed_summary=condensed_summary,
        cti_results=json.dumps(state.get("cti_results", {}), indent=2),
        tactics=", ".join(state.get("incident_tactics", [])) or "None detected by Sentinel",
        few_shot_examples=few_shot_examples,
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
        verdict = getattr(response, "output_parsed", None) or getattr(response, "parsed_output", None) or response

        if isinstance(verdict, AnalystVerdict):  # If the output parser worked correctly, we get a Pydantic model instance
            return verdict.dict()

        if isinstance(verdict, dict):
            return verdict

        raise ValueError("Unexpected structured output type from analyst LLM response.")

    except Exception as e:
        return {
            "classification": "Undetermined",
            "is_true_positive": False,
            "triage_summary": f"Analyst node failed: {str(e)}",
            "mitre_analysis": "N/A",
            "confidence": 0,
            "recommended_action": "N/A",
        }
