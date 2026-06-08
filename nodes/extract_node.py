"""
Extracts IOCs (Indicators of Compromise) from the condensed incident summary.

This node uses BOTH regex and LLM extraction in a hybrid approach.
"""

import re
import json
import structlog
import os

from state import TriageState
from models.exceptions import LLMExtractionError, LLMOutputValidationError

logger = structlog.get_logger(__name__)

# ── Compiled regex patterns ────────────────────────────────────────────────────
# IPv4 address pattern (excludes private/loopback ranges in the filter step)
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

# Private IP ranges to exclude (RFC 1918 + loopback)
PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
]


def _is_public_ip(ip: str) -> bool:
    """
    Determines if the IP is a public address (not a private/loopback address).

    Args:
        ip: The IP address string.

    Returns:
        True if the IP is public, False otherwise.
    """
    return not any(p.match(ip) for p in PRIVATE_IP_RANGES)


def _is_internal_ip(ip: str) -> bool:
    """
    Determines if the IP is an internal address (RFC-1918/loopback).

    Args:
        ip: The IP address string.

    Returns:
        True if the IP is internal, False otherwise.
    """
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)


def _extract_regex_iocs(text: str) -> dict:
    """
    Extracts IPs, hashes, and URLs from raw text using compiled regex patterns.

    Args:
        text: The raw text string to extract IOCs from.

    Returns:
        A dictionary of extracted IOC lists keyed by type.
    """
    all_ips = IP_PATTERN.findall(text)
    return {
        "ips": list(set(ip for ip in all_ips if _is_public_ip(ip))),
        "internal_ips": list(set(ip for ip in all_ips if _is_internal_ip(ip))),
        "hashes": list(set(HASH_SHA256.findall(text) + HASH_MD5.findall(text))),
        "urls": list(set(URL_PATTERN.findall(text))),
    }


def _extract_iocs_from_raw_alerts(raw_alerts: list[dict]) -> dict:
    """
    Extracts IOCs from ALL raw alert objects using structured entity fields and regex.

    Iterates every alert (not capped) to ensure IOCs beyond the summarize_node
    cap are captured for CTI enrichment.

    Args:
        raw_alerts: The full list of raw alert dicts from Sentinel.

    Returns:
        A dictionary of extracted IOC lists keyed by type.
    """
    ips: set[str] = set()
    internal_ips: set[str] = set()
    hashes: set[str] = set()
    urls: set[str] = set()

    for alert in raw_alerts:
        props = alert.get("properties", {})

        # ── Structured entity extraction ───────────────────────────────────
        for entity in props.get("entities", []):
            entity_type = entity.get("Type", "").lower()
            if entity_type == "ip":
                addr = entity.get("Address", "")
                if addr:
                    if _is_public_ip(addr):
                        ips.add(addr)
                    elif _is_internal_ip(addr):
                        internal_ips.add(addr)
            elif entity_type == "filehash":
                val = entity.get("Value", "")
                if val:
                    hashes.add(val)
            elif entity_type == "url":
                url = entity.get("Url", "")
                if url:
                    urls.add(url)

        # ── Regex over alert text fields ───────────────────────────────────
        text_fields = [
            props.get("description", ""),
            props.get("alertDisplayName", ""),
        ]
        combined_text = " ".join(text_fields)
        if combined_text.strip():
            text_iocs = _extract_regex_iocs(combined_text)
            ips.update(text_iocs["ips"])
            internal_ips.update(text_iocs["internal_ips"])
            hashes.update(text_iocs["hashes"])
            urls.update(text_iocs["urls"])

    return {
        "ips": list(ips),
        "internal_ips": list(internal_ips),
        "hashes": list(hashes),
        "urls": list(urls),
    }


async def extract_node(state: TriageState) -> dict:
    """
    Extracts IOCs from raw_alerts (all alerts) and condensed_summary (LLM context).

    Args:
        state: The current TriageState dictionary.

    Returns:
        A dictionary containing the extracted entities state updates.

    Raises:
        ValueError: If GOOGLE_API_KEY is not set.
    """
    if not os.getenv("GOOGLE_API_KEY"):
        raise ValueError("NO API KEY: GOOGLE_API_KEY")
    logger.info("node_entry", node="extract")
    text = state["condensed_summary"]

    # ── Phase 1: Structured + regex extraction from ALL raw alerts ─────────────
    raw_alerts_iocs = _extract_iocs_from_raw_alerts(state.get("raw_alerts", []))

    # ── Phase 2: Regex extraction from condensed summary (fallback coverage) ───
    summary_iocs = _extract_regex_iocs(text)

    # ── Phase 2: LLM extraction for contextual entities ───────────────────────
    from langchain_google_genai import ChatGoogleGenerativeAI

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",  # Use flash model here; preserve quota for the Analyst node
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        max_retries=0,
    )

    prompt = f"""
You are a security analyst extracting Indicators of Compromise (IOCs) from a Microsoft Sentinel incident summary.

RULES:
- Extract ONLY entities that are explicitly present in the TEXT below. Do NOT infer, guess, or generate values.
- If an entity type is not present in the text, return an empty list for that key.
- Output ONLY a raw JSON object. No markdown, no code fences, no explanation.

FIELD DEFINITIONS:
- "usernames": Account names, UPNs (user@domain.com), SAM account names (DOMAIN\\user), or service accounts observed performing or targeted by the suspicious activity. Exclude generic system accounts (e.g., SYSTEM, NT AUTHORITY).
- "hostnames": Device hostnames, NetBIOS names, or FQDNs (e.g., WKSTN-042, srv01.corp.local) that are sources or targets of the activity. Exclude cloud service endpoints and URLs.
- "domains": Second-level domains (e.g., evil.com, c2-domain.net) associated with command-and-control, phishing, or malware delivery. Exclude known-legitimate domains (e.g., microsoft.com, windows.com, office.com) unless they are clearly being abused (e.g., typosquatted). Strip to bare domain only - no protocols, no paths.

OUTPUT FORMAT (strict):
{{
  "usernames": [],
  "hostnames": [],
  "domains": []
}}

TEXT:
{text}
"""

    from throttle import gemini_rate_limiter
    from llm_utils import llm_retry

    @llm_retry
    async def _invoke_llm():
        async with gemini_rate_limiter:
            logger.info("llm_call_start", node="extract")
            return await llm.ainvoke(prompt)

    try:
        response = await _invoke_llm()
        metadata = getattr(response, "response_metadata", None)
        if isinstance(metadata, dict):
            usage_dict = metadata.get("usage_metadata", {})
            output_tokens = usage_dict.get("candidates_token_count") or usage_dict.get("completion_tokens", 0)
        else:
            output_tokens = 0
        logger.info("llm_call_end", node="extract", output_tokens=output_tokens)
        
        # Strip markdown fences if the model adds them despite instructions
        clean = response.content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        try:
            llm_entities = json.loads(clean)
        except json.JSONDecodeError as exc:
            raise LLMOutputValidationError(
                f"LLM returned unparsable output: {clean[:200]}", raw_data=clean
            ) from exc
    except (LLMExtractionError, LLMOutputValidationError):
        logger.warning("LLM extraction failed, falling back to regex-only", exc_info=True)
        llm_entities = {"usernames": [], "hostnames": [], "domains": []}
    except Exception as exc:
        logger.warning(
            "LLM extraction failed (unexpected: %s), falling back to regex-only",
            type(exc).__name__, exc_info=True,
        )
        llm_entities = {"usernames": [], "hostnames": [], "domains": []}

    # ── Merge: raw_alerts (complete) + summary regex (fallback) + LLM contextual
    entities = {
        "ips": list(set(raw_alerts_iocs["ips"]) | set(summary_iocs["ips"])),
        "internal_ips": list(set(raw_alerts_iocs["internal_ips"]) | set(summary_iocs["internal_ips"])),
        "hashes": list(set(raw_alerts_iocs["hashes"]) | set(summary_iocs["hashes"])),
        "urls": list(set(raw_alerts_iocs["urls"]) | set(summary_iocs["urls"])),
        "usernames": llm_entities.get("usernames", []),
        "hostnames": llm_entities.get("hostnames", []),
        "domains": llm_entities.get("domains", []),
    }

    logger.info("node_exit", node="extract")
    return {"entities": entities}