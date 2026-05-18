"""
Extracts IOCs (Indicators of Compromise) from the condensed incident summary.

This node uses BOTH regex and LLM extraction in a hybrid approach.
"""

import re
import json
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from state import TriageState

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
    """Returns True if the IP is not a private/loopback address."""
    return not any(p.match(ip) for p in PRIVATE_IP_RANGES)


def _is_internal_ip(ip: str) -> bool:
    """Returns True if the IP is a private/RFC-1918 address (lateral movement candidate)."""
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)


async def extract_node(state: TriageState) -> dict:
    """Extracts IOCs from the condensed summary using regex + LLM fallback."""
    text = state["condensed_summary"]

    # ── Phase 1: Regex extraction ──────────────────────────────────────────────
    all_ips = IP_PATTERN.findall(text)
    # Public IPs → threat-intel enrichment (VirusTotal, etc.)
    ips = list(set(ip for ip in all_ips if _is_public_ip(ip)))
    # Internal IPs → kept for lateral movement / host containment; NOT sent to VirusTotal
    internal_ips = list(set(ip for ip in all_ips if _is_internal_ip(ip)))
    hashes = list(set(HASH_SHA256.findall(text) + HASH_MD5.findall(text)))
    urls = list(set(URL_PATTERN.findall(text)))

    # ── Phase 2: LLM extraction for contextual entities ───────────────────────
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",  # Use flash model here; preserve quota for the Analyst node
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        max_retries=0,
    )

    prompt = f"""
You are an IOC extraction specialist. Extract the following entity types from the text below.
Return ONLY valid JSON. No preamble, no explanation, no markdown.

JSON schema:
{{
  "usernames": ["list of user accounts, UPNs, or email addresses"],
  "hostnames": ["list of device names, computer names, or FQDNs"],
  "domains": ["list of suspicious domains (not full URLs)"]
}}

If no entities of a type are found, return an empty list for that key.

TEXT:
{text}
"""

    from throttle import gemini_rate_limiter
    from llm_utils import llm_retry

    @llm_retry
    async def _invoke_llm():
        async with gemini_rate_limiter:
            return await llm.ainvoke(prompt)

    try:
        response = await _invoke_llm()
        # Strip markdown fences if the model adds them despite instructions
        clean = response.content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        llm_entities = json.loads(clean)
    except Exception:
        # If LLM extraction fails, proceed with regex-only results
        llm_entities = {"usernames": [], "hostnames": [], "domains": []}

    entities = {
        "ips": ips,                                          # Public IPs – enriched via threat intel
        "internal_ips": internal_ips,                        # Private IPs – lateral movement candidates
        "urls": urls,
        "hashes": hashes,
        "usernames": llm_entities.get("usernames", []),
        "hostnames": llm_entities.get("hostnames", []),
        "domains": llm_entities.get("domains", []),
    }

    return {"entities": entities}