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
    if not os.getenv("GOOGLE_API_KEY"):
        raise ValueError("NO API KEY: GOOGLE_API_KEY")
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
        "ips": ips,                                          # Public IPs - enriched via threat intel
        "internal_ips": internal_ips,                        # Private IPs - lateral movement candidates
        "urls": urls,
        "hashes": hashes,
        "usernames": llm_entities.get("usernames", []),
        "hostnames": llm_entities.get("hostnames", []),
        "domains": llm_entities.get("domains", []),
    }

    return {"entities": entities}