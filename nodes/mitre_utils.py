"""
Utilities for normalizing, validating, and enriching MITRE ATT&CK tactics and techniques.
Prevents LLM hallucination of technique IDs/names and provides structured mapping.
"""

import logging
import re
from types import MappingProxyType
from typing import Optional

logger = logging.getLogger(__name__)

# Pattern for valid MITRE ATT&CK Technique ID (e.g., T1078 or T1078.001)
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

TACTIC_MAPPING = {
    "initialaccess": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilegeescalation": "Privilege Escalation",
    "defenseevasion": "Defense Evasion",
    "credentialaccess": "Credential Access",
    "discovery": "Discovery",
    "lateralmovement": "Lateral Movement",
    "collection": "Collection",
    "commandandcontrol": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

# Curated reference catalog of common enterprise & cloud MITRE ATT&CK techniques
MITRE_CATALOG = {
    "Initial Access": {
        "T1078": "Valid Accounts",
        "T1078.001": "Valid Accounts: Default Accounts",
        "T1078.002": "Valid Accounts: Domain Accounts",
        "T1078.003": "Valid Accounts: Local Accounts",
        "T1078.004": "Valid Accounts: Cloud Accounts",
        "T1190": "Exploit Public-Facing Application",
        "T1566": "Phishing",
        "T1566.001": "Phishing: Spearphishing Attachment",
        "T1566.002": "Phishing: Spearphishing Link",
        "T1200": "Hardware Additions",
    },
    "Execution": {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "Command and Scripting Interpreter: PowerShell",
        "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
        "T1059.004": "Command and Scripting Interpreter: Unix Shell",
        "T1059.005": "Command and Scripting Interpreter: Visual Basic",
        "T1203": "Exploitation for Client Execution",
        "T1053": "Scheduled Task/Job",
        "T1053.005": "Scheduled Task/Job: Scheduled Task",
        "T1072": "Software Deployment",
    },
    "Persistence": {
        "T1098": "Account Manipulation",
        "T1098.001": "Account Manipulation: Additional Cloud Credentials",
        "T1098.005": "Account Manipulation: Device Registration",
        "T1136": "Create Account",
        "T1136.001": "Create Account: Local Account",
        "T1136.002": "Create Account: Domain Account",
        "T1136.003": "Create Account: Cloud Account",
        "T1053": "Scheduled Task/Job",
        "T1543": "Create or Modify System Process",
        "T1543.003": "Create or Modify System Process: Windows Service",
        "T1137": "Office Application Startup",
        "T1547": "Boot or Logon Autostart Execution",
    },
    "Privilege Escalation": {
        "T1548": "Abuse Elevation Control Mechanism",
        "T1548.002": "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "T1078": "Valid Accounts",
        "T1068": "Exploitation for Privilege Escalation",
        "T1543": "Create or Modify System Process",
    },
    "Defense Evasion": {
        "T1070": "Indicator Removal",
        "T1070.001": "Indicator Removal: Clear Windows Event Logs",
        "T1070.004": "Indicator Removal: File Deletion",
        "T1562": "Impair Defenses",
        "T1562.001": "Impair Defenses: Disable or Modify Tools",
        "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
        "T1112": "Modify Registry",
        "T1036": "Masquerading",
        "T1218": "System Binary Proxy Execution",
        "T1553": "Subvert Trust Controls",
    },
    "Credential Access": {
        "T1110": "Brute Force",
        "T1110.001": "Brute Force: Password Guessing",
        "T1110.002": "Brute Force: Password Cracking",
        "T1110.003": "Brute Force: Password Spraying",
        "T1110.004": "Brute Force: Credential Stuffing",
        "T1552": "Unsecured Credentials",
        "T1552.001": "Unsecured Credentials: Credentials in Files",
        "T1003": "OS Credential Dumping",
        "T1555": "Credentials from Password Stores",
        "T1539": "Steal Web Session Cookie",
        "T1606": "Forge Web Credentials",
    },
    "Discovery": {
        "T1082": "System Information Discovery",
        "T1016": "System Network Connection Discovery",
        "T1046": "Network Service Discovery",
        "T1087": "Account Discovery",
        "T1069": "Permission Groups Discovery",
        "T1057": "Process Discovery",
    },
    "Lateral Movement": {
        "T1021": "Remote Services",
        "T1021.001": "Remote Services: Remote Desktop Protocol",
        "T1021.002": "Remote Services: SMB/Windows Admin Shares",
        "T1021.006": "Remote Services: Windows Remote Management",
        "T1570": "Lateral Tool Transfer",
        "T1563": "Remote Service Session Hijacking",
    },
    "Collection": {
        "T1005": "Data from Local System",
        "T1114": "Email Collection",
        "T1119": "Automated Collection",
        "T1115": "Clipboard Data",
    },
    "Command and Control": {
        "T1071": "Application Layer Protocol",
        "T1071.001": "Application Layer Protocol: Web Protocols",
        "T1105": "Ingress Tool Transfer",
        "T1090": "Proxy",
        "T1573": "Encrypted Channel",
    },
    "Exfiltration": {
        "T1020": "Automated Exfiltration",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1567": "Exfiltration Over Web Service",
        "T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    },
    "Impact": {
        "T1485": "Data Destruction",
        "T1486": "Data Encrypted for Impact",
        "T1489": "Service Stop",
        "T1491": "Defacement",
    },
}


def _build_inverse_lookup() -> MappingProxyType[str, tuple[str, str]]:
    """
    Builds an immutable technique-ID → (name, tactic) index from MITRE_CATALOG.

    Keeps the first tactic mapping when a technique appears under multiple tactics.

    Returns:
        An immutable mapping of technique ID to a tuple of (name, tactic).
    """
    result: dict[str, tuple[str, str]] = {}
    for tactic_name, techniques in MITRE_CATALOG.items():
        for tech_id, name in techniques.items():
            if tech_id not in result:
                result[tech_id] = (name, tactic_name)
    return MappingProxyType(result)


# Inverse index for quick technique-to-tactic lookup
# Structure: { technique_id: (official_name, standardized_tactic) }
INVERSE_LOOKUP = _build_inverse_lookup()


def _resolve_id_by_name(raw_name: str) -> tuple[str, str] | None:
    """
    Searches the catalog for a technique matching raw_name (case-insensitive).

    Args:
        raw_name: The name of the technique to search for.

    Returns:
        A tuple of (technique_id, official_name) on match, or None.
    """
    target = raw_name.lower()
    for _tactic, techs in MITRE_CATALOG.items():
        for tid, name in techs.items():
            if name.lower() == target:
                return tid, name
    return None


def normalize_tactic(raw_tactic: str) -> str:
    """
    Standardizes a Sentinel or raw tactic name to official MITRE ATT&CK spelling.
    E.g. 'InitialAccess' -> 'Initial Access', 'credentialaccess' -> 'Credential Access'.

    Args:
        raw_tactic: The raw tactic name to normalize.

    Returns:
        The normalized tactic name string.
    """
    if not raw_tactic:
        return "Unknown"

    # Strip spaces, hyphens, and convert to lowercase for comparison
    clean = re.sub(r"[\s_-]", "", raw_tactic).lower()
    return TACTIC_MAPPING.get(clean, raw_tactic.strip().title())


def validate_and_enrich_techniques(
    suggested_techniques: list[dict], incident_tactics: list[str]
) -> tuple[list[dict], list[str]]:
    """
    Validates, normalizes, and enriches suggested MITRE techniques.

    Auto-corrects:
      - Typos/variations in technique names if the ID is valid.
      - Technique IDs if a exact name match is found.
      - Normalizes tactic names.

    Args:
        suggested_techniques: A list of dicts like [{"technique_id": "T1098", "name": "...", "confidence": 90}]
        incident_tactics: List of raw tactic names detected on the incident.

    Returns:
        A tuple: (list of verified techniques, list of non-fatal warnings or error strings).
    """
    verified = []
    warnings = []
    seen_ids = set()

    # Normalize incident tactics for comparison
    normalized_incident_tactics = {normalize_tactic(t) for t in incident_tactics if t}

    for item in suggested_techniques:
        if not isinstance(item, dict):
            continue

        raw_id = str(item.get("technique_id", "")).strip().upper()
        raw_name = str(item.get("name", "")).strip()
        confidence = item.get("confidence", 50)

        # Clean up technique ID formatting (e.g. T1078.001 instead of T1078_001)
        raw_id = raw_id.replace("_", ".")

        # Validate ID pattern
        if not TECHNIQUE_ID_PATTERN.match(raw_id):
            resolved = _resolve_id_by_name(raw_name)
            if resolved:
                raw_id, raw_name = resolved
                logger.info("Resolved technique ID %s for name '%s'", raw_id, raw_name)
            else:
                msg = f"MITRE Warning: Discarded technique '{raw_name}' with invalid ID format '{raw_id}'"
                logger.warning(msg)
                warnings.append(msg)
                continue

        # Deduplicate
        if raw_id in seen_ids:
            continue

        # Perform catalog lookup
        if raw_id in INVERSE_LOOKUP:
            official_name, official_tactic = INVERSE_LOOKUP[raw_id]

            # Check for name correction
            if raw_name.lower() != official_name.lower():
                logger.info(
                    "Auto-corrected technique %s name from '%s' to '%s'",
                    raw_id,
                    raw_name,
                    official_name,
                )

            # Group under the official tactic
            tactic = official_tactic

            # If the resolved tactic is not in the incident tactics list, note a weak correlation
            if (
                normalized_incident_tactics
                and tactic not in normalized_incident_tactics
            ):
                logger.debug(
                    "Technique %s (%s) tactic '%s' is not in incident tactics %s",
                    raw_id,
                    official_name,
                    tactic,
                    normalized_incident_tactics,
                )

            verified.append(
                {
                    "technique_id": raw_id,
                    "name": official_name,
                    "tactic": tactic,
                    "confidence": confidence,
                }
            )
            seen_ids.add(raw_id)
        else:
            # Technique ID looks valid but is not in our local static catalog
            # We preserve it to support custom/niche techniques, but flag it
            msg = f"MITRE Info: Technique ID '{raw_id}' ({raw_name}) is valid but not in the local verification catalog."
            logger.info(msg)

            # Infer a basic tactic based on raw input or inverse lookup or default
            suggested_tactic = normalize_tactic(item.get("tactic", "Unknown"))

            verified.append(
                {
                    "technique_id": raw_id,
                    "name": raw_name,
                    "tactic": suggested_tactic,
                    "confidence": confidence,
                    "unverified": True,
                }
            )
            seen_ids.add(raw_id)

    return verified, warnings
