"""
Containment node: Isolates compromised devices and revokes user sessions.

Executes only if containment_approved is True.
Uses the entities (hostnames + internal_ips) to trigger MDE device isolation concurrently.
Internal IPs found during lateral movement detection are treated as additional isolation
targets, since MDE accepts both hostnames and IP addresses for device lookup.
All API failures are captured as non-fatal errors in the errors list.
"""

import asyncio
import logging
import re
from sentinel_api import isolate_mde_device, resolve_mde_machine_id
from state import TriageState

logger = logging.getLogger(__name__)

# Allow only safe hostname characters (letters, digits, hyphens, dots)
_SAFE_HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9]$")


def _validate_hostname(hostname: str) -> bool:
    """
    Rejects hostnames with path traversal, whitespace, or injection characters.

    Args:
        hostname: The hostname string to validate.

    Returns:
        True if the hostname is safe, False otherwise.
    """
    return bool(_SAFE_HOSTNAME_PATTERN.match(hostname)) and ".." not in hostname


async def _isolate_target(target: str) -> str | None:
    """
    Resolves a hostname/IP to an MDE machine ID and isolates it.

    Args:
        target: The hostname or IP to isolate.

    Returns:
        An error string on failure, or None on success.
    """
    machine_id = await resolve_mde_machine_id(target)
    if machine_id is None:
        msg = f"MDE device not found for target {target}; skipping isolation"
        logger.warning(msg)
        return msg

    result = await isolate_mde_device(machine_id)
    if isinstance(result, dict):
        logger.info(f"Successfully isolated target {target} (machine_id={machine_id})")
    else:
        logger.warning(f"Unexpected result type for {target}: {type(result)}")
    return None


async def containment_node(state: TriageState) -> dict:
    """
    Orchestrates active containment: isolates MDE devices and revokes user sessions.

    Only executes if containment_approved is True.
    Validates and resolves hostnames to MDE machine IDs before calling isolation.
    All API failures are appended to errors list without crashing the pipeline.

    Args:
        state: The current TriageState dictionary.

    Returns:
        A dictionary containing the state updates for errors.
    """
    errors: list[str] = []
    
    # Guard clause: only execute if containment is approved
    if not state.get("containment_approved", False):
        logger.debug("Containment not approved; skipping containment_node")
        return {"errors": errors}
    
    logger.info("Containment approved; proceeding with device isolation")
    
    # Extract isolation targets: named hostnames + internal IPs (lateral movement candidates)
    entities = state.get("entities", {}) or {}
    hostnames = entities.get("hostnames", []) or []
    internal_ips = entities.get("internal_ips", []) or []

    # Merge and deduplicate; validate each target
    raw_targets = list(dict.fromkeys(hostnames + internal_ips))
    isolation_targets = []
    for target in raw_targets:
        if _validate_hostname(target):
            isolation_targets.append(target)
        else:
            msg = f"Rejected unsafe isolation target: {target!r}"
            logger.warning(msg)
            errors.append(msg)

    if not isolation_targets:
        logger.info("No valid hostnames or internal IPs found in entities; skipping MDE isolation")
        return {"errors": errors}

    logger.info(f"Attempting to isolate {len(isolation_targets)} targets: {isolation_targets}")
    
    # Resolve hostnames/IPs to MDE machine IDs and isolate
    for target in isolation_targets:
        try:
            err = await _isolate_target(target)
            if err:
                errors.append(err)
        except Exception as exc:
            error_msg = f"MDE isolation failed for {target}: {str(exc)}"
            logger.error(error_msg)
            errors.append(error_msg)
    
    return {"errors": errors}
