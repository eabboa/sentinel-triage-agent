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
from sentinel_api import isolate_mde_device
from state import TriageState

logger = logging.getLogger(__name__)


async def containment_node(state: TriageState) -> dict:
    """
    Orchestrates active containment: isolates MDE devices and revokes user sessions.
    
    Only executes if containment_approved is True.
    Parses hostnames from entities and triggers isolation concurrently.
    All API failures are appended to errors list without crashing the pipeline.
    """
    errors = []
    
    # Guard clause: only execute if containment is approved
    if not state.get("containment_approved", False):
        logger.debug("Containment not approved; skipping containment_node")
        return {"errors": errors}
    
    logger.info("Containment approved; proceeding with device isolation")
    
    # Extract isolation targets: named hostnames + internal IPs (lateral movement candidates)
    entities = state.get("entities", {}) or {}
    hostnames = entities.get("hostnames", []) or []
    internal_ips = entities.get("internal_ips", []) or []

    # Merge and deduplicate; hostnames take priority but IPs are valid MDE targets too
    isolation_targets = list(dict.fromkeys(hostnames + internal_ips))

    if not isolation_targets:
        logger.info("No hostnames or internal IPs found in entities; skipping MDE isolation")
        return {"errors": errors}

    logger.info(f"Attempting to isolate {len(isolation_targets)} targets: {isolation_targets}")
    
    # Create isolation tasks for each target
    async def isolate_all():
        tasks = [isolate_mde_device(target) for target in isolation_targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    
    try:
        # Run async isolation tasks
        results = await isolate_all()
        
        # Process results and capture any errors
        for target, result in zip(isolation_targets, results):
            if isinstance(result, Exception):
                error_msg = f"MDE isolation failed for {target}: {str(result)}"
                logger.error(error_msg)
                errors.append(error_msg)
            elif isinstance(result, dict):
                logger.info(f"Successfully isolated target {target}")
            else:
                logger.warning(f"Unexpected result type for {target}: {type(result)}")
        
    except Exception as e:
        # Catch any exception from task orchestration
        error_msg = f"Containment orchestration failed: {str(e)}"
        logger.error(error_msg)
        errors.append(error_msg)
    
    return {"errors": errors}
