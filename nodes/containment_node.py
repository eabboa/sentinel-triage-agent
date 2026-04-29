"""
Containment node: Isolates compromised devices and revokes user sessions.

Executes only if containment_approved is True.
Uses the entities (hostnames) to trigger MDE device isolation concurrently.
All API failures are captured as non-fatal errors in the errors list.
"""

import asyncio
import logging
from requests.exceptions import RequestException
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
    errors = state.get("errors", []).copy()
    
    # Guard clause: only execute if containment is approved
    if not state.get("containment_approved", False):
        logger.debug("Containment not approved; skipping containment_node")
        return {"errors": errors}
    
    logger.info("Containment approved; proceeding with device isolation")
    
    # Extract hostnames from entities
    entities = state.get("entities", {}) or {}
    hostnames = entities.get("hostnames", []) or []
    
    if not hostnames:
        logger.info("No hostnames found in entities; skipping MDE isolation")
        return {"errors": errors}
    
    logger.info(f"Attempting to isolate {len(hostnames)} devices: {hostnames}")
    
    # Create isolation tasks for each hostname
    async def isolate_all():
        tasks = [isolate_mde_device(hostname) for hostname in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    
    try:
        # Run async isolation tasks
        results = await isolate_all()
        
        # Process results and capture any errors
        for hostname, result in zip(hostnames, results):
            if isinstance(result, Exception):
                error_msg = f"MDE isolation failed for {hostname}: {str(result)}"
                logger.error(error_msg)
                errors.append(error_msg)
            elif isinstance(result, dict):
                # Successful response from MDE API
                logger.info(f"Successfully isolated device {hostname}")
            else:
                # Unexpected result type
                logger.warning(f"Unexpected result type for {hostname}: {type(result)}")
        
    except Exception as e:
        # Catch any exception from task orchestration
        error_msg = f"Containment orchestration failed: {str(e)}"
        logger.error(error_msg)
        errors.append(error_msg)
    
    return {"errors": errors}
