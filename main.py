"""
main.py
Entry point. Fetches open Sentinel incidents and runs each through the triage graph asynchronously.

Rate limit strategy:
- Fetch up to 5 incidents per run (covers Gemini free tier quota per cycle)
- Use asyncio.Semaphore(3) to limit concurrent API calls and respect Gemini rate limits
- Run this script manually or via Windows Task Scheduler / cron for polling
"""

import asyncio
import random
import sys
import time
import uuid
from typing import Any

import structlog
from dotenv import load_dotenv

from graph import build_graph
from logging_config import setup_logging
from metrics import TRIAGE_DURATION, TRIAGE_FP_TOTAL, TRIAGE_TOTAL
from nodes.containment_node import _validate_entra_user
from nodes.enrich_node import close_session as close_enrich_session
from nodes.learning_node import flush_and_shutdown
from sentinel_api import list_incidents

setup_logging()
logger = structlog.get_logger(__name__)

load_dotenv()


async def _collect_human_decisions(
    state_vals: dict,
    incident_title: str,
    incident_id: str,
    console_lock: asyncio.Lock,
) -> dict:
    """
    Collects analyst decisions via console prompts.

    Performs NO graph mutations; if this function raises, the checkpoint remains clean.

    Args:
        state_vals: Dictionary containing current values from the TriageState.
        incident_title: The Sentinel incident title.
        incident_id: The Sentinel incident ID.
        console_lock: An asyncio.Lock to prevent concurrent stdout/stdin interleaving.

    Returns:
        A dictionary of state updates to apply.
    """
    updates: dict[str, Any] = {}

    async with console_lock:
        print(f"\n--- Review Required for {incident_title} (ID: {incident_id}) ---")
        print(f"  ✓ Classification: {state_vals.get('classification')}")
        print(f"  ✓ Triage Summary: {state_vals.get('triage_summary')}")

        entities = state_vals.get("entities", {})
        hostnames = entities.get("hostnames", [])
        internal_ips = entities.get("internal_ips", [])
        usernames = entities.get("usernames", [])
        # Only surface users Graph can actually revoke (UPN or object-ID GUID).
        revocable_users = [u for u in usernames if _validate_entra_user(u)]
        isolation_targets = list(dict.fromkeys(hostnames + internal_ips))

        if isolation_targets or revocable_users:
            if isolation_targets:
                print(f"  [!] Containment candidate devices: {isolation_targets}")
            if revocable_users:
                print(f"  [!] Session-revocation candidate users: {revocable_users}")
            cont_approval = await asyncio.to_thread(
                input,
                "  Approve containment (device isolation + session revocation)? [y/N]: ",
            )
            if cont_approval.strip().lower() == "y":
                updates["containment_approved"] = True

        approval = await asyncio.to_thread(input, "  Approve closure? [y/N]: ")
        if approval.strip().lower() == "y":
            updates["close_approved"] = True
        else:
            print("  Skipping closure.")

        # ── Human reclassification for RAG learning ───────────────────
        llm_classification = state_vals.get("classification", "")
        VALID_CLASSIFICATIONS = {"TruePositive", "FalsePositive", "BenignPositive"}
        while True:
            reclassify = await asyncio.to_thread(
                input,
                f"  Reclassify? LLM said '{llm_classification}'. "
                f"Enter correct label [TruePositive/FalsePositive/BenignPositive] "
                f"or press Enter to agree: ",
            )
            reclassify = reclassify.strip()
            if not reclassify:
                break  # Analyst agrees with LLM
            if reclassify not in VALID_CLASSIFICATIONS:
                print(
                    f"  ⚠ Invalid label '{reclassify}' — must be one of {VALID_CLASSIFICATIONS}. Try again."
                )
                continue
            if reclassify == llm_classification:
                break  # Explicitly typed the same label — treat as agreement
            updates["human_classification"] = reclassify
            reclassify_reason = await asyncio.to_thread(
                input, "  Provide reason for reclassification (the 'WHY'): "
            )
            reclassify_reason = reclassify_reason.strip()
            if reclassify_reason:
                updates["human_classification_reason"] = reclassify_reason
            else:
                updates["human_classification_reason"] = (
                    "No reason provided by analyst."
                )
            print(f"  ✓ Reclassification '{reclassify}' recorded for learning.")
            break
        # ─────────────────────────────────────────────────────────────

        # ── Prometheus: false-positive rate tracking ──────────────────
        final_label = updates.get("human_classification", llm_classification)
        if final_label in VALID_CLASSIFICATIONS:
            TRIAGE_TOTAL.inc()
            if final_label == "FalsePositive":
                TRIAGE_FP_TOTAL.inc()
        # ─────────────────────────────────────────────────────────────

    return updates


async def process_incident(incident, graph, semaphore, console_lock):
    """
    Processes a single incident through the langgraph engine with human-in-the-loop support.

    Args:
        incident: The raw Sentinel incident dictionary.
        graph: The compiled langgraph StateGraph.
        semaphore: Concurrency limiter.
        console_lock: Console access lock for HITL prompting.

    Returns:
        None
    """
    incident_id = incident["name"]  # Sentinel uses 'name' as the unique ID
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(incident_id=incident_id)
    incident_title = incident["properties"]["title"]

    logger.info(f"Processing: {incident_title} (ID: {incident_id})")

    # Initialize state with only the incident_id | the fetch node gets the rest
    initial_state = {
        "incident_id": incident_id,
        # All other fields start empty. Nodes fill them later over time.
        "incident_title": "",
        "incident_severity": "",
        "incident_description": "",
        "incident_status": "",
        "incident_tactics": [],
        "raw_alerts": [],
        "condensed_summary": "",
        "entities": {},
        "cti_results": {},
        "is_true_positive": False,
        "classification": "",
        "triage_summary": "",
        "mitre_analysis": "",
        "mitre_techniques": [],
        "mitre_enrichment": [],
        "kql_queries": [],
        "confidence": 0,
        "containment_approved": False,
        "escalation_triggered": False,
        "escalation_summary": "",
        "human_classification": None,
        "human_classification_reason": None,
        "comment_posted": False,
        "incident_closed": False,
        "close_approved": False,
        "errors": [],
    }

    # Deterministic thread_id enables HITL resume after crash with persistent checkpointer
    thread_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel-triage:{incident_id}"))
    config = {"configurable": {"thread_id": thread_id}}

    triage_start = time.monotonic()
    async with semaphore:  # Limit concurrent processing to respect API rate limits

        # ── Phase 1: Graph engine pre-HITL execution ──────────────────────
        try:
            state = await graph.ainvoke(initial_state, config=config)
            snapshot = await asyncio.get_running_loop().run_in_executor(
                None, graph.get_state, config
            )
        except Exception as e:
            logger.critical(
                "Graph engine failed for %s during pre-HITL execution: %s",
                incident_id,
                e,
                exc_info=True,
            )
            return  # Nothing to resume — no state was committed

        if not snapshot.next:
            """
            Graph always will hit the HITL normally, however, this code block is necessary
            if the incident has already finished (resuming a completed checkpoint) or
            if the interrupt_after configuration is changed or disabled.
            """
            final_state = state
        else:
            # ── Phase 2: Human-in-the-loop console interaction ────────────
            try:
                human_decisions = await _collect_human_decisions(
                    snapshot.values,
                    incident_title,
                    incident_id,
                    console_lock,
                )
            except (EOFError, KeyboardInterrupt):
                logger.warning(
                    "Analyst session lost for %s (EOF/interrupt). "
                    "Incident is paused at HITL checkpoint and can be resumed.",
                    incident_id,
                )
                return  # Checkpoint is clean — no state mutations occurred
            except OSError as e:
                logger.error(
                    "Console I/O failure for %s: %s. "
                    "Incident is paused at HITL checkpoint.",
                    incident_id,
                    e,
                )
                return

            # ── Phase 3a: Apply human decisions to graph state ────────────
            try:
                if human_decisions:
                    graph.update_state(config, human_decisions)
            except Exception as e:
                logger.critical(
                    "State mutation failed for %s after analyst approved actions %s: %s. "
                    "MANUAL INTERVENTION REQUIRED — checkpoint may be inconsistent.",
                    incident_id,
                    list(human_decisions.keys()),
                    e,
                    exc_info=True,
                )
                return  # Do NOT resume the graph with potentially partial state

            # ── Phase 3b: Resume the graph post-HITL ─────────────────────
            containment_was_approved = human_decisions.get(
                "containment_approved", False
            )
            try:
                state = await graph.ainvoke(None, config=config)
            except Exception as e:
                if containment_was_approved:
                    logger.critical(
                        "Graph resumption failed for %s: %s. "
                        "containment_approved=True — "
                        "CONTAINMENT MAY NOT HAVE EXECUTED — verify manually.",
                        incident_id,
                        e,
                        exc_info=True,
                    )
                else:
                    logger.error(
                        "Graph resumption failed for %s: %s. "
                        "Incident remains at post-HITL checkpoint.",
                        incident_id,
                        e,
                        exc_info=True,
                    )
                return

            final_state = state

        # ── Phase 4: Final state logging (unguarded — crash = bug) ────────
        logger.info(f"  ✓ Classification: {final_state.get('classification')}")
        logger.info(f"  ✓ Comment posted: {final_state.get('comment_posted')}")
        logger.info(f"  ✓ Incident closed: {final_state.get('incident_closed')}")

        if final_state.get("errors"):
            logger.warning(f"  ⚠ Non-fatal errors: {final_state['errors']}")

        TRIAGE_DURATION.observe(time.monotonic() - triage_start)


async def main():
    """
    Main entry point for fetching and processing new Sentinel incidents.

    Returns:
        None
    """
    logger.info("Sentinel Triage Agent starting...")

    # Fetch new, unprocessed incidents with retries
    incidents = None
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            incidents = list_incidents(status_filter="New", max_results=5)
            break
        except Exception as e:
            if attempt < max_attempts:
                delay = (2**attempt) + random.uniform(0, 1)
                logger.warning(
                    f"Failed to fetch incidents (attempt {attempt}/{max_attempts}): {e}. Retrying in {delay:.2f} seconds..."
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    f"Failed to fetch incidents after {max_attempts} attempts: {e}",
                    exc_info=True,
                )
                sys.exit(1)

    if not incidents:
        logger.info("No new incidents found. Exiting.")
        return

    logger.info(f"Found {len(incidents)} incident(s) to triage.")
    graph, checkpointer = build_graph()
    semaphore = asyncio.Semaphore(3)
    console_lock = asyncio.Lock()

    try:
        tasks = [
            process_incident(incident, graph, semaphore, console_lock)
            for incident in incidents
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for incident, result in zip(incidents, results):
            if isinstance(result, Exception):
                logger.error(
                    "Pipeline failed for %s: %s",
                    incident.get("name", "unknown"),
                    result,
                    exc_info=result,
                )
        logger.info("\nBatch complete.")
    finally:
        logger.info("Flushing learning queue before exit...")
        await flush_and_shutdown()  # flush_and_shutdown() drains all pending ChromaDB writes and shuts down the process pool executor cleanly.
        await close_enrich_session()


if __name__ == "__main__":
    asyncio.run(main())
