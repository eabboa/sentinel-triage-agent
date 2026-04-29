"""
main.py
Entry point. Fetches open Sentinel incidents and runs each through the triage graph asynchronously.

Rate limit strategy:
- Fetch up to 5 incidents per run (covers Gemini free tier quota per cycle)
- Use asyncio.Semaphore(3) to limit concurrent API calls and respect Gemini rate limits
- Run this script manually or via Windows Task Scheduler / cron for polling
"""

import asyncio
from dotenv import load_dotenv
import uuid
from sentinel_api import list_incidents
from graph import build_graph

load_dotenv()


async def process_incident(incident, graph, semaphore, console_lock):
    incident_id = incident["name"]  # Sentinel uses 'name' as the unique ID
    incident_title = incident["properties"]["title"]
    
    print(f"Processing: {incident_title} (ID: {incident_id})")

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
        "kql_queries": [],
        "comment_posted": False,
        "incident_closed": False,
        "close_approved": False,
        "errors": [],
    }

    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}

    async with semaphore: # Limit concurrent processing to respect API rate limits
        try:
            state = await graph.ainvoke(initial_state, config=config)
            
            snapshot = graph.get_state(config)
            if snapshot.next:
                state_vals = snapshot.values
                
                async with console_lock:
                    print(f"\n--- Review Required for {incident_title} (ID: {incident_id}) ---")
                    print(f"  ✓ Classification: {state_vals.get('classification')}")
                    print(f"  ✓ Triage Summary: {state_vals.get('triage_summary')}")
                    
                    entities = state_vals.get("entities", {})
                    hostnames = entities.get("hostnames", [])
                    if hostnames:
                        print(f"  [!] Containment candidate hostnames: {hostnames}")
                        cont_approval = await asyncio.to_thread(input, "  Approve containment of hostnames? [y/N]: ")
                        if cont_approval.strip().lower() == 'y':
                            graph.update_state(config, {"containment_approved": True})
                    
                    approval = await asyncio.to_thread(input, "  Approve closure? [y/N]: ")
                    if approval.strip().lower() == 'y':
                        graph.update_state(config, {"close_approved": True})
                    else:
                        print("  Skipping closure.")
                        
                state = await graph.ainvoke(None, config=config)
            
            final_state = state
            
            print(f"  ✓ Classification: {final_state.get('classification')}")
            print(f"  ✓ Comment posted: {final_state.get('comment_posted')}")
            print(f"  ✓ Incident closed: {final_state.get('incident_closed')}")
            
            if final_state.get("errors"):
                print(f"  ⚠ Non-fatal errors: {final_state['errors']}")

        except Exception as e:
            print(f"  ✗ Pipeline failed for {incident_id}: {e}")


async def main():
    print("Sentinel Triage Agent starting...")
    
    # Fetch new, unprocessed incidents
    incidents = list_incidents(status_filter="New", max_results=5)
    
    if not incidents:
        print("No new incidents found. Exiting.")
        return

    print(f"Found {len(incidents)} incident(s) to triage.")
    graph, checkpointer = build_graph()
    semaphore = asyncio.Semaphore(3)
    console_lock = asyncio.Lock()

    tasks = [process_incident(incident, graph, semaphore, console_lock) for incident in incidents]
    await asyncio.gather(*tasks)

    print("\nBatch complete.")


# Shutdown hook example:
#
# from nodes.learning_node import flush_and_shutdown
#
# async def on_shutdown() -> None:
#     await flush_and_shutdown() ## Flush any pending learning data and perform cleanup before shutdown
#
#
# For CLI applications, use asyncio signal handlers to trigger graceful shutdown
# and call `await flush_and_shutdown()` before exiting.

if __name__ == "__main__":
    asyncio.run(main())