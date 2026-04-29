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
from sentinel_api import list_incidents
from graph import build_graph

load_dotenv()


async def process_incident(incident, graph, semaphore):
    incident_id = incident["name"]  # Sentinel uses 'name' as the unique ID
    incident_title = incident["properties"]["title"]
    
    print(f"Processing: {incident_title} (ID: {incident_id})")

    # Initialize state with only the incident_id | the fetch node gets the rest
    initial_state = {
        "incident_id": incident_id,
        # All other fields start empty. Nodes populate them over time.
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

    async with semaphore:
        try:
            final_state = await graph.ainvoke(initial_state)
            
            print(f"  ✓ Classification: {final_state['classification']}")
            print(f"  ✓ Comment posted: {final_state['comment_posted']}")
            print(f"  ✓ Incident closed: {final_state['incident_closed']}")
            
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
    graph = build_graph()
    semaphore = asyncio.Semaphore(3)

    tasks = [process_incident(incident, graph, semaphore) for incident in incidents]
    await asyncio.gather(*tasks)

    print("\nBatch complete.")


# Shutdown hook example:
#
# from nodes.learning_node import flush_and_shutdown
#
# async def on_shutdown() -> None:
#     await flush_and_shutdown()
#
#
# For CLI applications, use asyncio signal handlers to trigger graceful shutdown
# and call `await flush_and_shutdown()` before exiting.

if __name__ == "__main__":
    asyncio.run(main())