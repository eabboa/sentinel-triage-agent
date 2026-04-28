"""
main.py
Entry point. Fetches open Sentinel incidents and runs each through the triage graph.

Rate limit strategy:
- Fetch up to 5 incidents per run (covers Gemini free tier quota per cycle)
- Sleep 30 seconds between incidents (gives VT free tier room to breathe)
- Run this script manually or via Windows Task Scheduler / cron for polling
"""

import time
from dotenv import load_dotenv
from sentinel_api import list_incidents
from graph import build_graph

load_dotenv()


def main():
    print("Sentinel Triage Agent starting...")
    
    # Fetch new, unprocessed incidents
    incidents = list_incidents(status_filter="New", max_results=5)
    
    if not incidents:
        print("No new incidents found. Exiting.")
        return

    print(f"Found {len(incidents)} incident(s) to triage.")
    graph = build_graph()

    for i, incident in enumerate(incidents):
        incident_id = incident["name"]  # Sentinel uses 'name' as the unique ID
        incident_title = incident["properties"]["title"]
        
        print(f"\n[{i+1}/{len(incidents)}] Processing: {incident_title} (ID: {incident_id})")

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
            "errors": [],
        }

        try:
            final_state = graph.invoke(initial_state)
            
            print(f"  ✓ Classification: {final_state['classification']}")
            print(f"  ✓ Comment posted: {final_state['comment_posted']}")
            print(f"  ✓ Incident closed: {final_state['incident_closed']}")
            
            if final_state.get("errors"):
                print(f"  ⚠ Non-fatal errors: {final_state['errors']}")

        except Exception as e:
            print(f"  ✗ Pipeline failed for {incident_id}: {e}")

        # Rate limit protection between incidents
        if i < len(incidents) - 1:
            print(f"  Sleeping 30s (rate limit protection)...")
            time.sleep(30)

    print("\nBatch complete.")


if __name__ == "__main__":
    main()