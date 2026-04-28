"""
Assembles all nodes into the LangGraph StateGraph.

Node execution order:
  fetch → summarize → extract → enrich → analyst → kql → writeback

Future branching opportunity: after analyst_node, branch on severity.
High-severity incidents could trigger an additional "escalation" node that
pages the on-call analyst via Teams webhook, while Medium/Low go directly
to writeback.
"""

from langgraph.graph import StateGraph, START, END
from state import TriageState
from nodes.fetch_node import fetch_node
from nodes.summarize_node import summarize_node
from nodes.extract_node import extract_node
from nodes.enrich_node import enrich_node
from nodes.analyst_node import analyst_node
from nodes.kql_node import kql_node
from nodes.writeback_node import writeback_node


def build_graph():
    """Constructs and compiles the triage graph."""
    builder = StateGraph(TriageState)

    # Register all nodes
    builder.add_node("fetch", fetch_node)
    builder.add_node("summarize", summarize_node)
    builder.add_node("extract", extract_node)
    builder.add_node("enrich", enrich_node)
    builder.add_node("analyst", analyst_node)
    builder.add_node("kql", kql_node)
    builder.add_node("writeback", writeback_node)

    # Define the execution order (linear chain)
    builder.add_edge(START, "fetch")
    builder.add_edge("fetch", "summarize")
    builder.add_edge("summarize", "extract")
    builder.add_edge("extract", "enrich")
    builder.add_edge("enrich", "analyst")
    builder.add_edge("analyst", "kql")
    builder.add_edge("kql", "writeback")
    builder.add_edge("writeback", END)

    return builder.compile()