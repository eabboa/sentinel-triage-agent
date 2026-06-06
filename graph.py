"""
Assembles all nodes into the LangGraph StateGraph.

Node execution order:
  fetch → summarize → extract → enrich → analyst → kql → writeback → containment → close_review → learning

Future branching opportunity: after analyst_node, branch on severity.
High-severity incidents could trigger an additional "escalation" node that
pages the on-call analyst via Teams webhook, while Medium/Low go directly
to writeback.
"""

from typing import Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, START, END
from state import TriageState
from nodes.fetch_node import fetch_node
from nodes.summarize_node import summarize_node
from nodes.extract_node import extract_node
from nodes.enrich_node import enrich_node
from nodes.analyst_node import analyst_node
from nodes.kql_node import kql_node
from nodes.writeback_node import close_review_node, writeback_node
from nodes.learning_node import learning_node
from nodes.containment_node import containment_node


def _next_after_extract(state: TriageState) -> Literal["analyst", "enrich"]:
    """
    Routes directly to analyst when no actionable entities were extracted.

    Args:
        state: The current TriageState.

    Returns:
        "enrich" if actionable entities exist, otherwise "analyst".
    """
    entities = state.get("entities", {}) or {}
    if any(entities.get(key) for key in ("ips", "hashes", "urls")):
        return "enrich"
    return "analyst"


def _next_after_analyst(state: TriageState) -> Literal["escalation", "writeback", "kql"]:
    """
    Chooses the next node based on analyst classification and confidence.

    Args:
        state: The current TriageState.

    Returns:
        "escalation", "writeback", or "kql" depending on classification and confidence.
    """
    classification = state.get("classification", "")
    confidence = state.get("confidence", 0)

    if classification == "TruePositive" and confidence > 90:
        return "escalation"
    if classification == "FalsePositive" and confidence > 95:
        return "writeback"
    return "kql"


def _next_after_writeback(state: TriageState) -> Literal["containment", "close_review"]:
    """
    Routes based on approval status.
    
    No autonomous closure occurs regardless of classification or confidence score.
    If containment is approved, run containment before close_review.

    Args:
        state: The current TriageState.

    Returns:
        "containment" if containment is approved, otherwise "close_review".
    """
    # If containment is approved, run containment before close_review
    if state.get("containment_approved", False):
        return "containment"
    
    return "close_review"


def escalation_node(state: TriageState) -> dict:
    """
    Placeholder escalation node for high-confidence TruePositive incidents.

    Args:
        state: The current TriageState.

    Returns:
        A dict with state updates reflecting escalation.
    """
    return {
        "escalation_triggered": True,
        "escalation_summary": "This incident requires escalation before writeback.",
    }


def build_graph():
    """
    Constructs and compiles the triage graph.

    Returns:
        A tuple containing the compiled StateGraph and the MemorySaver checkpointer.
    """
    builder = StateGraph(TriageState)  # type: ignore

    # Register all nodes
    builder.add_node("fetch", fetch_node)
    builder.add_node("summarize", summarize_node)
    builder.add_node("extract", extract_node)
    builder.add_node("enrich", enrich_node)
    builder.add_node("analyst", analyst_node)
    builder.add_node("kql", kql_node)
    builder.add_node("escalation", escalation_node)
    builder.add_node("writeback", writeback_node)
    builder.add_node("containment", containment_node)
    builder.add_node("close_review", close_review_node)
    builder.add_node("learning", learning_node)

    # Define the execution order with conditional routing
    builder.add_edge(START, "fetch")
    builder.add_edge("fetch", "summarize")
    builder.add_edge("summarize", "extract")
    builder.add_conditional_edges("extract", _next_after_extract)
    builder.add_edge("enrich", "analyst")
    builder.add_conditional_edges("analyst", _next_after_analyst)
    builder.add_edge("kql", "writeback")
    builder.add_edge("escalation", "writeback")
    builder.add_conditional_edges("writeback", _next_after_writeback)
    builder.add_edge("containment", "close_review")
    builder.add_edge("close_review", "learning")
    builder.add_edge("learning", END)

    checkpointer = MemorySaver() # TODO: In Production use AsyncSqliteSaver or PostgresSaver
    """
    MemorySaver is only for the development stage.
    It fails when the Python process crashes. The memory is completely wiped.   
    """
    compiled_graph = builder.compile(
        interrupt_after=["writeback"],
        checkpointer=checkpointer,
    )
    return compiled_graph, checkpointer
