"""
Behavioral Contract for learning_node.py

Valid Input:
- TriageState containing 'classification' (LLM) and 'human_classification'.

Expected Output:
- If a mismatch is detected, the incident details and corrections are added to a non-blocking asyncio.Queue.
- Returns empty dict.

Failure Modes:
- If ChromaDB is unavailable, the circuit breaker opens to prevent blocking, and subsequent errors are logged.
- If queue is full, payloads are dropped (Data loss occurs but pipeline latency is preserved).

Concurrency Invariants:
- Queue insertion is thread-safe/async-safe and strictly non-blocking.
- Uses ProcessPoolExecutor to offload SentenceTransformer embedding encoding so it does not block the async event loop.
"""

import pytest
from unittest.mock import patch, AsyncMock
from nodes.learning_node import learning_node, embed_and_store, learning_queue

@pytest.mark.asyncio
async def test_learning_node_mismatch_queues_payload(empty_triage_state):
    """Asserts a mismatch triggers asynchronous queueing."""
    state = empty_triage_state.copy()
    state["classification"] = "FalsePositive"
    state["human_classification"] = "TruePositive"
    state["condensed_summary"] = "Test"
    state["triage_summary"] = "LLM was wrong"
    
    with patch("nodes.learning_node.embed_and_store", new_callable=AsyncMock) as mock_embed:
        result = await learning_node(state)
        assert result == {}
        mock_embed.assert_called_once()

@pytest.mark.asyncio
async def test_learning_node_match_does_nothing(empty_triage_state):
    """Asserts identical classifications bypass queueing."""
    state = empty_triage_state.copy()
    state["classification"] = "TruePositive"
    state["human_classification"] = "TruePositive"
    
    with patch("nodes.learning_node.embed_and_store", new_callable=AsyncMock) as mock_embed:
        result = await learning_node(state)
        assert result == {}
        mock_embed.assert_not_called()


@pytest.mark.asyncio
async def test_learning_node_no_human_classification(empty_triage_state):
    """Asserts missing human_classification defaults to LLM classification and bypasses queueing."""
    state = empty_triage_state.copy()
    state["classification"] = "TruePositive"
    # human_classification defaults to llm_classification when absent
    state.pop("human_classification", None)

    with patch("nodes.learning_node.embed_and_store", new_callable=AsyncMock) as mock_embed:
        result = await learning_node(state)
        assert result == {}
        mock_embed.assert_not_called()


@pytest.mark.asyncio
async def test_learning_node_empty_human_classification(empty_triage_state):
    """Asserts empty human_classification string bypasses queueing."""
    state = empty_triage_state.copy()
    state["classification"] = "TruePositive"
    state["human_classification"] = ""

    with patch("nodes.learning_node.embed_and_store", new_callable=AsyncMock) as mock_embed:
        result = await learning_node(state)
        assert result == {}
        mock_embed.assert_not_called()


@pytest.mark.asyncio
async def test_embed_and_store_queue_full():
    """Asserts queue-full condition drops payload without crash."""
    import asyncio
    from nodes.learning_node import embed_and_store, learning_queue

    # Fill the queue to max
    original_maxsize = learning_queue.maxsize
    # Drain any existing items first
    while not learning_queue.empty():
        try:
            learning_queue.get_nowait()
            learning_queue.task_done()
        except asyncio.QueueEmpty:
            break

    # Fill to capacity
    for i in range(learning_queue.maxsize):
        learning_queue.put_nowait({
            "condensed_summary": f"fill-{i}",
            "triage_summary": "fill",
            "human_classification": "fill",
            "human_classification_reason": "",
        })

    # This should NOT raise - it should log and drop
    await embed_and_store("overflow", "overflow", "overflow", "")

    # Drain the queue to clean up
    while not learning_queue.empty():
        try:
            learning_queue.get_nowait()
            learning_queue.task_done()
        except asyncio.QueueEmpty:
            break

