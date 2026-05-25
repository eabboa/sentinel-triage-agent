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
