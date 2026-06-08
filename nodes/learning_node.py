"""
Learning node for RAG-based correction loop.
Compares LLM classification with human classification and stores mismatches for future retrieval.
"""

import asyncio
import concurrent.futures
import structlog
import os
import threading
import time
import uuid

from state import TriageState

logger = structlog.get_logger(__name__)

class _WorkerState:
    """Module-level state for the embedding process pool."""
    def __init__(self):
        self.embedding_model = None
        self.executor: concurrent.futures.ProcessPoolExecutor | None = None

    def ensure_executor(self, max_workers: int = 1) -> concurrent.futures.ProcessPoolExecutor:
        """
        Creates or reuses a process executor for encoding batches.

        Args:
            max_workers: The maximum number of worker processes to use.

        Returns:
            The ProcessPoolExecutor instance.
        """
        if self.executor is None or getattr(self.executor, "_shutdown", False):
            self.executor = concurrent.futures.ProcessPoolExecutor(
                max_workers=max_workers,
                initializer=_init_worker,
            )
        return self.executor


_worker_state = _WorkerState()


def _init_worker():
    """
    Initializes the worker process embedding model.

    Returns:
        None
    """
    from sentence_transformers import SentenceTransformer

    _worker_state.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


learning_queue: asyncio.Queue[dict[str, str]] = asyncio.Queue(maxsize=1000)


class ChromaSingleton:
    """Thread-safe singleton for ChromaDB client, collection, and embedding model."""

    _instance: "ChromaSingleton | None" = None
    _lock: threading.Lock = threading.Lock()
    _init_error: Exception | None = None
    _circuit_open_until: float = 0.0
    _failure_count: int = 0

    def __init__(self):
        host = os.environ.get('CHROMA_HOST', 'localhost')
        port = int(os.environ.get('CHROMA_PORT', '8000'))
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer

            self.client = chromadb.HttpClient(host=host, port=port)
            self.collection = self.client.get_or_create_collection(name="triage_corrections")
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception as exc:
            logger.exception("Failed to initialize ChromaDB singleton for learning node")
            self.__class__._init_error = exc
            raise

    @classmethod
    def get_instance(cls):
        if time.time() < cls._circuit_open_until:
            raise RuntimeError('ChromaDB Circuit Open')
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    try:
                        cls._instance = cls()
                        cls._failure_count = 0
                    except Exception:
                        cls._instance = None
                        cls._failure_count += 1
                        if cls._failure_count > 3:
                            cls._circuit_open_until = time.time() + 60
                            logger.critical("ChromaDB Circuit Breaker opened due to repeated initialization failures")
                        raise
        if cls._instance is None:
            raise RuntimeError("ChromaDB singleton failed to initialize")
        return cls._instance


def _build_document(payload: dict[str, str]) -> str:
    """
    Builds the textual document for ChromaDB embedding.

    Args:
        payload: Dictionary containing summary and classification data.

    Returns:
        The formatted string representing the document.
    """
    reason = payload.get('human_classification_reason', '')
    reason = payload.get('human_classification_reason', '')
    return (
        f"Incident Context: {payload['condensed_summary']}\n"
        f"Incorrect LLM Reasoning: {payload['triage_summary']}\n"
        f"Human Correction Reason: {reason or 'No reason provided.'}\n"
        f"Correct Label: {payload['human_classification']}"
    )


def _encode_batch(documents: list[str]) -> list[list[float]]:
    """
    Encodes a batch of documents into embeddings.

    Args:
        documents: A list of string documents to encode.

    Returns:
        A list of embedding vectors.

    Raises:
        RuntimeError: If the worker embedding model is not initialized.
    """
    if _worker_state.embedding_model is None:
        if _worker_state.embedding_model is None:
            raise RuntimeError("Worker embedding model not initialized")
    return _worker_state.embedding_model.encode(documents).tolist()


async def embed_and_store(
    condensed_summary: str,
    triage_summary: str,
    human_classification: str,
    human_classification_reason: str = "",
):
    """
    Queues a learning payload for batched embedding and storage.

    Args:
        condensed_summary: The summary of the incident.
        triage_summary: The LLM's triage explanation.
        human_classification: The correct classification.
        human_classification_reason: The reason for the classification.

    Returns:
        None
    """
    payload = {
        "condensed_summary": condensed_summary,
        "triage_summary": triage_summary,
        "human_classification": human_classification,
        "human_classification_reason": human_classification_reason,
    }
    try:
        learning_queue.put_nowait(payload)
        logger.debug("Queued learning payload for human_classification=%s", human_classification)
    except asyncio.QueueFull:
        logger.error("Learning queue saturated; dropping payload to prevent blocking. Data loss occurred for human_classification=%s", human_classification)


async def _embed_and_write_batch(
    instance: ChromaSingleton,
    executor: concurrent.futures.ProcessPoolExecutor,
    loop: asyncio.AbstractEventLoop,
    batch: list[dict[str, str]],
) -> bool:
    """
    Embeds documents and writes them to ChromaDB.

    Args:
        instance: The ChromaSingleton instance.
        executor: The ProcessPoolExecutor for embedding.
        loop: The current asyncio event loop.
        batch: A list of learning payload dictionaries.

    Returns:
        True on success, False on failure.
    """
    documents = [_build_document(item) for item in batch]
    metadatas = [{"human_classification": item["human_classification"]} for item in batch]
    ids = [f"mismatch_{uuid.uuid4()}" for _ in batch]

    try:
        embeddings = await loop.run_in_executor(executor, _encode_batch, documents)
    except Exception:
        logger.exception("Embedding model failure in learning_node")
        return False

    try:
        await loop.run_in_executor(
            None,
            lambda: instance.collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids,
            ),
        )
    except Exception:
        logger.exception("Failed to write learning mismatch batch to ChromaDB")
        return False

    return True


async def consume_learning_queue(batch_size: int = 32, flush_interval: float = 5):
    """
    Continuously consumes the learning queue, embeds in batches, and writes to ChromaDB.

    Args:
        batch_size: The number of items to process in a batch.
        flush_interval: Maximum time in seconds to wait for a full batch.

    Returns:
        None
    """
    try:
        instance = ChromaSingleton.get_instance()
    except Exception:
        logger.exception("Unable to obtain ChromaDB singleton instance for learning_node")
        return

    if not instance.embedding_model or not instance.collection:
        logger.warning(
            "ChromaDB singleton is not fully available; stopping learning queue consumer"
        )
        return

    loop = asyncio.get_running_loop()
    executor = _worker_state.ensure_executor()

    while True:
        batch: list[dict[str, str]] = []
        try:
            first_item = await asyncio.wait_for(
                learning_queue.get(),
                timeout=flush_interval,
            )
            batch.append(first_item)
            learning_queue.task_done()
        except asyncio.TimeoutError:
            logger.debug("Learning queue flush interval elapsed with no new items")

        while len(batch) < batch_size:
            try:
                item = learning_queue.get_nowait()
                batch.append(item)
                learning_queue.task_done()
            except asyncio.QueueEmpty:
                break

        if not batch:
            continue

        if await _embed_and_write_batch(instance, executor, loop, batch):
            logger.debug("Successfully stored %d learning mismatch documents", len(batch))


async def flush_and_shutdown(batch_size: int = 32):
    """
    Drains all remaining items in learning_queue and commits them to ChromaDB.

    Args:
        batch_size: The number of items to process in a batch.

    Returns:
        None
    """
    try:
        instance = ChromaSingleton.get_instance()
    except Exception:
        logger.exception(
            "Unable to obtain ChromaDB singleton instance for learning_node flush_and_shutdown"
        )
        return

    if not instance.embedding_model or not instance.collection:
        logger.warning(
            "ChromaDB singleton is not fully available; aborting learning queue flush"
        )
        return

    loop = asyncio.get_running_loop()
    executor = _worker_state.ensure_executor()

    while not learning_queue.empty():
        batch: list[dict[str, str]] = []
        while len(batch) < batch_size:
            try:
                item = learning_queue.get_nowait()
                batch.append(item)
                learning_queue.task_done()
            except asyncio.QueueEmpty:
                break

        if not batch:
            break

        if await _embed_and_write_batch(instance, executor, loop, batch):
            logger.debug("Flushed %d remaining learning mismatch documents", len(batch))

    try:
        await learning_queue.join()
    except Exception:
        logger.exception("Error waiting for learning_queue task completion during shutdown")

    try:
        executor.shutdown(wait=True)
    except Exception:
        logger.exception("Error shutting down learning node executor")
    finally:
        _worker_state.executor = None

    logger.info("Learning node flush and shutdown complete")

async def learning_node(state: TriageState) -> dict:
    """
    LangGraph node: Evaluates human vs. LLM classification and queues mismatches.

    Args:
        state: The current TriageState dictionary.

    Returns:
        An empty dictionary.
    """
    logger.info("node_entry", node="learning")
    llm_classification = state.get("classification", "")
    # 'human_classification' is injected into state during the HITL pause.
    # Defaults to llm_classification when absent to avoid false positives in the RAG loop.
    human_classification = state.get("human_classification", llm_classification)

    if human_classification and human_classification != llm_classification:
        condensed = state.get("condensed_summary", "")
        triage = state.get("triage_summary", "")
        reason = state.get("human_classification_reason") or ""
        
        # Non-blocking queue insertion
        await embed_and_store(condensed, triage, human_classification, reason)

    logger.info("node_exit", node="learning")
    return {}