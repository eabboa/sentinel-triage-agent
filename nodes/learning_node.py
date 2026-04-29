"""
Learning node for RAG-based correction loop.
Compares LLM classification with human classification and stores mismatches for future retrieval.
"""

import asyncio
import concurrent.futures
import logging
import os
import threading
import time
import uuid

import chromadb
from sentence_transformers import SentenceTransformer
from state import TriageState

logger = logging.getLogger(__name__)

worker_embedding_model = None
embedding_executor: concurrent.futures.ProcessPoolExecutor | None = None

def _init_worker():
    """Initialize the worker process embedding model."""
    global worker_embedding_model
    worker_embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


def _ensure_embedding_executor(max_workers: int = 1) -> concurrent.futures.ProcessPoolExecutor:
    """Create or reuse a process executor for encoding batches."""
    global embedding_executor
    if embedding_executor is None or getattr(embedding_executor, "_shutdown", False):
        embedding_executor = concurrent.futures.ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=_init_worker,
        )
    return embedding_executor


learning_queue: asyncio.Queue[dict[str, str]] = asyncio.Queue(maxsize=1000)


class ChromaSingleton:
    """Thread-safe singleton for ChromaDB client, collection, and embedding model."""

    _instance = None
    _lock = threading.Lock()
    _init_error = None
    _circuit_open_until = 0
    _failure_count = 0

    def __init__(self):
        host = os.environ.get('CHROMA_HOST', 'localhost')
        port = int(os.environ.get('CHROMA_PORT', '8000'))
        try:
            self.client = chromadb.HttpClient(host=host, port=port)
            self.collection = self.client.get_or_create_collection(name="triage_corrections")
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception as exc:
            logger.exception("Failed to initialize ChromaDB singleton for learning node")
            self.client = None
            self.collection = None
            self.embedding_model = None
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
    return (
        f"Condensed Summary: {payload['condensed_summary']}\n"
        f"Triage Summary: {payload['triage_summary']}\n"
        f"Human Classification: {payload['human_classification']}"
    )


def _encode_batch(documents: list[str]) -> list[list[float]]:
    if worker_embedding_model is None:
        raise RuntimeError("Worker embedding model not initialized")
    return worker_embedding_model.encode(documents).tolist()


async def embed_and_store(condensed_summary: str, triage_summary: str, human_classification: str):
    """Queue learning payload for batched embedding and storage."""
    payload = {
        "condensed_summary": condensed_summary,
        "triage_summary": triage_summary,
        "human_classification": human_classification,
    }
    try:
        learning_queue.put_nowait(payload)
        logger.debug("Queued learning payload for human_classification=%s", human_classification)
    except asyncio.QueueFull:
        logger.error("Learning queue saturated; dropping payload to prevent blocking. Data loss occurred for human_classification=%s", human_classification)


async def consume_learning_queue(batch_size: int = 32, flush_interval: float = 5):
    """Continuously consume the learning queue, embed in batches, and write to ChromaDB."""
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
    executor = _ensure_embedding_executor()

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
            pass

        while len(batch) < batch_size:
            try:
                item = learning_queue.get_nowait()
                batch.append(item)
                learning_queue.task_done()
            except asyncio.QueueEmpty:
                break

        if not batch:
            continue

        documents = [_build_document(item) for item in batch]
        metadatas = [
            {"human_classification": item["human_classification"]}
            for item in batch
        ]
        ids = [f"mismatch_{uuid.uuid4()}" for _ in batch]

        try:
            embeddings = await loop.run_in_executor(
                executor,
                _encode_batch,
                documents,
            )
        except Exception:
            logger.exception("Embedding model failure in learning_node.consume_learning_queue")
            continue

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
            continue

        logger.debug(
            "Successfully stored %d learning mismatch documents",
            len(batch),
        )


async def flush_and_shutdown(batch_size: int = 32):
    """Drain all remaining items in learning_queue and commit them to ChromaDB."""
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
    executor = _ensure_embedding_executor()

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

        documents = [_build_document(item) for item in batch]
        metadatas = [
            {"human_classification": item["human_classification"]}
            for item in batch
        ]
        ids = [f"mismatch_{uuid.uuid4()}" for _ in batch]

        try:
            embeddings = await loop.run_in_executor(
                executor,
                _encode_batch,
                documents,
            )
        except Exception:
            logger.exception("Embedding model failure in learning_node.flush_and_shutdown")
            continue

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
            logger.exception(
                "Failed to write learning mismatch batch to ChromaDB during shutdown"
            )
            continue

        logger.debug(
            "Flushed %d remaining learning mismatch documents",
            len(batch),
        )

    try:
        await loop.run_in_executor(None, learning_queue.join)
    except Exception:
        logger.exception("Error waiting for learning_queue task completion during shutdown")

    try:
        executor.shutdown(wait=True)
    except Exception:
        logger.exception("Error shutting down learning node executor")
    finally:
        global embedding_executor
        embedding_executor = None

    logger.info("Learning node flush and shutdown complete")

async def learning_node(state: TriageState) -> dict:
    """
    LangGraph node: Evaluates human vs. LLM classification and queues mismatches.
    """
    llm_classification = state.get("classification", "")
    # Assuming 'human_classification' is injected into the state during the HITL pause.
    # If it is not present, default to the LLM classification to avoid false positives in the RAG loop.
    human_classification = state.get("human_classification", llm_classification)

    if human_classification and human_classification != llm_classification:
        condensed = state.get("condensed_summary", "")
        triage = state.get("triage_summary", "")
        
        # Non-blocking queue insertion
        await embed_and_store(condensed, triage, human_classification)

    # Return empty dict or update state flags as needed by your TriageState schema
    return {}