"""
Learning node for RAG-based correction loop.
Compares LLM classification with human classification and stores mismatches for future retrieval.
"""

import asyncio
import os

import chromadb
from sentence_transformers import SentenceTransformer
from state import TriageState


# Global variables for ChromaDB and embedding model
chroma_client = None
collection = None
embedding_model = None


def initialize_chroma():
    """Initialize ChromaDB client and collection."""
    global chroma_client, collection, embedding_model
    if chroma_client is None:
        # Use persistent directory
        persist_dir = os.path.join(os.getcwd(), "chroma_db")
        chroma_client = chromadb.PersistentClient(path=persist_dir)
        collection = chroma_client.get_or_create_collection(name="triage_corrections")
        embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


async def embed_and_store(condensed_summary: str, triage_summary: str, human_classification: str):
    """Embed the mismatch data and store in ChromaDB."""
    if chroma_client is None:
        initialize_chroma()

    # Combine the texts for embedding
    document = f"Condensed Summary: {condensed_summary}\nTriage Summary: {triage_summary}\nHuman Classification: {human_classification}"

    # Generate embedding
    embedding = embedding_model.encode(document).tolist()

    # Store in collection
    await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: collection.add(
            documents=[document],
            embeddings=[embedding],
            metadatas=[{"human_classification": human_classification}],
            ids=[f"mismatch_{len(collection.get()['ids'])}"]  # Simple ID generation
        )
    )


async def learning_node(state: TriageState) -> dict:
    """
    Compares LLM classification with human classification.
    If they differ, stores the mismatch for RAG retrieval.
    """
    llm_classification = state.get("classification")
    human_classification = state.get("human_classification")

    if not human_classification:
        # No human review provided, skip
        return {}

    if llm_classification != human_classification:
        # Mismatch detected, store for learning
        condensed_summary = state.get("condensed_summary", "")
        triage_summary = state.get("triage_summary", "")

        await embed_and_store(condensed_summary, triage_summary, human_classification)

    return {}