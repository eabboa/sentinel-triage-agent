"""
seed_learning.py
================
Offline seed script to populate ChromaDB with historical analyst-classified incidents.
Run this ONCE before going live to give the RAG learning loop a non-zero knowledge base.

Usage:
    python seed_learning.py --csv incidents.csv [--batch-size 32] [--dry-run]

CSV format (UTF-8, with header row):
    condensed_summary, triage_summary, human_classification, human_classification_reason

    human_classification must be one of:
        TruePositive | FalsePositive | BenignPositive

    human_classification_reason is optional but strongly recommended.
    It should explain WHY the analyst classified the incident this way.

Example row:
    "User executed mimikatz.exe on DC01","LM/NTLM hash dump detected on domain controller. Confirmed credential dumping.",TruePositive,"LSASS memory dump confirmed via Sysmon EventID 10. Known attacker tooling."
"""

import argparse
import csv
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, cast

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("seed_learning")

VALID_CLASSIFICATIONS = {"TruePositive", "FalsePositive", "BenignPositive"}


def load_csv(path: Path) -> list[dict]:
    """
    Loads and validates the training seed data from a CSV file.

    Args:
        path: A Path object pointing to the CSV file.

    Returns:
        A list of parsed row dictionaries containing learning data.

    Raises:
        ValueError: If the CSV is missing required columns.
    """
    rows = []
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"condensed_summary", "triage_summary", "human_classification"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError(
                f"CSV must have columns: {required}. Found: {reader.fieldnames}"
            )
        has_reason = "human_classification_reason" in (reader.fieldnames or [])
        for i, row in enumerate(reader, start=2):  # row 1 is header
            classification = row["human_classification"].strip()
            if classification not in VALID_CLASSIFICATIONS:
                logger.warning(
                    "Row %d skipped — invalid classification '%s'. "
                    "Must be one of %s.",
                    i,
                    classification,
                    VALID_CLASSIFICATIONS,
                )
                continue
            if not row["condensed_summary"].strip() or not row["triage_summary"].strip():
                logger.warning("Row %d skipped — empty summary field.", i)
                continue
            entry = {
                "condensed_summary": row["condensed_summary"].strip(),
                "triage_summary": row["triage_summary"].strip(),
                "human_classification": classification,
            }
            if has_reason:
                entry["human_classification_reason"] = row.get("human_classification_reason", "").strip()
            rows.append(entry)
    return rows


def build_document(payload: dict) -> str:
    """
    Builds the textual representation of an incident for ChromaDB embedding.

    Args:
        payload: Dictionary containing incident data from the CSV.

    Returns:
        A formatted string used as the vector embedding document.
    """
    reason = payload.get('human_classification_reason', '')
    return (
        f"Incident Context: {payload['condensed_summary']}\n"
        f"Incorrect LLM Reasoning: {payload['triage_summary']}\n"
        f"Human Correction Reason: {reason or 'No reason provided.'}\n"
        f"Correct Label: {payload['human_classification']}"
    )


def seed(csv_path: Path, batch_size: int, dry_run: bool) -> None:
    """
    Seeds the ChromaDB vector store with historical incident data.

    Args:
        csv_path: Path to the input CSV file.
        batch_size: Number of documents to process and insert at once.
        dry_run: If True, prints actions instead of writing to DB.

    Returns:
        None
    """
    rows = load_csv(csv_path)
    if not rows:
        logger.error("No valid rows found in CSV. Exiting.")
        sys.exit(1)

    logger.info("Loaded %d valid rows from '%s'.", len(rows), csv_path)

    if dry_run:
        logger.info("[DRY RUN] Would insert %d documents. Skipping ChromaDB write.", len(rows))
        for i, row in enumerate(rows[:5], 1):
            logger.info("  Sample %d: classification=%s | summary=%s...", i, row["human_classification"], row["condensed_summary"][:80])
        return

    # Lazy imports — only needed when actually writing
    import chromadb
    from sentence_transformers import SentenceTransformer

    logger.info("Connecting to ChromaDB...")
    import os
    host = os.environ.get("CHROMA_HOST", "localhost")
    port = int(os.environ.get("CHROMA_PORT", "8000"))
    client = chromadb.HttpClient(host=host, port=port)
    collection = client.get_or_create_collection(name="triage_corrections")

    logger.info("Loading embedding model (all-MiniLM-L6-v2)...")
    model = SentenceTransformer("all-MiniLM-L6-v2")

    total = 0
    for start in range(0, len(rows), batch_size):
        batch = rows[start : start + batch_size]
        documents = [build_document(r) for r in batch]
        metadatas = [{"human_classification": r["human_classification"]} for r in batch]
        ids = [f"seed_{uuid.uuid4()}" for _ in batch]

        logger.info(
            "Encoding batch %d–%d (%d docs)...",
            start + 1,
            start + len(batch),
            len(batch),
        )
        embeddings = model.encode(documents).tolist()

        collection.add(
            documents=documents,
            embeddings=embeddings,
            metadatas=cast(Any, metadatas),
            ids=ids,
        )
        total += len(batch)
        logger.info("  ✓ Stored %d / %d documents so far.", total, len(rows))

    logger.info("Seed complete. %d documents written to ChromaDB collection 'triage_corrections'.", total)
    count = collection.count()
    logger.info("Collection now contains %d total documents.", count)


def main():
    """
    Parses CLI arguments and invokes the seed function.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(
        description="Seed ChromaDB with historical analyst-classified incidents."
    )
    parser.add_argument("--csv", required=True, type=Path, help="Path to the input CSV file.")
    parser.add_argument("--batch-size", type=int, default=32, help="Embedding batch size (default: 32).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and preview the CSV without writing to ChromaDB.",
    )
    args = parser.parse_args()

    if not args.csv.exists():
        logger.error("CSV file not found: %s", args.csv)
        sys.exit(1)

    seed(args.csv, args.batch_size, args.dry_run)


if __name__ == "__main__":
    main()
