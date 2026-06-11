"""
Enriches MITRE ATT&CK technique IDs found in an incident with authoritative
data (tactic, description, telemetry data sources) from the MITRE ATT&CK
Enterprise STIX bundle.

Design notes:
- Runs *after* the analyst so it can enrich the validated `mitre_techniques`
  the LLM produced (plus any IDs that appear verbatim in incident/alert text).
  The enrichment is consumer-facing: ``writeback_node`` renders it into the
  Sentinel incident comment for the human reviewer and for hunting follow-up.
- STIX bundle availability is treated as a CTI source: a whole-source outage is
  reported via ``degraded_sources`` (project convention), while individual
  unresolved technique IDs are reported as non-fatal ``errors`` warnings — never
  written back as fabricated "enrichment".
"""

import asyncio
import contextlib
import json
import os
import re
import tempfile
import time

import aiofiles
import aiohttp
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from nodes.mitre_utils import TECHNIQUE_ID_PATTERN
from state import TriageState

logger = structlog.get_logger(__name__)

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Cache location is configurable; defaults to a stable per-user temp dir so the
# bundle is not re-downloaded into whatever CWD the process happens to launch in
# (and never the repo root). See _resolve_cache_file().
_DEFAULT_CACHE_DIR = os.path.join(tempfile.gettempdir(), "sentinel-triage-agent")
STIX_CACHE_FILE = os.path.join(
    os.getenv("MITRE_STIX_CACHE_DIR", _DEFAULT_CACHE_DIR), "enterprise-attack.json"
)

MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
CACHE_TTL = int(os.getenv("MITRE_STIX_CACHE_TTL", str(86400)))  # 24h default
# Negative-result cache: after a download/parse failure, do not re-attempt the
# network for this many seconds. Prevents a retry storm where every incident in
# a batch serially re-runs the full tenacity backoff during an outage.
FAILURE_TTL = int(os.getenv("MITRE_STIX_FAILURE_TTL", str(300)))  # 5 min default
# Cap per-technique description size so the (checkpointed) state stays small.
DESCRIPTION_LIMIT = 500

# Source name disclosed in ``degraded_sources`` when the bundle is unavailable.
SOURCE_NAME = "mitre_attack"

# Anchored full-match validation is owned by mitre_utils (single source of truth
# for what a valid technique ID looks like). For *extraction* from free text we
# need a boundary-anchored scanning variant of the same shape.
TECHNIQUE_SCAN_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_stix_cache: dict[str, dict] = {}
_stix_cache_time: float = 0.0
_stix_failure_time: float = 0.0
_stix_download_lock: asyncio.Lock = asyncio.Lock()


def _cache_valid() -> bool:
    """Returns True when the in-memory STIX cache is populated and within TTL."""
    return bool(_stix_cache) and (time.time() - _stix_cache_time) < CACHE_TTL


def _safe_mtime_age(path: str) -> float | None:
    """Returns the age of ``path`` in seconds, or None if it cannot be stat'd.

    Tolerates the file vanishing between an ``os.path.exists`` check and this
    call (TOCTOU race) by returning None rather than raising.
    """
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return None


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
    reraise=True,
)
async def _download_stix_data() -> None:
    """
    Downloads the MITRE ATT&CK STIX bundle to a temporary file,
    and replaces the existing cache file safely upon completion.
    Uses aiofiles to prevent blocking the event loop.

    Raises:
        ValueError: If the file exceeds MAX_DOWNLOAD_SIZE.
        aiohttp.ClientError: If network download fails.
        asyncio.TimeoutError: If connection times out.
        OSError: If writing to disk fails.
    """
    os.makedirs(os.path.dirname(STIX_CACHE_FILE), exist_ok=True)
    tmp_file = f"{STIX_CACHE_FILE}.tmp"
    bytes_written = 0
    timeout = aiohttp.ClientTimeout(total=120, connect=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(STIX_URL) as response:
                response.raise_for_status()
                async with aiofiles.open(tmp_file, "wb") as f:
                    async for chunk in response.content.iter_chunked(8192):
                        bytes_written += len(chunk)
                        if bytes_written > MAX_DOWNLOAD_SIZE:
                            raise ValueError(
                                f"File exceeded {MAX_DOWNLOAD_SIZE // (1024*1024)}MB limit"
                            )
                        await f.write(chunk)
        os.replace(tmp_file, STIX_CACHE_FILE)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError):
        with contextlib.suppress(OSError):
            os.remove(tmp_file)
        raise


def _parse_stix_json(file_path: str) -> dict[str, dict]:
    """
    Parses the STIX JSON file synchronously to extract technique data.
    Designed to be run via asyncio.to_thread to avoid blocking.

    Hardened against malformed bundles: a non-object root, non-dict objects,
    missing/None ``phase_name`` values, and revoked/deprecated techniques are
    all handled without raising.

    Args:
        file_path: The path to the STIX JSON file.

    Returns:
        A dictionary mapping technique IDs to their details.

    Raises:
        json.JSONDecodeError: If the file is corrupted.
        ValueError: If the JSON root is not an object.
        OSError: If reading the file fails.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("STIX bundle root is not a JSON object")

    parsed_cache: dict[str, dict] = {}
    for obj in data.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        # Skip retired techniques so stale IDs are never presented as current.
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        tech_id = None
        for ext in obj.get("external_references", []):
            if isinstance(ext, dict) and ext.get("source_name") == "mitre-attack":
                tech_id = ext.get("external_id")
                break

        if not tech_id:
            continue

        tactics = [
            (phase.get("phase_name") or "").replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if isinstance(phase, dict)
        ]
        tactics = [t for t in tactics if t]

        parsed_cache[tech_id] = {
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "data_sources": obj.get("x_mitre_data_sources", []) or [],
        }
    return parsed_cache


async def _ensure_stix_data() -> tuple[dict[str, dict], str | None]:
    """
    Returns the parsed MITRE ATT&CK technique map, downloading/parsing lazily.

    Resilience guarantees:
      - In-memory cache TTL is measured from the on-disk file's mtime (not the
        parse time), so a restart against a nearly-expired file does not extend
        the effective TTL.
      - On a failed refresh, a stale-but-parseable on-disk bundle is served as
        graceful degradation rather than discarded.
      - A corrupt or empty bundle is deleted (self-heal) so the next run can
        re-download instead of looping on the same bad file.
      - Failures are negatively cached for FAILURE_TTL to avoid a retry storm.

    Returns:
        A tuple ``(stix_data, degraded_message_or_None)``. ``stix_data`` may be
        non-empty *and* carry a degraded message when stale data is served.
    """
    global _stix_cache, _stix_cache_time, _stix_failure_time

    if _cache_valid():
        return _stix_cache, None

    async with _stix_download_lock:
        # Double-check after acquiring the lock.
        if _cache_valid():
            return _stix_cache, None

        now = time.time()
        file_exists = os.path.exists(STIX_CACHE_FILE)
        mtime_age = _safe_mtime_age(STIX_CACHE_FILE) if file_exists else None
        file_fresh = mtime_age is not None and mtime_age < CACHE_TTL
        recent_failure = (
            bool(_stix_failure_time) and (now - _stix_failure_time) < FAILURE_TTL
        )
        degraded_msg: str | None = None

        if not file_fresh:
            if recent_failure and not file_exists:
                # Nothing usable on disk and we just failed — degrade fast.
                return {}, "STIX unavailable: download failed recently (cached)"

            if not recent_failure:
                logger.info(
                    "Downloading MITRE ATT&CK STIX bundle",
                    url=STIX_URL,
                    file=STIX_CACHE_FILE,
                )
                try:
                    await _download_stix_data()
                    logger.info("Download complete.")
                except ValueError as ve:
                    logger.error(
                        "node_error",
                        node="mitre_enrich",
                        error="size_limit_exceeded",
                        exc_info=True,
                    )
                    _stix_failure_time = now
                    if not file_exists:
                        return {}, f"STIX Download Failed: {str(ve)}"
                    degraded_msg = f"STIX Download Failed: {str(ve)}"
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    logger.error(
                        "node_error",
                        node="mitre_enrich",
                        error="download_failed",
                        exc_info=True,
                    )
                    _stix_failure_time = now
                    if not file_exists:
                        return (
                            {},
                            "STIX Download Failed: Network timeout or client error",
                        )
                    degraded_msg = (
                        "STIX Download Failed: Network timeout or client error"
                    )
                except OSError as oe:
                    logger.error(
                        "node_error",
                        node="mitre_enrich",
                        error="download_failed",
                        exc_info=True,
                    )
                    _stix_failure_time = now
                    if not file_exists:
                        return {}, f"STIX Download Failed: I/O error ({oe})"
                    degraded_msg = f"STIX Download Failed: I/O error ({oe})"
            else:
                # Recent failure but a stale file exists — serve it, degraded.
                degraded_msg = (
                    "STIX bundle is stale (refresh deferred after recent failure)"
                )

        try:
            parsed = await asyncio.to_thread(_parse_stix_json, STIX_CACHE_FILE)
        except (json.JSONDecodeError, ValueError, OSError):
            logger.error(
                "node_error", node="mitre_enrich", error="parse_failed", exc_info=True
            )
            with contextlib.suppress(OSError):
                os.remove(STIX_CACHE_FILE)  # self-heal: drop the corrupt file
            _stix_failure_time = now
            return {}, "STIX Parsing Failed: Corrupted or missing JSON cache file"

        if not parsed:
            logger.error("node_error", node="mitre_enrich", error="empty_bundle")
            with contextlib.suppress(OSError):
                os.remove(STIX_CACHE_FILE)  # self-heal: drop the empty file
            _stix_failure_time = now
            return {}, "STIX Parsing Failed: bundle contained no techniques"

        _stix_cache = parsed
        # Fresh data: anchor TTL to the file's real age (so a near-expired file
        # is not treated as brand new). Stale fallback: cache in memory for a
        # full TTL so we don't re-parse the large file on every incident during
        # an outage.
        _stix_cache_time = now if degraded_msg else (now - (mtime_age or 0.0))
        if degraded_msg is None:
            _stix_failure_time = 0.0
        return _stix_cache, degraded_msg


def _extract_technique_ids(state: TriageState) -> set[str]:
    """Collects candidate MITRE technique IDs from incident text and LLM output.

    IDs are scanned with a boundary-anchored pattern (so substrings like
    ``HOST1234`` do not yield ``T1234``) and re-validated against the canonical
    anchored pattern from ``mitre_utils`` for consistency across the codebase.
    """
    candidates: set[str] = set()

    text_to_search = [
        state.get("incident_title", ""),
        state.get("incident_description", ""),
    ]
    for alert in state.get("raw_alerts", []):
        # raw_alerts are validated SentinelAlert.model_dump() outputs, shaped
        # {"properties": {"alertDisplayName": ..., "description": ...}}.
        props = alert.get("properties", alert) if isinstance(alert, dict) else {}
        text_to_search.append(props.get("alertDisplayName", ""))
        text_to_search.append(props.get("description", ""))

    for text in text_to_search:
        if text:
            candidates.update(TECHNIQUE_SCAN_PATTERN.findall(str(text)))

    for tech in state.get("mitre_techniques", []):
        tech_id = str(tech.get("technique_id", "")).strip().upper()
        if tech_id:
            candidates.update(TECHNIQUE_SCAN_PATTERN.findall(tech_id))

    # Keep only IDs that pass the canonical (anchored) validation.
    return {tid for tid in candidates if TECHNIQUE_ID_PATTERN.match(tid)}


async def mitre_enrich_node(state: TriageState) -> dict:
    """
    Extracts MITRE ATT&CK technique IDs from incident/alert text and the
    validated analyst techniques, then enriches them from the local STIX bundle.

    Args:
        state: The current triage workflow state.

    Returns:
        A partial state update containing ``mitre_enrichment`` and, when
        applicable, ``degraded_sources`` (bundle outage) and ``errors``
        (unresolved technique IDs / bundle warnings).
    """
    logger.info("node_entry", node="mitre_enrich")

    extracted_ids = _extract_technique_ids(state)

    if not extracted_ids:
        logger.info("node_exit", node="mitre_enrich")
        return {"mitre_enrichment": []}

    stix_data, degraded_msg = await _ensure_stix_data()

    updates: dict = {}
    errors: list[str] = []
    if degraded_msg:
        updates["degraded_sources"] = [SOURCE_NAME]
        errors.append(degraded_msg)

    if not stix_data:
        # Whole source down with no usable data — surface, enrich nothing.
        updates["mitre_enrichment"] = []
        if errors:
            updates["errors"] = errors
        logger.info("node_exit", node="mitre_enrich")
        return updates

    enrichments = []
    for tech_id in sorted(extracted_ids):
        info = stix_data.get(tech_id)
        if info is None:
            # Source is up but the ID is not in the bundle: flag it as a
            # warning instead of fabricating an "Unknown Technique" record.
            errors.append(
                f"MITRE Warning: Technique {tech_id} not found in ATT&CK Enterprise bundle"
            )
            continue
        tactics = info.get("tactics") or []
        enrichments.append(
            {
                "technique_id": tech_id,
                "tactic": tactics[0] if tactics else "Unknown",
                "name": info.get("name", ""),
                "description": (info.get("description") or "")[:DESCRIPTION_LIMIT],
                "data_sources": (info.get("data_sources") or [])[:3],
            }
        )

    updates["mitre_enrichment"] = enrichments
    if errors:
        updates["errors"] = errors

    logger.info("node_exit", node="mitre_enrich")
    return updates
