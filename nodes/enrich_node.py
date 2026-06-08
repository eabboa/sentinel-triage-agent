"""
Queries VirusTotal and AbuseIPDB concurrently for all extracted IOCs.
Internal (RFC 1918) IPs are NOT sent to external CTI services; they are
tagged as lateral_movement candidates and passed through for the analyst.

Threshold semantics:
  VT_MALICIOUS_THRESHOLD (default 5):
    VirusTotal's last_analysis_stats.malicious is a vote count across ~70 AV engines.
    A single engine detection is frequently a PUA heuristic false positive.
    Threshold bands:
      >= VT_MALICIOUS_THRESHOLD  → "malicious"   (strong engine consensus)
      >= 2 and < threshold       → "suspicious"  (weak signal, investigate)
      <= 1                       → "clean"        (likely FP from one heuristic engine)

  ABUSEIPDB_MALICIOUS_THRESHOLD (default 75):
    AbuseIPDB's abuseConfidenceScore is a Bayesian-weighted aggregate of community
    abuse reports. Recent reports and verified reporters are weighted higher.
    Threshold bands:
      >= ABUSEIPDB_MALICIOUS_THRESHOLD → "malicious"  (confirmed abusive)
      >= 25 and < threshold            → "suspicious" (investigate further)
      < 25                             → "clean"       (no significant abuse history)

Neutral baseline guarantee:
    If a CTI lookup fails (timeout, HTTP error, exception), the IOC result is stripped
    from cti_results entirely and appended to the graph errors list instead.
    The LLM never sees an error object in the cti_results payload - it only receives
    verified signals. This prevents the LLM from inferring threat signals from the
    mere presence of a failed lookup (e.g. "timeout = IP blocking scanners").

Graceful degradation:
    If an entire CTI source is unavailable (missing API key, DNS failure, etc.),
    the source name is appended to degraded_sources and the pipeline continues
    with partial results from the remaining sources. Individual IOC failures
    within a healthy source are captured in errors but do not mark the source
    as degraded.
"""

import asyncio
import time
import structlog
import os
import aiohttp
# pyrefly: ignore [missing-import]
from aiolimiter import AsyncLimiter
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from state import TriageState
from metrics import ENRICHMENT_LATENCY
from pydantic import ValidationError
from models.validation import AbuseIPDBResponse
from models.exceptions import AbuseIPDBResponseValidationError
from models.exceptions import VirusTotalResponseValidationError
from models.validation import VirusTotalResponse

logger = structlog.get_logger(__name__)
DEFAULT_HTTP_TIMEOUT = 10
RETRY_ATTEMPTS = 3

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Configurable thresholds - override via environment variables in production.
# See module docstring for threshold semantics and rationale.
VT_MALICIOUS_THRESHOLD: int = int(os.getenv("VT_MALICIOUS_THRESHOLD", "5")) # default 5
ABUSEIPDB_MALICIOUS_THRESHOLD: int = int(os.getenv("ABUSEIPDB_MALICIOUS_THRESHOLD", "75")) # default 75
ABUSEIPDB_SUSPICIOUS_THRESHOLD: int = 25  # Fixed lower bound for "suspicious" band

class _SessionManager:
    """Manages a shared aiohttp.ClientSession with lazy initialization."""
    def __init__(self):
        self._session: aiohttp.ClientSession | None = None

    async def get(self) -> aiohttp.ClientSession:
        """
        Retrieves the shared aiohttp.ClientSession, initializing it if necessary.

        Returns:
            The active aiohttp.ClientSession.
        """
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=DEFAULT_HTTP_TIMEOUT)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """
        Closes the aiohttp session. Call during shutdown.

        Returns:
            None
        """
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None


_session_mgr = _SessionManager()
vt_rate_limiter = AsyncLimiter(4, 60)


async def get_session() -> aiohttp.ClientSession:
    """
    Retrieves the global shared aiohttp.ClientSession.

    Returns:
        The active aiohttp.ClientSession.
    """
    return await _session_mgr.get()


async def close_session():
    """
    Closes the global aiohttp session. Call during shutdown.

    Returns:
        None
    """
    await _session_mgr.close()


class TransientHTTPError(Exception):
    pass


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
def _vt_verdict(raw_data: dict, ioc: str, ioc_type: str) -> dict:
    """
    Validates a VT response and returns a verdict dict.

    Args:
        raw_data: The raw JSON response from VirusTotal.
        ioc: The indicator of compromise.
        ioc_type: The type of IOC (e.g., "url", "hash").

    Returns:
        A dictionary containing the parsed verdict.

    Raises:
        VirusTotalResponseValidationError: If the response fails schema validation.
    """
    try:
        validated = VirusTotalResponse.model_validate(raw_data)
        malicious_count: int = validated.data.attributes.last_analysis_stats.malicious
        suspicious_count: int = validated.data.attributes.last_analysis_stats.suspicious
    except ValidationError as exc:
        logger.error("VirusTotal response failed schema validation. Raw response: %s", raw_data)
        raise VirusTotalResponseValidationError(
            message=f"VT {ioc_type} schema mismatch: {str(exc)}",
            raw_data=raw_data
        ) from exc

    if malicious_count >= VT_MALICIOUS_THRESHOLD:
        verdict = "malicious"
    elif malicious_count >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "ioc": ioc, "type": ioc_type,
        "malicious": malicious_count, "suspicious": suspicious_count,
        "verdict": verdict, "threshold_used": VT_MALICIOUS_THRESHOLD,
    }


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
async def _check_vt_url(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Queries VirusTotal URL analysis endpoint.

    Args:
        session: The aiohttp session to use for the request.
        url: The URL to analyze.

    Returns:
        A dictionary containing the URL verdict or error information.

    Raises:
        TransientHTTPError: If a retryable HTTP status is returned.
    """
    import base64
    encoded = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    t0 = time.monotonic()
    async with session.get(endpoint, headers={"x-apikey": VT_API_KEY}) as resp:
        ENRICHMENT_LATENCY.labels(api_name="virustotal_url").observe(
            (time.monotonic() - t0) * 1000
        )
        if resp.status in (429, 503, 504):
            raise TransientHTTPError(f"VirusTotal URL lookup transient HTTP {resp.status} for {url}")
        if resp.status == 200:
            return _vt_verdict(await resp.json(), url, "url")
        return {"ioc": url, "type": "url", "error": f"HTTP {resp.status}"}


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
async def _check_vt_hash(session: aiohttp.ClientSession, file_hash: str) -> dict:
    """
    Queries VirusTotal file hash endpoint.

    Args:
        session: The aiohttp session to use for the request.
        file_hash: The file hash to analyze.

    Returns:
        A dictionary containing the hash verdict or error information.

    Raises:
        TransientHTTPError: If a retryable HTTP status is returned.
    """
    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    t0 = time.monotonic()
    async with session.get(endpoint, headers={"x-apikey": VT_API_KEY}) as resp:
        ENRICHMENT_LATENCY.labels(api_name="virustotal_hash").observe(
            (time.monotonic() - t0) * 1000
        )
        if resp.status in (429, 503, 504):
            raise TransientHTTPError(f"VirusTotal hash lookup transient HTTP {resp.status} for {file_hash}")
        if resp.status == 200:
            return _vt_verdict(await resp.json(), file_hash, "hash")
        if resp.status == 404:
            # Not in VT database - genuinely unknown, not clean.
            # Returned as a valid (non-error) result so the LLM can reason about novelty.
            return {"ioc": file_hash, "type": "hash", "verdict": "not_found_in_vt"}
        return {"ioc": file_hash, "type": "hash", "error": f"HTTP {resp.status}"}


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
def _abuseipdb_verdict(raw_data: dict, ip: str) -> dict:
    """
    Validates an AbuseIPDB response and returns a verdict dict.

    Args:
        raw_data: The raw JSON response from AbuseIPDB.
        ip: The IP address analyzed.

    Returns:
        A dictionary containing the parsed IP verdict.

    Raises:
        AbuseIPDBResponseValidationError: If the response fails schema validation.
    """
    try:
        parsed = AbuseIPDBResponse.model_validate(raw_data)
        d_obj = parsed.data
        score = d_obj.abuseConfidenceScore
    except ValidationError as exc:
        logger.error("AbuseIPDB response failed schema validation. Raw response: %s", raw_data)
        raise AbuseIPDBResponseValidationError(
            message=f"AbuseIPDB schema mismatch: {str(exc)}",
            raw_data=raw_data
        ) from exc

    if score >= ABUSEIPDB_MALICIOUS_THRESHOLD:
        verdict = "malicious"
    elif score >= ABUSEIPDB_SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "ioc": ip, "type": "ip",
        "abuse_score": score, "verdict": verdict,
        "threshold_used": ABUSEIPDB_MALICIOUS_THRESHOLD,
        "total_reports": d_obj.totalReports,
        "country": d_obj.countryCode,
        "isp": d_obj.isp,
        "usage_type": d_obj.usageType,
    }


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
async def _check_abuseipdb(session: aiohttp.ClientSession, ip: str) -> dict:
    """
    Queries AbuseIPDB for IP reputation.

    Args:
        session: The aiohttp session to use for the request.
        ip: The IP address to check.

    Returns:
        A dictionary containing the IP verdict or error information.

    Raises:
        TransientHTTPError: If a retryable HTTP status is returned.
    """
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    t0 = time.monotonic()
    async with session.get(endpoint, headers=headers, params=params) as resp:
        ENRICHMENT_LATENCY.labels(api_name="abuseipdb").observe(
            (time.monotonic() - t0) * 1000
        )
        if resp.status in (429, 503, 504):
            raise TransientHTTPError(f"AbuseIPDB lookup transient HTTP {resp.status} for {ip}")
        if resp.status == 200:
            return _abuseipdb_verdict(await resp.json(), ip)
        return {"ioc": ip, "type": "ip", "error": f"HTTP {resp.status}"}


def _is_error_result(result: dict) -> bool:
    """
    Determines if a CTI lookup result represents a failed lookup.

    Args:
        result: The lookup result dictionary.

    Returns:
        True if the result contains an error, False otherwise.
    """
    return "error" in result


def _partition_results(
    results: list,
    iocs: list[str],
    source_label: str,
) -> tuple[list[dict], list[str]]:
    """
    Separates gather() results into successful reports and error strings.

    Args:
        results: The list of results returned by asyncio.gather.
        iocs: The list of corresponding indicators queried.
        source_label: A label describing the CTI source (e.g., "VirusTotal URL").

    Returns:
        A tuple containing (list of successful reports, list of error strings).
    """
    reports: list[dict] = []
    errors: list[str] = []

    for idx, result in enumerate(results):
        ioc_label = iocs[idx] if idx < len(iocs) else "?"

        if isinstance(result, BaseException):
            msg = f"enrich_node: {source_label} lookup failed for {ioc_label}: {result}"
            logger.exception(msg)
            errors.append(msg)
            continue

        if not isinstance(result, dict):
            continue

        if _is_error_result(result):
            ioc_label = result.get("ioc") or ioc_label
            msg = f"enrich_node: {source_label} returned error for {ioc_label}: {result['error']}"
            logger.warning(msg)
            errors.append(msg)
        else:
            reports.append(result)

    return reports, errors


def _build_internal_reports(entities: dict) -> list[dict]:
    """
    Builds non-enriched reports for RFC 1918 lateral movement candidates.

    Args:
        entities: The extracted entities dictionary.

    Returns:
        A list of internal IP report dictionaries.
    """
    return [
        {
            "ioc": ip, "type": "internal_ip",
            "verdict": "lateral_movement_candidate",
            "note": "RFC 1918 address - not submitted to external CTI. Investigate for host-to-host pivoting.",
        }
        for ip in entities.get("internal_ips", [])
    ]


async def _rate_limited_vt(session, check_fn, ioc: str, ioc_type: str):
    """
    Wraps a VT check coroutine with rate limiting and error capture.

    Args:
        session: The aiohttp session.
        check_fn: The coroutine function to call (e.g., _check_vt_url).
        ioc: The indicator to check.
        ioc_type: The type of indicator (e.g., "url", "hash").

    Returns:
        The verdict dictionary or an error dictionary.
    """
    async with vt_rate_limiter:
        try:
            return await check_fn(session, ioc)
        except Exception as exc:
            logger.exception("VirusTotal %s enrichment failed for %s", ioc_type, ioc)
            return {"ioc": ioc, "type": ioc_type, "error": str(exc)}


async def _run_enrichment(entities: dict) -> tuple[dict, list[str], list[str]]:
    """
    Runs all CTI lookups concurrently.

    Args:
        entities: Dictionary of extracted entities to enrich.

    Returns:
        A tuple containing (cti_results, errors, degraded_sources).
    """
    session = await get_session()

    ip_list = entities.get("ips", [])
    url_list = entities.get("urls", [])
    hash_list = entities.get("hashes", [])

    ip_reports, url_reports, hash_reports = [], [], []
    enrichment_errors: list[str] = []
    degraded: list[str] = []

    # ── AbuseIPDB tasks ───────────────────────────────────────────────────
    abuseipdb_tasks: list = []
    try:
        if ip_list:
            if not ABUSEIPDB_API_KEY:
                raise ValueError("ABUSEIPDB_API_KEY not configured")
            abuseipdb_tasks = [_check_abuseipdb(session, ip) for ip in ip_list]
    except Exception as exc:
        degraded.append("abuseipdb")
        enrichment_errors.append(f"enrich_node: AbuseIPDB unavailable: {exc}")
        logger.warning("AbuseIPDB source degraded: %s", exc)

    # ── VirusTotal tasks ──────────────────────────────────────────────────
    vt_url_tasks: list = []
    vt_hash_tasks: list = []
    try:
        if url_list or hash_list:
            if not VT_API_KEY:
                raise ValueError("VT_API_KEY not configured")
            vt_url_tasks = [_rate_limited_vt(session, _check_vt_url, u, "url") for u in url_list]
            vt_hash_tasks = [_rate_limited_vt(session, _check_vt_hash, h, "hash") for h in hash_list]
    except Exception as exc:
        degraded.append("virustotal")
        enrichment_errors.append(f"enrich_node: VirusTotal unavailable: {exc}")
        logger.warning("VirusTotal source degraded: %s", exc)

    # ── Run all surviving tasks concurrently ──────────────────────────────
    all_tasks = abuseipdb_tasks + vt_url_tasks + vt_hash_tasks

    if all_tasks:
        results = await asyncio.gather(*all_tasks, return_exceptions=True)

        ab_len = len(abuseipdb_tasks)
        vt_url_len = len(vt_url_tasks)

        # ── Process AbuseIPDB results ─────────────────────────────────
        try:
            ip_reports, ip_errs = _partition_results(
                results[:ab_len], ip_list, "AbuseIPDB",
            )
            enrichment_errors.extend(ip_errs)
        except Exception as exc:
            if "abuseipdb" not in degraded:
                degraded.append("abuseipdb")
            enrichment_errors.append(f"enrich_node: AbuseIPDB result processing failed: {exc}")
            logger.error("AbuseIPDB result processing failed: %s", exc)

        # ── Process VirusTotal results ────────────────────────────────
        try:
            vt_results = results[ab_len:]
            url_reports, url_errs = _partition_results(
                vt_results[:vt_url_len], url_list, "VirusTotal URL",
            )
            hash_reports, hash_errs = _partition_results(
                vt_results[vt_url_len:], hash_list, "VirusTotal hash",
            )
            enrichment_errors.extend(url_errs + hash_errs)
        except Exception as exc:
            if "virustotal" not in degraded:
                degraded.append("virustotal")
            enrichment_errors.append(f"enrich_node: VirusTotal result processing failed: {exc}")
            logger.error("VirusTotal result processing failed: %s", exc)

    return (
        {
            "ip_reports": ip_reports,
            "url_reports": url_reports,
            "hash_reports": hash_reports,
            "internal_ip_reports": _build_internal_reports(entities),
        },
        enrichment_errors,
        degraded,
    )


async def enrich_node(state: TriageState) -> dict:
    """
    Enriches extracted IOCs using external threat intelligence sources.

    Args:
        state: The current TriageState dictionary.

    Returns:
        A dictionary containing state updates for cti_results, errors, and degraded_sources.
    """
    logger.info("node_entry", node="enrich")
    entities = state.get("entities", {}) or {}

    if not any([entities.get("ips"), entities.get("urls"), entities.get("hashes"), entities.get("internal_ips")]):
        logger.info("node_exit", node="enrich")
        return {"cti_results": {"ip_reports": [], "url_reports": [], "hash_reports": [], "internal_ip_reports": []}}

    cti_results, enrichment_errors, degraded = await _run_enrichment(entities)

    update: dict = {"cti_results": cti_results}
    if enrichment_errors:
        update["errors"] = enrichment_errors
    if degraded:
        update["degraded_sources"] = degraded

    logger.info("node_exit", node="enrich")
    return update