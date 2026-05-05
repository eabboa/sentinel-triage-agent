"""
Queries VirusTotal and AbuseIPDB concurrently for all extracted IOCs.
"""

import asyncio
import logging
import os
import aiohttp
from aiolimiter import AsyncLimiter
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from state import TriageState

logger = logging.getLogger(__name__)
DEFAULT_HTTP_TIMEOUT = 10
RETRY_ATTEMPTS = 3

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Global instances for connection pooling and rate limiting
_client_session: aiohttp.ClientSession | None = None
vt_rate_limiter = AsyncLimiter(4, 60)

async def get_session() -> aiohttp.ClientSession:
    global _client_session
    if _client_session is None or _client_session.closed:
        timeout = aiohttp.ClientTimeout(total=DEFAULT_HTTP_TIMEOUT)
        _client_session = aiohttp.ClientSession(timeout=timeout)
    return _client_session


class TransientHTTPError(Exception):
    pass


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
async def _check_vt_url(session: aiohttp.ClientSession, url: str) -> dict:
    """Queries VirusTotal URL analysis endpoint."""
    import base64
    # VT API v3 requires the URL to be URL-safe base64 encoded (no padding)
    encoded = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    async with session.get(endpoint, headers={"x-apikey": VT_API_KEY}) as resp:
        if resp.status in (429, 503, 504):
            raise TransientHTTPError(f"VirusTotal URL lookup transient HTTP {resp.status} for {url}")
        if resp.status == 200:
            data = await resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "ioc": url,
                "type": "url",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
            }
        return {"ioc": url, "type": "url", "error": f"HTTP {resp.status}"}


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
async def _check_vt_hash(session: aiohttp.ClientSession, file_hash: str) -> dict:
    """Queries VirusTotal file hash endpoint."""
    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    async with session.get(endpoint, headers={"x-apikey": VT_API_KEY}) as resp:
        if resp.status in (429, 503, 504):
            raise TransientHTTPError(f"VirusTotal hash lookup transient HTTP {resp.status} for {file_hash}")
        if resp.status == 200:
            data = await resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "ioc": file_hash,
                "type": "hash",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
            }
        elif resp.status == 404:
            return {"ioc": file_hash, "type": "hash", "verdict": "not_found"}
        return {"ioc": file_hash, "type": "hash", "error": f"HTTP {resp.status}"}


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError, TransientHTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    reraise=True,
)
async def _check_abuseipdb(session: aiohttp.ClientSession, ip: str) -> dict:
    """Queries AbuseIPDB for IP reputation."""
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    async with session.get(endpoint, headers=headers, params=params) as resp:
        if resp.status in (429, 503, 504):
            raise TransientHTTPError(f"AbuseIPDB lookup transient HTTP {resp.status} for {ip}")
        if resp.status == 200:
            data = await resp.json()
            d = data["data"]
            return {
                "ioc": ip,
                "type": "ip",
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "usage_type": d.get("usageType", "Unknown"),
            }
        return {"ioc": ip, "type": "ip", "error": f"HTTP {resp.status}"}


async def _run_enrichment(entities: dict) -> dict:
    """
    Runs all CTI lookups concurrently.
    VT calls are rate limited to 4 req/min using aiolimiter.
    """
    ip_reports = []
    url_reports = []
    hash_reports = []

    session = await get_session()

    # Prepare AbuseIPDB tasks
    ip_tasks = [_check_abuseipdb(session, ip) for ip in entities.get("ips", [])]

    # Prepare VirusTotal URL tasks with rate limit wrapper
    async def fetch_vt_url(url: str):
        async with vt_rate_limiter:
            try:
                return await _check_vt_url(session, url)
            except Exception as exc:
                logger.exception("VirusTotal URL enrichment failed for %s", url)
                return {"ioc": url, "type": "url", "error": str(exc)}

    url_tasks = [fetch_vt_url(url) for url in entities.get("urls", [])]

    # Prepare VirusTotal Hash tasks with rate limit wrapper
    async def fetch_vt_hash(file_hash: str):
        async with vt_rate_limiter:
            try:
                return await _check_vt_hash(session, file_hash)
            except Exception as exc:
                logger.exception("VirusTotal hash enrichment failed for %s", file_hash)
                return {"ioc": file_hash, "type": "hash", "error": str(exc)}

    hash_tasks = [fetch_vt_hash(h) for h in entities.get("hashes", [])]

    # Run all tasks concurrently
    all_tasks = ip_tasks + url_tasks + hash_tasks
    if all_tasks:
        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        
        # Unpack results based on task counts
        ip_len = len(ip_tasks)
        url_len = len(url_tasks)
        
        ip_results = results[:ip_len]
        url_results = results[ip_len:ip_len+url_len]
        hash_results = results[ip_len+url_len:]
        
        for ip, result in zip(entities.get("ips", []), ip_results):
            if isinstance(result, Exception):
                logger.exception("AbuseIPDB enrichment failed for %s", ip)
                ip_reports.append({"ioc": ip, "type": "ip", "error": str(result)})
            else:
                ip_reports.append(result)
                
        for result in url_results:
            if isinstance(result, Exception):
                url_reports.append({"ioc": "unknown", "type": "url", "error": str(result)})
            else:
                url_reports.append(result)
                
        for result in hash_results:
            if isinstance(result, Exception):
                hash_reports.append({"ioc": "unknown", "type": "hash", "error": str(result)})
            else:
                hash_reports.append(result)

    return {
        "ip_reports": ip_reports,
        "url_reports": url_reports,
        "hash_reports": hash_reports,
    }


async def enrich_node(state: TriageState) -> dict:
    entities = state.get("entities", {})

    if not any([entities.get("ips"), entities.get("urls"), entities.get("hashes")]):
        return {"cti_results": {"ip_reports": [], "url_reports": [], "hash_reports": []}}

    cti_results = await _run_enrichment(entities)
    return {"cti_results": cti_results}