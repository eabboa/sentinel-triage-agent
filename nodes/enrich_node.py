"""
Queries VirusTotal and AbuseIPDB concurrently for all extracted IOCs.
"""

import asyncio
import logging
import os
import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from state import TriageState

logger = logging.getLogger(__name__)
DEFAULT_HTTP_TIMEOUT = 10
RETRY_ATTEMPTS = 3

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

VT_RATE_LIMIT_SLEEP = 15


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
    Runs all CTI lookups concurrently with rate limiting.
    VT calls are serialized (rate limited)
    AbuseIPDB calls are concurrent.
    """
    ip_reports = []
    url_reports = []
    hash_reports = []

    timeout = aiohttp.ClientTimeout(total=DEFAULT_HTTP_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # AbuseIPDB
        ip_tasks = [_check_abuseipdb(session, ip) for ip in entities.get("ips", [])]
        if ip_tasks:
            ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
            for ip, result in zip(entities.get("ips", []), ip_results):
                if isinstance(result, Exception):
                    logger.exception("AbuseIPDB enrichment failed for %s", ip)
                    ip_reports.append({"ioc": ip, "type": "ip", "error": str(result)})
                else:
                    ip_reports.append(result)

        # VirusTotal URLs
        for url in entities.get("urls", []):
            try:
                result = await _check_vt_url(session, url)
            except Exception as exc:
                logger.exception("VirusTotal URL enrichment failed for %s", url)
                result = {"ioc": url, "type": "url", "error": str(exc)}
            url_reports.append(result)
            await asyncio.sleep(VT_RATE_LIMIT_SLEEP)

        # VirusTotal Hashes
        for file_hash in entities.get("hashes", []):
            try:
                result = await _check_vt_hash(session, file_hash)
            except Exception as exc:
                logger.exception("VirusTotal hash enrichment failed for %s", file_hash)
                result = {"ioc": file_hash, "type": "hash", "error": str(exc)}
            hash_reports.append(result)
            await asyncio.sleep(VT_RATE_LIMIT_SLEEP)

    return {
        "ip_reports": ip_reports,
        "url_reports": url_reports,
        "hash_reports": hash_reports,
    }


def enrich_node(state: TriageState) -> dict:
    entities = state.get("entities", {})

    if not any([entities.get("ips"), entities.get("urls"), entities.get("hashes")]):
        return {"cti_results": {"ip_reports": [], "url_reports": [], "hash_reports": []}}

    cti_results = asyncio.run(_run_enrichment(entities))
    return {"cti_results": cti_results}