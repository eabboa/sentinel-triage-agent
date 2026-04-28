"""
Queries VirusTotal and AbuseIPDB concurrently for all extracted IOCs.
"""

import asyncio
import os
import aiohttp
from state import TriageState

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

VT_RATE_LIMIT_SLEEP = 15


async def _check_vt_url(session: aiohttp.ClientSession, url: str) -> dict:
    """Queries VirusTotal URL analysis endpoint."""
    import base64
    # VT API v3 requires the URL to be URL-safe base64 encoded (no padding)
    encoded = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"
    
    async with session.get(endpoint, headers={"x-apikey": VT_API_KEY}) as resp:
        if resp.status == 200:
            data = await resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {"ioc": url, "type": "url", "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0), "total": sum(stats.values())}
        return {"ioc": url, "type": "url", "error": f"HTTP {resp.status}"}


async def _check_vt_hash(session: aiohttp.ClientSession, file_hash: str) -> dict:
    """Queries VirusTotal file hash endpoint."""
    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    async with session.get(endpoint, headers={"x-apikey": VT_API_KEY}) as resp:
        if resp.status == 200:
            data = await resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {"ioc": file_hash, "type": "hash", "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0), "total": sum(stats.values())}
        elif resp.status == 404:
            return {"ioc": file_hash, "type": "hash", "verdict": "not_found"}
        return {"ioc": file_hash, "type": "hash", "error": f"HTTP {resp.status}"}


async def _check_abuseipdb(session: aiohttp.ClientSession, ip: str) -> dict:
    """Queries AbuseIPDB for IP reputation."""
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    
    async with session.get(endpoint, headers=headers, params=params) as resp:
        if resp.status == 200:
            data = await resp.json()
            d = data["data"]
            return {
                "ioc": ip, "type": "ip",
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

    async with aiohttp.ClientSession() as session:
        # AbuseIPDB
        ip_tasks = [_check_abuseipdb(session, ip) for ip in entities.get("ips", [])]
        if ip_tasks:
            ip_reports = await asyncio.gather(*ip_tasks, return_exceptions=False)

        # VirusTotal URLs
        for url in entities.get("urls", []):
            result = await _check_vt_url(session, url)
            url_reports.append(result)
            await asyncio.sleep(VT_RATE_LIMIT_SLEEP)

        # VirusTotal Hashes
        for file_hash in entities.get("hashes", []):
            result = await _check_vt_hash(session, file_hash)
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