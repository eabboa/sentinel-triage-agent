"""
Authentication using Azure Identity for Azure REST API access.
Uses DefaultAzureCredential to obtain tokens via Managed Identity (production) or Azure CLI (local development).
"""

import os
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential

# The scope for Azure Resource Manager API (management.azure.com)
# ".default" means "all permissions for this app has been granted".
MANAGEMENT_SCOPE = "https://management.azure.com/.default"

credential = DefaultAzureCredential()

# Module-level cache for tokens by scope
_cached_tokens = {}


import time

def get_access_token(scope: str = MANAGEMENT_SCOPE) -> str:
    """
    Get cached bearer token using DefaultAzureCredential.
    
    This architecture is strictly secretless, relying on Managed Identity (prod) and Azure CLI (local).
    Tokens are cached locally to avoid unnecessary function call overhead and potential round-trip latency.
    The token is refreshed only if missing or within 5 minutes of expiration.
    """
    global _cached_tokens

    cached = _cached_tokens.get(scope)
    if (cached is None or
        cached["expires_on"] is None or
        time.time() + 300 >= cached["expires_on"]):
        token = credential.get_token(scope)
        _cached_tokens[scope] = {
            "token": token.token,
            "expires_on": token.expires_on,
        }

    return _cached_tokens[scope]["token"]


def get_graph_token() -> str:
    """Get a token scoped to Microsoft Graph."""
    return get_access_token("https://graph.microsoft.com/.default")


def get_mde_token() -> str:
    """Get a token scoped to Microsoft Defender for Endpoint."""
    return get_access_token("https://api.securitycenter.microsoft.com/.default")


def get_auth_headers() -> dict:
    """Return authorization headers with Bearer token."""
    token = get_access_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }