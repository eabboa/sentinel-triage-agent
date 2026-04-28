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

# Module-level cache for token and expiration
_cached_token = None
_token_expires_on = None


def get_access_token() -> str:
    """
    Get cached bearer token using DefaultAzureCredential.
    
    This architecture is strictly secretless, relying on Managed Identity (prod) and Azure CLI (local).
    Tokens are cached locally to avoid unnecessary function call overhead and potential round-trip latency.
    The token is refreshed only if missing or within 5 minutes of expiration.
    """
    global _cached_token, _token_expires_on
    
    if (_cached_token is None or 
        _token_expires_on is None or 
        datetime.now() + timedelta(minutes=5) >= _token_expires_on):
        
        token = credential.get_token(MANAGEMENT_SCOPE)
        _cached_token = token.token
        _token_expires_on = token.expires_on
    
    return _cached_token


def get_auth_headers() -> dict:
    """Return authorization headers with Bearer token."""
    token = get_access_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }