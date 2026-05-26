"""
Authentication using Azure Identity for Azure REST API access.
Uses DefaultAzureCredential to obtain tokens via Managed Identity (production) or Azure CLI (local development).

DefaultAzureCredential (singleton)
        │
        ▼
get_access_token(scope)  ←── _cached_tokens dict (check the cache first, and refresh if needed)
        │
        ├── get_graph_token()       → Microsoft Graph API
        ├── get_mde_token()         → Defender for Endpoint API
        └── get_auth_headers()      → Azure Management API (default)
"""

import threading
import time
from typing import Any
from azure.identity import DefaultAzureCredential

# The scope for Azure Resource Manager API (management.azure.com)
# ".default" means "all permissions for this app has been granted".
MANAGEMENT_SCOPE = "https://management.azure.com/.default"

_credential: DefaultAzureCredential | None = None
_credential_lock = threading.Lock()


def _get_credential() -> DefaultAzureCredential:
    """Return the shared DefaultAzureCredential, creating it on first use."""
    global _credential
    if _credential is None:
        with _credential_lock:
            if _credential is None:
                _credential = DefaultAzureCredential()
    return _credential


# Module-level cache for tokens by scope
_cached_tokens: dict[str, dict[str, Any]] = {}
_token_lock = threading.Lock()


def get_access_token(scope: str = MANAGEMENT_SCOPE) -> str:
    """
    Get cached bearer token using DefaultAzureCredential.
    This architecture is strictly secretless, relying on Managed Identity (prod) and Azure CLI (local).
    Tokens are cached locally to avoid unnecessary function call overhead and potential round-trip latency.
    The token is refreshed only if missing or within 5 minutes of expiration.
    """ 
    with _token_lock:
        cached = _cached_tokens.get(scope) # Check cache for token 
        if (cached is None or
            cached["expires_on"] is None or
            time.time() + 300 >= cached["expires_on"]): # Refresh if missing or within 5 minutes of expiration
            token = _get_credential().get_token(scope)
            _cached_tokens[scope] = {
                "token": token.token, # JWT access token string
                "expires_on": token.expires_on,
            }

        return _cached_tokens[scope]["token"]


"""
Facade wrappers hides URI complexity from the callers. 
Instead of writing the URLs every time, we define functions to do this.
"""

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