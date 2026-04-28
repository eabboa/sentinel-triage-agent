"""
Authentication using Azure Identity for Azure REST API access.
Uses DefaultAzureCredential to obtain tokens via Managed Identity or Azure CLI.
"""

import os
from azure.identity import DefaultAzureCredential

# The scope for Azure Resource Manager API (management.azure.com)
# ".default" means "all permissions for this app has been granted".
MANAGEMENT_SCOPE = "https://management.azure.com/.default"


def get_access_token() -> str:
    """Get bearer token using DefaultAzureCredential."""
    credential = DefaultAzureCredential()
    token = credential.get_token(MANAGEMENT_SCOPE)
    return token.token


def get_auth_headers() -> dict:
    """Return authorization headers with Bearer token."""
    token = get_access_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }