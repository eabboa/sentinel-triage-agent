"""
OAuth2 Client Credentials flow for Azure REST API access.
MSAL (MS Authentication Library) handles token caching automatically.
"""

import os
import msal
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# The scope for Azure Resource Manager API (management.azure.com)
# ".default" means "all permissions for this app has been granted". I gave "MS Sentinel Contributor" back then.
MANAGEMENT_SCOPE = ["https://management.azure.com/.default"]


def get_access_token() -> str: ## Get bearer token using Client Credentials flow. we did not used authorization model because Client Credentials flow is the correct way to handle M2M auth.
    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}", ## if microsoft changes that specific url, the code will break.
    )

    # acquire_token_for_client checks the MSAL cache first.
    # If a valid token exists, it returns it without a call.
    # If expired, it fetches a new one.
    result = app.acquire_token_for_client(scopes=MANAGEMENT_SCOPE)

    if "access_token" not in result:
        # result contains error details when authentication fails
        raise RuntimeError( ## it lumps every single error under the name of RuntimeError. further development might distinguish `AuthenticationError` vs. `ConnectionError` and automatically retry.
	            f"Authentication failed: {result.get('error')} - "
	            f"{result.get('error_description')}"
        )

    return result["access_token"]


	def get_auth_headers() -> dict: ## readability and changeability for future use. e.g. if Content-Type or Authorization header suddenly changes etc etc.
	    token = get_access_token()
	    return {
	        "Authorization": f"Bearer {token}",
	        "Content-Type": "application/json",
	    }