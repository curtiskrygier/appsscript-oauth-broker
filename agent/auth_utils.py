import logging
import os

import httpx
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
# Set these as environment variables on your Reasoning Engine / Agent deployment.

# URL of the deployed Cloud Run broker, no trailing slash.
AUTH_SERVICE_URL = os.environ["AUTH_SERVICE_URL"]

# Shared secret — must match TOKEN_SERVICE_SECRET on the broker.
_TOKEN_SECRET = os.environ["TOKEN_SERVICE_SECRET"]

# API Executable deployment ID (starts with AKfy), from Deploy → Manage deployments.
SCRIPT_ID = os.environ["SCRIPT_ID"]

AUTH_URL = f"{AUTH_SERVICE_URL}/auth"


# ── Token retrieval ───────────────────────────────────────────────────────────

async def get_access_token(email: str) -> str | None:
    """
    Calls the broker's /token endpoint to get a fresh access token for the user.
    Returns None if the user has not yet completed the /auth consent flow,
    or if the broker is unreachable.
    """
    headers = {"Authorization": f"Bearer {_TOKEN_SECRET}"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{AUTH_SERVICE_URL}/token",
                params={"email": email},
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.error(f"Auth service error {e.response.status_code}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to connect to auth service: {e}")
        return None

    data = resp.json()
    if data.get("status") == "auth_required":
        logger.warning(f"No token stored for {email} — user must visit {AUTH_URL}")
        return None
    return data.get("access_token")


# ── Apps Script execution ─────────────────────────────────────────────────────

def scripts_run(access_token: str, function_name: str, params: dict) -> dict:
    """
    Executes a function in the linked Apps Script API Executable deployment
    using the provided user access token.
    """
    creds = Credentials(token=access_token)
    service = build("script", "v1", credentials=creds)
    return service.scripts().run(
        scriptId=SCRIPT_ID,
        body={"function": function_name, "parameters": [params], "devMode": False},
    ).execute()
