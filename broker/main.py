import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from email.utils import parseaddr
from functools import lru_cache

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from google.api_core.exceptions import AlreadyExists
from google.cloud import secretmanager
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
# All values must be provided as environment variables — no defaults.

PROJECT_ID = os.environ["PROJECT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
# REDIRECT_URI: full callback URL, e.g. https://YOUR-SERVICE.run.app/auth/callback
REDIRECT_URI = os.environ["REDIRECT_URI"]
BASE_URL = REDIRECT_URI.removesuffix("/auth/callback")

# Shared secret between this service and the agent. Used to authenticate /token calls.
TOKEN_SERVICE_SECRET = os.environ["TOKEN_SERVICE_SECRET"]

# CLIENT_SECRET is stored in Secret Manager under this secret ID.
CLIENT_SECRET_ID = os.environ.get("CLIENT_SECRET_ID", "oauth-client-secret")

# ── Scopes ────────────────────────────────────────────────────────────────────
# Adjust to the minimum your Apps Script project declares.
# Mismatched scopes cause PERMISSION_DENIED from scripts.run.
SCOPES = [
    # Required for all deployments — identifies the user after consent
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",

    # Apps Script execution — minimum required for scripts.run
    "https://www.googleapis.com/auth/script.projects",
    "https://www.googleapis.com/auth/script.external_request",
    "https://www.googleapis.com/auth/script.scriptapp",

    # Drive / Docs / Sheets / Slides — add only what your script actually calls
    # Remove scopes your Apps Script function does not use.
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/presentations",

    # Forms — remove if your script does not create or edit Forms
    "https://www.googleapis.com/auth/forms.body",

    # Gmail — remove if your script does not send or read email
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",

    # Calendar — remove if your script does not access Calendar
    "https://www.googleapis.com/auth/calendar",

    # Contacts / Directory — remove if your script does not look up people
    "https://www.googleapis.com/auth/contacts",
    "https://www.googleapis.com/auth/directory.readonly",
]

app = FastAPI(title="Cloud Run OAuth Broker")


# ── Secret Manager helpers ────────────────────────────────────────────────────

@lru_cache()
def _get_client_secret() -> str:
    # Cached for the instance lifetime. If the secret is rotated in Secret Manager,
    # redeploy the service to pick up the new value (gcloud run services update --region ...).
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{CLIENT_SECRET_ID}/versions/latest"
    return client.access_secret_version(request={"name": name}).payload.data.decode()


def _get_refresh_token(email: str) -> str | None:
    secret_id = f"workspace-token-{email.replace('@', '-').replace('.', '-')}"
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        return client.access_secret_version(request={"name": name}).payload.data.decode()
    except Exception as e:
        logger.error(f"Failed to retrieve token for {email}: {e}")
        return None


def _store_refresh_token(email: str, refresh_token: str):
    secret_id = f"workspace-token-{email.replace('@', '-').replace('.', '-')}"
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{PROJECT_ID}"
    secret_path = f"{parent}/secrets/{secret_id}"
    try:
        client.get_secret(request={"name": secret_path})
    except Exception:
        try:
            client.create_secret(request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            })
        except AlreadyExists:
            pass  # concurrent first-auth race; the other request already created the secret
    try:
        client.add_secret_version(request={
            "parent": secret_path,
            "payload": {"data": refresh_token.encode()},
        })
    except Exception as e:
        logger.error(f"Failed to store refresh token for {email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to store authorisation token")
    logger.info(f"Stored refresh token for {email}")


# ── OAuth flow helpers ────────────────────────────────────────────────────────

def _make_flow() -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": _get_client_secret(),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
    )


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _sign_state(payload: str) -> str:
    sig = hmac.new(TOKEN_SERVICE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify_state(signed: str) -> dict:
    if "." not in signed:
        raise HTTPException(status_code=400, detail="Unsigned state parameter.")
    payload, sig = signed.rsplit(".", 1)
    expected = hmac.new(TOKEN_SERVICE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=400, detail="Invalid state signature.")
    return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/auth")
async def auth_start(hint: str = ""):
    """
    Entry point for the OAuth consent flow.
    Send users here once. Their refresh token is stored in Secret Manager.
    Optional ?hint= parameter is surfaced on the success page.
    """
    flow = _make_flow()
    flow.redirect_uri = REDIRECT_URI
    verifier, challenge = _pkce_pair()
    auth_url, oauth_state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    state_payload = base64.urlsafe_b64encode(
        json.dumps({"cv": verifier, "s": oauth_state, "h": hint}).encode()
    ).decode()
    signed = _sign_state(state_payload)
    auth_url = auth_url.replace(f"state={oauth_state}", f"state={signed}")
    return RedirectResponse(auth_url)


@app.get("/auth/callback")
async def auth_callback(code: str, state: str):
    state_data = _verify_state(state)
    flow = _make_flow()
    flow.redirect_uri = REDIRECT_URI
    flow.fetch_token(code=code, code_verifier=state_data["cv"])

    creds = flow.credentials
    user_info = build("oauth2", "v2", credentials=creds).userinfo().get().execute()
    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not retrieve user email.")

    _store_refresh_token(email, creds.refresh_token)

    import html as _html
    hint = state_data.get("h", "")
    success_message = os.environ.get("AUTH_SUCCESS_MESSAGE", "Return to your agent and re-submit your request.")
    hint_html = (
        f"<p>You originally asked: <em>{_html.escape(hint)}</em></p>"
        f"<p>{_html.escape(success_message)}</p>"
        if hint else
        f"<p>{_html.escape(success_message)}</p>"
    )
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>Authorisation Successful</title>
<style>body{{font-family:sans-serif;max-width:600px;margin:80px auto;text-align:center;color:#202124}}
h1{{color:#1a73e8}}p{{line-height:1.6}}</style></head>
<body>
<h1>&#10003; Authorisation Successful</h1>
<p>Access granted for <strong>{email}</strong>.</p>
{hint_html}
</body></html>""")


@app.get("/token")
async def get_token(request: Request, email: str):
    """
    Called by the ADK agent to exchange a stored refresh token for a fresh access token.
    Requires Authorization: Bearer <TOKEN_SERVICE_SECRET>.
    Returns {"status": "ok", "access_token": "..."} or
            {"status": "auth_required", "auth_url": "..."}.
    """
    if not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {TOKEN_SERVICE_SECRET}"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not email:
        raise HTTPException(status_code=400, detail="email param required")

    _, addr = parseaddr(email)
    if "@" not in addr:
        raise HTTPException(status_code=400, detail="Invalid email address")

    refresh_token = _get_refresh_token(email)
    if not refresh_token:
        return JSONResponse({"status": "auth_required", "auth_url": f"{BASE_URL}/auth"})

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post("https://oauth2.googleapis.com/token", data={
                "client_id": CLIENT_ID,
                "client_secret": _get_client_secret(),
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            })
        resp.raise_for_status()
        return {"status": "ok", "access_token": resp.json()["access_token"]}
    except httpx.HTTPStatusError as e:
        if e.response.json().get("error") == "invalid_grant":
            logger.warning(f"invalid_grant for {email} — token revoked or expired; re-auth required")
            return JSONResponse({"status": "auth_required", "auth_url": f"{BASE_URL}/auth"})
        logger.error(f"Token exchange HTTP error for {email}: {e}")
        raise HTTPException(status_code=500, detail="Token exchange failed")
    except Exception as e:
        logger.error(f"Token exchange failed for {email}: {e}")
        raise HTTPException(status_code=500, detail="Token exchange failed")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
