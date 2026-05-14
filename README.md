# workspace-oauth-broker

Google's `scripts.run` API requires a user OAuth token — service accounts can't call it on behalf of users. This Cloud Run broker solves that gap: users consent once, their refresh token is stored in Secret Manager, and your agent exchanges it for a fresh access token on every call.

Works with ADK, LangChain, Claude API, or any framework that can make an HTTP call. The broker is framework-agnostic; `agent/auth_utils.py` is an ADK + Apps Script example.

Full write-up: [The Cloud Run OAuth Broker: Per-User Identity for AI Agents](https://techmusings.krygier.fr/post/cloud-run-oauth-broker)

## How it works

```
User (once)    → GET /auth            → Google OAuth consent
               → GET /auth/callback   → refresh token stored in Secret Manager

Agent (per call) → GET /token?email=  → fresh access token
                   (Authorization: Bearer TOKEN_SERVICE_SECRET)
               → call any Google API as that user
```

Two flows, one infrastructure. Users authorise once. Every subsequent agent call executes as the requesting user — their identity appears in Drive, Docs, Calendar, and audit logs.

## Prerequisites summary

Several GCP resources are needed before this works: Cloud Run, two Secret Manager secrets (client secret + broker shared secret), an OAuth 2.0 Web client, IAM bindings for two service accounts, and an Apps Script API Executable deployment. Per-user secrets are created automatically on first auth. See [Prerequisites](#prerequisites) below.

## Repository structure

```
broker/
  main.py          Cloud Run service: /auth, /auth/callback, /token, /health
  requirements.txt
  Dockerfile

agent/
  auth_utils.py    Token retrieval + Apps Script helper (copy into your agent package)
  requirements.txt Agent-side dependencies
  __init__.py

.env.example       All required environment variables documented
```

## Prerequisites

### GCP IAM

| Principal | Role | Scope |
|-----------|------|-------|
| Cloud Run Service Account | `roles/secretmanager.secretAccessor` | Project |
| Cloud Run Service Account | `roles/logging.logWriter` | Project |
| Agent Service Account | `roles/run.invoker` | This Cloud Run service only |
| Your admin account | `roles/secretmanager.admin` | Project |

Grant `roles/run.invoker` **per service**, not at project level:

```bash
gcloud run services add-iam-policy-binding YOUR_SERVICE \
  --region=YOUR_REGION \
  --member="serviceAccount:YOUR_AGENT_SA@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

### OAuth client

Create a **Web application** OAuth 2.0 client in GCP Console → APIs & Services → Credentials.  
Add `https://YOUR-SERVICE-URL/auth/callback` as an Authorised Redirect URI.  
Store the client secret in Secret Manager:

```bash
echo -n "your-client-secret" | \
  gcloud secrets create oauth-client-secret --data-file=- --project=YOUR_PROJECT
```

### Apps Script

- Deploy your script as **API Executable** (Deploy → New deployment → API Executable).
- The Apps Script project and the GCP project making the `scripts.run` call must be linked to the same standard Google Cloud project.
- Note the deployment ID (`AKfy...`) from Deploy → Manage deployments — this is `SCRIPT_ID`, not the editor-visible script identifier.

## Deployment

### Broker (Cloud Run)

Store `TOKEN_SERVICE_SECRET` in Secret Manager first — do not pass it as a plain env var:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))" | \
  gcloud secrets create token-service-secret --data-file=- --project=YOUR_PROJECT
```

Then deploy, injecting the secret rather than writing it into the command line:

```bash
cd broker

gcloud run deploy YOUR_SERVICE \
  --source . \
  --region YOUR_REGION \
  --set-env-vars "PROJECT_ID=YOUR_PROJECT,CLIENT_ID=YOUR_CLIENT_ID,REDIRECT_URI=https://YOUR_SERVICE_URL/auth/callback" \
  --set-secrets "TOKEN_SERVICE_SECRET=token-service-secret:latest"
```

Verify the broker is up:

```bash
curl https://YOUR_SERVICE_URL/health
# {"status":"ok"}
```

### Agent (ADK example)

Copy `agent/auth_utils.py` into your agent package and set these environment variables:

```bash
agents-cli deploy ... \
  --update-env-vars "AUTH_SERVICE_URL=https://YOUR_SERVICE_URL,SCRIPT_ID=AKfy...YOUR_DEPLOYMENT_ID" \
  --update-secrets "TOKEN_SERVICE_SECRET=token-service-secret:latest"
```

## Usage

The broker is framework-agnostic — any code that can make an HTTP request can call `/token`. The `agent/` directory is an ADK + Apps Script example; adapt it to your framework.

**Minimal usage (any framework):**

```python
import httpx

async def get_workspace_token(user_email: str) -> str | None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{AUTH_SERVICE_URL}/token",
            params={"email": user_email},
            headers={"Authorization": f"Bearer {TOKEN_SERVICE_SECRET}"},
        )
    data = resp.json()
    if data.get("status") == "auth_required":
        return None  # send user to AUTH_SERVICE_URL/auth
    return data.get("access_token")
```

**ADK tool function example:**

`get_access_token` is async — call it from an `async def` tool:

```python
from .auth_utils import get_access_token, scripts_run, AUTH_URL

async def setup_client_workspace(client_name: str, project_type: str, tool_context) -> dict:
    user_email = tool_context.user_id
    access_token = await get_access_token(user_email)
    if not access_token:
        return {"status": "auth_required", "url": AUTH_URL}

    result = scripts_run(access_token, "api_setup_client_workspace", {
        "clientName": client_name,
        "projectType": project_type,
    })
    if result.get("error"):
        return {"status": "error", "detail": result["error"]}
    return result.get("response", {}).get("result", {})
```

`get_access_token` returns a standard Bearer token usable with any Google API. `scripts_run` is the Apps Script example — pass the token to `google.oauth2.credentials.Credentials(token=access_token)` to build any other service client.

## Security notes

**Blast radius of `TOKEN_SERVICE_SECRET`:** This secret authenticates every `/token` call. A leaked value gives the holder access to every stored user refresh token — Drive, Gmail, Calendar, and Docs for every user who has completed the consent flow. Treat it like a root credential: rotate immediately if exposed, redeploy the broker, and audit Secret Manager access logs.

**Refresh token lifecycle:**
- If a user revokes access via [myaccount.google.com/permissions](https://myaccount.google.com/permissions), the next `/token` call returns `{"status": "auth_required"}` — the broker detects `invalid_grant` and signals re-auth automatically. Your tool only needs to handle the `auth_required` response.
- Existing tokens do not gain new scopes if you expand `SCOPES`. Users must re-authorise via `/auth` to get an updated token.
- Secret Manager versions accumulate on every re-authorisation. Set a destroy policy to keep history bounded:

```bash
gcloud secrets update workspace-token-YOUR-USER-AT-EXAMPLE-COM \
  --versions-destroy-ttl=86400s \
  --project=YOUR_PROJECT
```

Or set the policy when creating each secret by adding `"version_destroy_ttl": {"seconds": 86400}` to the `create_secret` call.

**Client secret rotation:** `_get_client_secret()` is cached for the lifetime of each instance. After rotating the OAuth client secret in Secret Manager, redeploy the broker to pick up the new value:

```bash
gcloud run services update YOUR_SERVICE --region YOUR_REGION
```

**Scope minimisation:** Remove every scope from `SCOPES` that your Apps Script function does not call. The default list is annotated — trim it to reduce the consent screen footprint and blast radius.

## Testing

**ADK / Agent Builder playground:** `tool_context.user_id` resolves to a system identity, not a user email. Add a guard for local testing and remove it before any shared deployment:

```python
DEV_EMAIL = os.environ.get("DEV_EMAIL", "")

def my_tool(tool_context):
    user_email = tool_context.user_id
    if user_email == "vais-query-reasoning-engine":
        user_email = DEV_EMAIL  # REMOVE before production
    ...
```

**Other frameworks:** Pass the user's email directly — no framework-specific identity resolution needed. Ensure your user has completed the `/auth` consent flow first.

## Known limitations

- **No rate limiting on `/token`:** Each call hits Secret Manager and Google's token endpoint. A misconfigured agent in a retry loop will exhaust quota. Add retry backoff in your agent code and consider caching the access token for its 1-hour lifetime on the client side.
- **Single-instance token cache:** `_get_client_secret()` is cached per Cloud Run instance. In a multi-instance deployment, each instance fetches the secret independently on first call.
