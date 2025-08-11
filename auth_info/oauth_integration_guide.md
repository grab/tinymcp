# OAuth Integration Guide for Tiny MCP

This guide shows how to implement OAuth 2.1 PKCE authentication for Tiny MCP that works with FastAPI Server's existing IdP (Identity Provider) OIDC integration. This authentication mechanism is independent of TinyMCP. The main thing to note from the TinyMCP mcp router are: the specific MCP routes and some specific endpoints for OAuth discovery, registration and overall authentication process.

## Overview

This implementation enables MCP clients (like Cursor) to authenticate using OAuth 2.1 PKCE via FastAPI Server's existing OAuth integration with IdPs.

**Key Components:**
1. **Resource Discovery** - OAuth protected resource metadata
2. **Authorization Server Discovery** - OAuth 2.1 server metadata
3. **Dynamic Client Registration** - Ephemeral client registration in Redis
4. **PKCE Authorization Flow** - With intermediate redirect handling
5. **Token Exchange** - Proxy to IdP for token validation

## OAuth Flow Diagram

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│ MCP Client  │    │    FastAPI   │    │      IdP        │
│ (Cursor)    │    │    Server    │    │                 │
└──────┬──────┘    └──────┬───────┘    └─────────┬───────┘
       │                  │                      │
   1.  │ GET /mcp         │                      │
       ├─────────────────►│ 401 + Discovery      │
       │                  │                      │
   2.  │ /.well-known/*   │                      │
       ├─────────────────►│ Resource & Server    │
       │                  │ Discovery            │
   3.  │ POST /register   │                      │
       ├─────────────────►│ Ephemeral client     │
       │                  │ (Redis TTL)          │
   4.  │ /authorize+PKCE  │                      │
       ├─────────────────►├─────────────────────►│
       │                  │ Intermediate redirect│
   5.  │                  │◄─────────────────────┤
       │ Relay to client  │ Code to /callback    │
       │◄─────────────────┤                      │
       │                  │                      │
   6.  │ POST /token      │                      │
       ├─────────────────►├─────────────────────►│
       │                  │ Code + verifier      │
   7.  │ JWT Token        │◄─────────────────────┤
       │◄─────────────────┤                      │
       │                  │                      │
   8.  │ /mcp + Bearer    │                      │
       ├─────────────────►│ Validate & Forward   │
       │                  │                      │
```

## End-to-End OAuth Sequence

### 1. Tool Access Attempt
The MCP client sends a request to a protected resource at the designated router (e.g., `/mcp`) in FastAPI Server.

FastAPI Server's authentication middleware intercepts the unauthenticated request and responds with:
- **HTTP 401 Unauthorized**
- **WWW-Authenticate header** with metadata discovery location (`resource_metadata`)

This triggers OAuth discovery on the MCP Client's side.

### 2. Resource Discovery
The MCP client discovers FastAPI Server as resource server via:
```
/.well-known/oauth-protected-resource
```

This endpoint advertises FastAPI Server as the resource server for protected MCP endpoints.

### 3. OAuth Server Discovery
The MCP client follows the discovery pattern and calls:
```
/.well-known/oauth-authorization-server
```

The response includes key metadata (e.g.,):
- `authorization_endpoint`: `/auth-mcp/authorize`
- `token_endpoint`: `/auth-mcp/token`
- `registration_endpoint`: `/auth-mcp/register`

### 4. Dynamic Client Registration
MCP client registers with FastAPI Server via:
```
POST /auth-mcp/register
```

- Provides its `redirect_uri` (e.g., `cursor://auth/callback`)
- Receives ephemeral `client_id` (and `client_secret` if required)

### 5. Authorization Request with PKCE
The client calls `/auth-mcp/authorize` some info for the auth to continue. These includes:
- `code_challenge` (MCP client generates this, which is a hash of a unique `code_verifier` string stored at the client side. MCP client sends back this `code_verifier` when calling `/token`)
- `code_challenge_method`
- `redirect_uri` (its own callback endpoint, specific to the client/tool, e.g., cursor url for specific mcp tool)

### 6. FastAPI Server Authorization Server Actions
On receiving this request, FastAPI Server:
1. **Creates a unique string** for state persistence throughout the request cycle
2. **Stores the redirect_uri** (e.g., cursor mcp tool url) and state in Redis (temporary state store)
3. **Defines an intermediate redirect URI** within the FastAPI Server server (e.g., `/auth-mcp/oauth/callback`) to receive the code from IdP
4. **Constructs a new authorization request** and redirects the user to the IDP (IdP) using this intermediate callback URI

### 7. IDP Code Response to Intermediate Callback
IdP completes user authentication and returns the authorization code by redirecting the browser to the intermediate callback URI:
```
/auth-mcp/oauth/callback
```
⚠️ **This intermediate redirect is necessary** because IdP can't dynamically redirect to each unique MCP client's URI, which varies by client/tool. This callback endpoint at the FastAPI Server acts as a relay.

FastAPI Server server then:
1. **Retrieves the original redirect_uri** from Redis
2. **Redirects the client** to its original redirect URI (e.g. cursor mcp tool url), appending the received code and state in the query param


### 8. Token Exchange
The MCP client then calls:
```
POST /auth-mcp/token
```

Including the code and the original `code_verifier`

FastAPI Server:
- **Exchanges the code + code_verifier** with IdP for a valid `access_token` (JWT). This endpoint acts as a proxy, calling IdP's `/token` endpoint internally
- **The access token is returned** to the MCP client

### 9. Authenticated Resource Access
The client caches the token (e.g., in local storage) and uses it in a Bearer token header to call:
```
/mcp... endpoints (i.e., tool APIs)
```

The middleware validates the token and forwards the request to the FastAPI's MCP router for tool calling.

## Endpoint Responsibilities Summary

| Endpoint | Purpose |
|----------|---------|
| `/mcp` | MCP endpoints that require authentication |
| `/.well-known/oauth-protected-resource` | Resource server discovery endpoint, advertising FastAPI Server as the resource server for protected MCP endpoints |
| `/.well-known/oauth-authorization-server` | OAuth 2.1 metadata (authorization/token/register URLs) |
| `/auth-mcp/register` | Dynamic client registration endpoint, allowing MCP clients to register their unique redirect_uris and receive ephemeral client_id and client_secret |
| `/auth-mcp/authorize` | Handles PKCE initiation, stores state and redirect_uri, redirects to IDP |
| `/auth-mcp/oauth/callback` | Intermediary to receive auth code from IDP, re-redirects to client |
| `/auth-mcp/token` | Accepts code + code_verifier, exchanges for token via IDP. Acts as a proxy, calling IdP's /token endpoint internally |


## Technical Gotchas and Solutions

### 1. HTTPS Protocol Loss
**Problem**: Load balancers may drop X-Forwarded-Proto headers during internal redirects, causing HTTPS URLs to become HTTP.

**Solution**:
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# ProxyHeadersMiddleware with trusted hosts
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
```

### 2. State Management
**Problem**: OAuth state needs to be maintained across redirects.

**Solution**: Redis-based state storage with TTL:
```python
redis_client.setex(f"oauth_state:{state}", 600, json.dumps(state_data))
redis_client.setex(f"oauth_redirect:{state}", 600, redirect_uri)
```

### 3. Intermediate Redirect URI Handling
**Problem**: IdP (IDP) is not aware of the per-mcp tool redirect URIs used by various MCP clients and tools. Redirecting directly from the IDP to the MCP client hence is not workable.

**Solution**: This is addressed by using an internal intermediate redirect URI (`/auth-mcp/oauth/callback`) within FastAPI Server. This endpoint:
- Acts as a relay that can receive the auth code from IdP
- Uses the stored state to retrieve the original client-specific redirect_uri from Redis
- Then performs a second redirect to the actual MCP client URI with the correct code and state

This approach prevents IdP from needing to know or whitelist every client callback URI while maintaining the desired OAuth flow.

## Integration with Tiny MCP

Once OAuth is implemented, your Tiny MCP tools can access user context:

```python
from tiny_mcp import mcp_tool
from fastapi import Request

@mcp_tool(description="Get user-specific data")
async def get_user_data(request: Request) -> dict:
    """Get data specific to the authenticated user"""
    # Access authenticated user (set by auth middleware)
    user = request.state.user

    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
        "message": f"Hello {user['name']}!"
    }

# Create MCP router with custom prefix if needed
mcp_router = create_mcp_router(
    name="SpellVault MCP",
    version="0.1.0",
    prefix="/mcp"  # Configurable endpoint
)

# Add all routers to FastAPI
app.include_router(discovery_router)
app.include_router(auth_router)
app.include_router(mcp_router)
```

This implementation provides a complete, production-ready OAuth 2.1 PKCE integration for Tiny MCP that works seamlessly with FastAPI Server's existing IdP OIDC infrastructure!



## Sample Implementation of various endpoints and functions for Integration with existing OAuth

```python
import secrets
import time
import base64
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict
from uuid import uuid4

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
)
from fastapi.responses import RedirectResponse

import config
from ext.redis_ext import redis_client
from handlers.auth_api import (
    _generate_jwt_token,
    _get_issuer,
)
from logger import Logger
from handlers.auth_api import jwt_min_expiry_seconds


tag = "your_server_mcp.auth"
LOG = Logger(tag)

"""
The flow involves three parties:
1. MCP Client (e.g., Cursor) - requests access to protected resources
2. Your-Server - acts as both authorization server and resource server
3. IDP Provider - performs actual user authentication

OAuth Flow Architecture:
- MCP Client initiates OAuth flow with your-server
- Your-server redirects to IDP provider for authentication
- IDP provider redirects back to your-server with authorization code
- Your-server redirects to MCP client with authorization code
- MCP client exchanges code for access token from your-server
- Your-server validates code with IDP provider and issues its own token
"""


mcp_auth_router = APIRouter(prefix="/auth-mcp")


mcp_discovery_router = APIRouter()
logger = Logger(tag)


@mcp_discovery_router.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata() -> Dict[str, Any]:
    """
    OAuth 2.0 Authorization Server Metadata (RFC 8414)
    Provides discovery information about the authorization server's endpoints and capabilities
    """
    base_url = config.get_string(
        "YOUR_SERVER_HOST", "https://your-server-gt.stg.mngd.int.engtools.net"
    )

    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth-mcp/authorize",
        "token_endpoint": f"{base_url}/auth-mcp/token",
        "registration_endpoint": f"{base_url}/auth-mcp/register",
        "resource": f"{base_url}/mcp",
        "scopes_supported": ["user", "openid", "email", "mcp:access"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }


@mcp_discovery_router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource() -> Dict[str, Any]:
    """
    OAuth 2.0 Protected Resource Metadata (RFC 8414)
    Describes the protected resource and its authorization requirements
    """
    FN_TAG = f"{tag}.oauth_protected_resource"
    LOG.debug(FN_TAG, "OAuth 2.0 Protected Resource")

    base_url = config.get_string(
        "YOUR_SERVER_HOST", "https://your-server-gt.stg.mngd.int.engtools.net"
    )

    return {
        "resource": f"{base_url}/mcp",
        "authorization_servers": [f"{base_url}"],
        "scopes_supported": ["user", "openid", "email", "mcp:access"],
        "bearer_methods_supported": ["header"],
    }


@mcp_auth_router.post("/register")
async def oauth_client_registration(request: Request) -> Dict[str, Any]:
    """
    OAuth 2.0 Dynamic Client Registration (RFC 7591)
    Allows clients to register dynamically and obtain client credentials
    """

    FN_TAG = f"{tag}.oauth_client_registration"
    LOG.debug(FN_TAG, "OAuth 2.0 Dynamic Client Registration")

    try:
        body = await request.json()

        # Validate required parameters per RFC 7591
        if "redirect_uris" not in body or not body["redirect_uris"]:
            raise HTTPException(status_code=400, detail="redirect_uris required")

        # Generate client credentials
        client_id = str(uuid4())
        client_secret = secrets.token_hex(32)

        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": body.get("redirect_uris"),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "user openid email",
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@mcp_auth_router.get("/authorize")
def oauth_authorize_endpoint(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = None,
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None,
    code_verifier: str = None,
    resource: str = None,
) -> RedirectResponse:
    """
    OAuth 2.0 Authorization Endpoint (RFC 6749 Section 3.1)
    Handles authorization requests from MCP clients by redirecting to IDP provider

    Flow:
    1. Validate OAuth parameters per RFC 6749
    2. Generate/validate PKCE parameters per RFC 7636
    3. Store state for CSRF protection per RFC 6749 Section 10.12
    4. Redirect to IDP provider's authorization endpoint
    """
    FN_TAG = f"{tag}.oauth_authorize_endpoint"
    LOG.debug(FN_TAG, f"Request: {request}")
    try:
        # Validate OAuth 2.0 parameters
        if response_type != "code":
            raise HTTPException(status_code=400, detail="unsupported_response_type")

        # CSRF protection: Generate state parameter if not provided
        if not state:
            state = secrets.token_urlsafe(32)

        # Set default OpenID Connect scopes
        if not scope:
            scope = "openid email user"

        # Get IDP provider configuration
        idp_provider_url = config.get_string("YOUR_SERVER_OIDC_HOST")
        idp_provider_client_id = config.get_string("YOUR_SERVER_OIDC_AUDIENCE")

        if not idp_provider_url or not idp_provider_client_id:
            raise HTTPException(status_code=500, detail="OAuth configuration missing")

        # Store OAuth state parameters in Redis for callback validation
        # This prevents CSRF attacks and ensures callback integrity
        redis_key_state = f"oauth_state:{state}"
        redis_key_redirect = (
            f"oauth_redirect:{state}"  # store the original MCP client redirect uri
        )
        redis_key_client = f"oauth_client:{state}"

        # TTL of 5 minutes for security (OAuth flows should complete quickly)
        redis_client.set(redis_key_state, state, ex=300)
        redis_client.set(redis_key_redirect, redirect_uri, ex=300)
        redis_client.set(redis_key_client, client_id, ex=300)

        base_url = config.get_string(
            "YOUR_SERVER_HOST", "https://your-server-gt.stg.mngd.int.engtools.net"
        )
        your_server_redirect_uri = f"{base_url}/auth-mcp/oauth/callback"

        # Build IDP provider OAuth authorization URL
        # This redirects user to the actual identity provider for authentication
        oauth_params = {
            "client_id": idp_provider_client_id,
            "scope": "openid email",
            "state": state,
            "response_type": "code",
            "redirect_uri": your_server_redirect_uri,  # Our intermediate callback
            "code_challenge_method": code_challenge_method or "S256",
            "code_challenge": code_challenge,  # PKCE parameter from MCP client
            "resource": resource,
        }

        param_str = "&".join([f"{k}={v}" for k, v in oauth_params.items()])
        oauth_url = f"{idp_provider_url}/auth?{param_str}"

        return RedirectResponse(url=oauth_url)

    except Exception as e:
        LOG.exception("oauth_authorize_endpoint", f"Authorization failed: {str(e)}")
        raise HTTPException(status_code=500, detail="server_error")


@mcp_auth_router.get("/oauth/callback")
async def oauth_callback_for_mcp(
    code: str, state: str, request: Request
) -> RedirectResponse:
    """
    OAuth 2.0 Authorization Response Handler (RFC 6749 Section 4.1.2)
    Intermediate callback that receives authorization code from IDP provider
    and redirects back to the original MCP client

    This intermediate step is necessary because:
    1. IDP provider needs a single, consistent redirect URI
    2. MCP clients have dynamic, tool-specific redirect URIs
    3. Allows your-server to maintain control over the OAuth flow
    """
    FN_TAG = f"{tag}.oauth_callback_for_mcp"
    try:
        # Validate state parameter to prevent CSRF attacks (RFC 6749 Section 10.12)
        redis_key_state = f"oauth_state:{state}"
        redis_key_redirect = f"oauth_redirect:{state}"
        redis_key_client = f"oauth_client:{state}"

        stored_state = redis_client.get(redis_key_state)
        original_redirect_uri = redis_client.get(redis_key_redirect)
        client_id = redis_client.get(redis_key_client)

        # Clean up Redis state immediately after use (security best practice)
        redis_client.connection().delete(redis_key_state)
        redis_client.connection().delete(redis_key_redirect)
        redis_client.connection().delete(redis_key_client)

        LOG.debug(FN_TAG, f"stored_state: {stored_state}")
        LOG.debug(FN_TAG, f"original_redirect_uri: {original_redirect_uri}")
        LOG.debug(FN_TAG, f"client_id: {client_id}")

        # Validate state parameter integrity
        if (
            not all([stored_state, original_redirect_uri, client_id])
            or stored_state != state
        ):
            raise HTTPException(status_code=400, detail="Invalid state")

        # Redirect back to original MCP client with authorization code
        # The MCP client will use this code to request an access token
        callback_url = f"{original_redirect_uri}?code={code}&state={state}"

        return RedirectResponse(url=callback_url)
    except Exception as e:
        LOG.exception(FN_TAG, f"Callback failed: {str(e)}", e)
        raise HTTPException(status_code=400, detail="callback_error")


@mcp_auth_router.post("/token")
async def oauth_token_endpoint(request: Request) -> Dict[str, Any]:
    """
    OAuth 2.0 Token Endpoint (RFC 6749 Section 3.2)
    Exchanges authorization code for access token using authorization code grant

    Flow:
    1. Validate token request parameters per RFC 6749
    2. Exchange authorization code with IDP provider
    3. Validate user authentication from IDP provider
    4. Generate your-server access token for MCP client
    5. Return token response per RFC 6749 Section 5.1
    """
    FN_TAG = f"{tag}.oauth_token_endpoint"
    try:
        body = await request.form()
        LOG.debug(FN_TAG, f"Body: {body}")

        # Validate grant type (RFC 6749 Section 4.1.3)
        grant_type = body.get("grant_type")
        if grant_type not in ["authorization_code"]:
            raise HTTPException(status_code=400, detail="unsupported_grant_type")

        # Extract required parameters for authorization code grant
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")  # MCP client's redirect URI
        client_id = body.get("client_id")
        code_verifier = body.get(
            "code_verifier"
        )  # PKCE code verifier from MCP client (RFC 7636)

        if grant_type == "authorization_code":
            if not all([code, redirect_uri, client_id]):
                raise HTTPException(status_code=400, detail="invalid_request")

        base_url = config.get_string(
            "YOUR_SERVER_HOST", "https://your-server-gt.stg.mngd.int.engtools.net"
        )
        internal_redirect_uri = f"{base_url}/auth-mcp/oauth/callback"

        # Exchange authorization code with IDP provider
        # This validates the code and retrieves user information
        issuer = _get_issuer("idp_provider")
        auth_response = issuer.authorize(
            code=code,
            redirect_uri=internal_redirect_uri,
            code_verifier=code_verifier,
        )

        # Validate successful authentication from IDP provider
        if not auth_response.email:
            raise HTTPException(status_code=400, detail="invalid_grant")

        # Generate your-server access token with appropriate expiration
        expire_in_seconds = auth_response.expires_in_seconds or jwt_min_expiry_seconds
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expire_in_seconds)

        # Create JWT token for your-server API access
        access_token = _generate_jwt_token(
            auth_response.email,
            "idp_provider",
            auth_response.access_token,
            auth_response.refresh_token,
            expire_date=expires_at,
        )

        # Return OAuth 2.0 token response (RFC 6749 Section 5.1)
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expire_in_seconds,
            "scope": "user openid email",
            "refresh_token": access_token,
        }

        # Development logging: Log token details for debugging
        # WARNING: Only enable in development environments
        try:
            header_b64, payload_b64, _ = access_token.split(".")
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode())
            LOG.info(
                FN_TAG,
                f"Issued your-server token (HS256 expected): alg={header.get('alg')}, sub={payload.get('sub')}, user_id={payload.get('user_id')}, email={payload.get('email')}, exp={payload.get('exp')}",
            )
            LOG.info(FN_TAG, f"MCP access_token (full): {access_token}")
        except Exception:
            LOG.info(FN_TAG, "Issued your-server token")
        LOG.debug(FN_TAG, f"Response: {response}")
        return response
    except Exception as e:
        LOG.exception("oauth_token_endpoint", f"Token exchange failed: {str(e)}", e)
        raise HTTPException(status_code=400, detail="invalid_grant")
```
