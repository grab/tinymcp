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
