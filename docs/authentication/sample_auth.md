```python:auth.py
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
from handlers.auth_api import jwt_min_expiry_seconds


"""
OAuth 2.0 Integration for MCP (Model Context Protocol)

This implementation follows the OAuth 2.0 Authorization Framework (RFC 6749) and provides
a bridge between MCP clients and identity providers. The flow involves three parties:

1. MCP Client (e.g., Cursor) - requests access to protected resources
2. Your-Server - acts as both authorization server and resource server
3. IDP Provider - performs actual user authentication

Key OAuth Flow:
- MCP Client initiates OAuth flow with your-server
- Your-server redirects to IDP provider for authentication
- IDP provider redirects back to your-server with authorization code
- Your-server redirects to MCP client with authorization code
- MCP client exchanges code for access token from your-server
- Your-server validates code with IDP provider and issues its own token
"""


mcp_auth_router = APIRouter(prefix="/auth-mcp")
mcp_discovery_router = APIRouter()


@mcp_discovery_router.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata() -> Dict[str, Any]:
    """
    OAuth 2.0 Authorization Server Metadata (RFC 8414)
    Provides discovery information about the authorization server's endpoints and capabilities
    """
    base_url = config.get_string(
        "YOUR_SERVER_HOST", "https://your-server.example.com"
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
    base_url = config.get_string(
        "YOUR_SERVER_HOST", "https://your-server.example.com"
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

    Security Features:
    - CSRF protection via state parameter
    - PKCE support for public clients (RFC 7636)
    - Parameter validation per OAuth 2.0 spec
    """
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

        # Store OAuth state parameters for callback validation (prevents CSRF)
        redis_key_state = f"oauth_state:{state}"
        redis_key_redirect = f"oauth_redirect:{state}"  # original MCP client redirect uri
        redis_key_client = f"oauth_client:{state}"

        # TTL of 5 minutes for security (OAuth flows should complete quickly)
        redis_client.set(redis_key_state, state, ex=300)
        redis_client.set(redis_key_redirect, redirect_uri, ex=300)
        redis_client.set(redis_key_client, client_id, ex=300)

        base_url = config.get_string(
            "YOUR_SERVER_HOST", "https://your-server.example.com"
        )
        your_server_redirect_uri = f"{base_url}/auth-mcp/oauth/callback"

        # Build IDP provider OAuth authorization URL
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
        raise HTTPException(status_code=500, detail="server_error")


@mcp_auth_router.get("/oauth/callback")
async def oauth_callback_for_mcp(
    code: str, state: str, request: Request
) -> RedirectResponse:
    """
    OAuth 2.0 Authorization Response Handler (RFC 6749 Section 4.1.2)

    Intermediate callback that receives authorization code from IDP provider
    and redirects back to the original MCP client. This pattern is necessary
    because IDP providers need consistent redirect URIs while MCP clients
    have dynamic, tool-specific redirect URIs.
    """
    try:
        # Validate state parameter to prevent CSRF attacks
        redis_key_state = f"oauth_state:{state}"
        redis_key_redirect = f"oauth_redirect:{state}"
        redis_key_client = f"oauth_client:{state}"

        stored_state = redis_client.get(redis_key_state)
        original_redirect_uri = redis_client.get(redis_key_redirect)
        client_id = redis_client.get(redis_key_client)

        # Clean up Redis state immediately (security best practice)
        redis_client.connection().delete(redis_key_state)
        redis_client.connection().delete(redis_key_redirect)
        redis_client.connection().delete(redis_key_client)

        # Validate state parameter integrity
        if (
            not all([stored_state, original_redirect_uri, client_id])
            or stored_state != state
        ):
            raise HTTPException(status_code=400, detail="Invalid state")

        # Redirect back to original MCP client with authorization code
        callback_url = f"{original_redirect_uri}?code={code}&state={state}"

        return RedirectResponse(url=callback_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail="callback_error")


@mcp_auth_router.post("/token")
async def oauth_token_endpoint(request: Request) -> Dict[str, Any]:
    """
    OAuth 2.0 Token Endpoint (RFC 6749 Section 3.2)

    Exchanges authorization code for access token. This endpoint:
    1. Validates the authorization code with the IDP provider
    2. Retrieves user information from IDP provider
    3. Generates a your-server access token for the MCP client
    4. Returns standard OAuth 2.0 token response
    """
    try:
        body = await request.form()

        # Validate grant type (RFC 6749 Section 4.1.3)
        grant_type = body.get("grant_type")
        if grant_type not in ["authorization_code"]:
            raise HTTPException(status_code=400, detail="unsupported_grant_type")

        # Extract required parameters for authorization code grant
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")  # MCP client's redirect URI
        client_id = body.get("client_id")
        code_verifier = body.get("code_verifier")  # PKCE code verifier

        if grant_type == "authorization_code":
            if not all([code, redirect_uri, client_id]):
                raise HTTPException(status_code=400, detail="invalid_request")

        base_url = config.get_string(
            "YOUR_SERVER_HOST", "https://your-server.example.com"
        )
        internal_redirect_uri = f"{base_url}/auth-mcp/oauth/callback"

        # Exchange authorization code with IDP provider
        issuer = _get_issuer("idp_provider")
        auth_response = issuer.authorize(
            code=code,
            redirect_uri=internal_redirect_uri,
            code_challenge=code_verifier,
        )

        # Validate successful authentication
        if not auth_response.email:
            raise HTTPException(status_code=400, detail="invalid_grant")

        # Generate your-server access token
        expire_in_seconds = auth_response.expires_in_seconds or jwt_min_expiry_seconds
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expire_in_seconds)

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

        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail="invalid_grant")
```

Now here are the key supporting functions that make this OAuth implementation work:

```python:jwt_token_generation.py
# Sample JWT Token Generation Function
# This shows how your-server creates its own access tokens after validating with IDP provider

from datetime import datetime
from typing import Dict, Any
from core.auth.token import Tokenizer
from service import user_service
from middlewares.database_session_middleware import get_session

def _generate_jwt_token(
    email: str,
    issuer: str,
    issuer_access_token: str,
    issuer_refresh_token: str | None = None,
    expire_date: datetime | None = None,
) -> str:
    """
    Generates a JWT token for your-server after successful IDP provider authentication

    Args:
        email: User email from IDP provider
        issuer: Identity provider name (e.g., "idp_provider")
        issuer_access_token: Access token from IDP provider
        issuer_refresh_token: Refresh token from IDP provider (if available)
        expire_date: Token expiration date

    Returns:
        JWT token string for your-server API access
    """
    # Get or create user in your-server's database
    user_db = user_service.get_or_create_user(email)
    get_session().refresh(user_db)

    # Build user roles/permissions from database
    roles = {}
    if user_db.user_tenants is not None:
        for assoc in user_db.user_tenants:
            roles[assoc.tenant.id] = assoc.role

    # Create user context for JWT payload
    user_ctx = UserContext(
        user_id=user_db.id,
        name=user_db.name,
        roles=roles,
        iss=issuer,
        access_token=issuer_access_token,
        refresh_token=issuer_refresh_token,
        sub=f"{user_db.id}",
        email=user_db.name,
        account_type=user_db.account_type,
    )

    # Generate and return JWT token
    tokenizer = Tokenizer(config.get_string("JWT_SECRET"))
    return tokenizer.encode(user_ctx.model_dump(), expire_date)
```

```python:auth_provider_interface.py
# Sample IDP Provider Interface
# This shows how your-server communicates with identity providers

from abc import ABC, abstractmethod
from dataclasses import dataclass
import requests
import json

@dataclass
class AuthResponse:
    """Response from IDP provider after successful authentication"""
    email: str
    access_token: str
    refresh_token: str
    expires_in_seconds: int
    original_response: dict


class AuthIssuer(ABC):
    """Interface for different identity providers"""

    @abstractmethod
    def authorize(self, **kwargs) -> AuthResponse:
        """Exchange authorization code for user information"""
        pass

    @abstractmethod
    def refresh_token(self, **kwargs) -> AuthResponse:
        """Refresh an expired access token"""
        pass


class IDPProviderAuth(AuthIssuer):
    """Sample implementation for a generic IDP provider"""

    def authorize(self, **kwargs) -> AuthResponse:
        """
        Exchange authorization code with IDP provider

        Args:
            code: Authorization code from OAuth flow
            redirect_uri: Redirect URI used in authorization
            code_challenge: PKCE code verifier for security

        Returns:
            AuthResponse with user information and tokens
        """
        code = kwargs["code"]
        code_challenge = kwargs["code_challenge"]
        redirect_uri = kwargs["redirect_uri"]

        # Get IDP provider configuration
        oidc_host = config.get_string("YOUR_SERVER_OIDC_HOST")
        oidc_audience = config.get_string("YOUR_SERVER_OIDC_AUDIENCE")

        # Exchange code for tokens with IDP provider
        params = {
            "code": code,
            "client_id": oidc_audience,
            "grant_type": "authorization_code",
            "code_verifier": code_challenge,
            "redirect_uri": redirect_uri,
        }

        response = requests.post(f"{oidc_host}/token", data=params)
        resp_json = json.loads(response.content.decode())

        # Validate and decode ID token from IDP provider
        id_token = resp_json["id_token"]
        tokenizer = Tokenizer(config.get_string("JWT_SECRET"))
        id_token_dict = tokenizer.decode_jwks(
            f"{oidc_host}/keys", id_token, oidc_audience
        )

        # Extract user information
        email = id_token_dict["email"]
        access_token = resp_json["access_token"]
        expires_in = resp_json["expires_in"]

        return AuthResponse(
            email=email,
            access_token=access_token,
            expires_in_seconds=expires_in,
            original_response=resp_json,
            refresh_token=None,
        )
```

```python:request_authorization_middleware.py
# Sample Request Authorization Middleware
# This shows how your-server validates tokens in incoming requests

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import HTTPException
from core.auth.token import Tokenizer

class UserAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that validates JWT tokens on incoming requests"""

    def __init__(self, app, dispatch=None):
        super().__init__(app, dispatch)
        self._tokenizer = Tokenizer(config.get_string("JWT_SECRET"))

    async def dispatch(self, request, call_next):
        """
        Validates authorization for incoming requests

        MCP routes require valid bearer tokens
        Other routes may be optional depending on configuration
        """

        # Skip auth for OAuth discovery endpoints
        if request.url.path in [
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            "/auth-mcp/",
        ]:
            response = await call_next(request)
            return response

        # Get authorization header (supports both formats)
        authorization = request.headers.get("x-authorization") or request.headers.get("authorization")

        # Enforce authentication for MCP API routes
        if request.url.path.startswith("/mcp"):
            try:
                headers = {"WWW-Authenticate": f"Bearer resource_metadata={request.url}"}

                if not authorization or not self.validate_token(authorization):
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Unauthorized"},
                        headers=headers,
                    )

            except Exception as e:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized"},
                    headers=headers
                )

        # Validate token and set user context if present
        if authorization:
            try:
                user_ctx = self.validate_token(authorization)

                # Auto-select tenant for MCP requests
                if request.url.path.startswith("/mcp") and user_ctx.roles:
                    tenant_ids = sorted(user_ctx.roles.keys())
                    # Use first available tenant or specific default
                    user_ctx.current_tenant_id = tenant_ids[0]

                # Set user context for request processing
                set_user_context(user_ctx)

            except Exception as e:
                # Log validation error but continue for non-MCP routes
                pass

        response = await call_next(request)
        return response

    def validate_token(self, auth_header: str) -> UserContext | None:
        """
        Validates JWT token and returns user context

        Args:
            auth_header: Authorization header value (e.g., "Bearer token123")

        Returns:
            UserContext object with user information and permissions

        Raises:
            Exception if token is invalid or expired
        """
        jwt_token = auth_header.replace("Bearer ", "")
        token_payload = self._tokenizer.decode(jwt_token)
        return UserContext.parse_obj(token_payload)
```
