"""Cred AutoGen integration.

Returns FunctionTools that AutoGen agents can call for delegated OAuth access.
The tool schema matches the Cred MCP tool spec:

    name:   cred_delegate
    params: { service: str, scopes: list[str] }

user_id and app_client_id are pre-configured at factory time and are not
agent-controlled inputs.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Optional

from autogen_core.tools import FunctionTool

from cred import Cred


def cred_delegate_tool(
    agent_token: str,
    user_id: str,
    app_client_id: str,
    base_url: str,
    token_format: str = "raw",
) -> FunctionTool:
    """Create an AutoGen FunctionTool for credential delegation.

    The returned tool is pre-configured with the user's identity and app context.
    At runtime, the agent supplies ``service`` and ``scopes``.

    Args:
        agent_token:    Agent token issued by Cred (starts with ``cred_at_``).
        user_id:        The user whose credentials to delegate.
        app_client_id:  The Cred app client ID to delegate for.
        base_url:       Override the API base URL.

    Returns:
        A ``FunctionTool`` ready to use with AutoGen agents.

    Raises:
        ConsentRequiredError: (from the tool at runtime) when the user hasn't
            connected the requested service. The error message includes
            ``consent_url`` so the caller can redirect the user.

    Example::

        from cred_autogen import cred_delegate_tool

        tool = cred_delegate_tool(
            agent_token=os.environ["CRED_AGENT_TOKEN"],
            user_id="user_123",
            app_client_id="my_app",
        )
        # Register with an AutoGen agent
    """
    if token_format not in {"raw", "handle"}:
        raise ValueError("token_format must be 'raw' or 'handle'")

    cred = Cred(agent_token=agent_token, base_url=base_url)

    def delegate(
        service: Annotated[str, "Service slug to get a token for (e.g. 'google', 'github', 'google-calendar')."],
        scopes: Annotated[list[str], "OAuth scopes to request (e.g. ['calendar.readonly']). Pass an empty list to use all consented scopes."],
    ) -> str:
        """Get a delegated OAuth access token for a third-party service on behalf of the current user.

        Returns JSON with access_token, token_type, expires_in, service, scopes,
        and delegation_id. Raises an error with consent_url if the user hasn't
        connected the service.
        """
        resolved_scopes: Optional[list[str]] = scopes if scopes else None

        if token_format == "handle":
            result = cred.delegate_handle(
                service=service,
                user_id=user_id,
                app_client_id=app_client_id,
                scopes=resolved_scopes,
            )
            return json.dumps({
                "token_type": result.token_type,
                "expires_in": result.expires_in,
                "service": result.service,
                "user_id": result.user_id,
                "scopes": result.scopes,
                "delegation_id": result.delegation_id,
                "note": "Pass delegation_id to cred_use to make authenticated API calls.",
            })

        result = cred.delegate(
            service=service,
            user_id=user_id,
            app_client_id=app_client_id,
            scopes=resolved_scopes,
        )
        return json.dumps({
            "access_token": result.access_token,
            "token_type": result.token_type,
            "expires_in": result.expires_in,
            "service": result.service,
            "scopes": result.scopes,
            "delegation_id": result.delegation_id,
        })

    description = (
        ("Get a brokered OAuth delegation handle for a third-party service "
         if token_format == "handle"
         else "Get a delegated OAuth access token for a third-party service ") +
        "on behalf of the current user. " +
        ("Returns token_type, expires_in, service, user_id, scopes, and delegation_id. Pass delegation_id to cred_use. "
         if token_format == "handle"
         else "Returns access_token, token_type, expires_in, service, and scopes. ") +
        "Raises an error with consent_url if the user hasn't connected the service."
    )
    return FunctionTool(delegate, name="cred_delegate", description=description)


def cred_use_tool(
    agent_token: str,
    base_url: str,
) -> FunctionTool:
    """Create an AutoGen FunctionTool for brokered upstream API calls."""
    cred = Cred(agent_token=agent_token, base_url=base_url)

    def use(
        delegation_id: Annotated[str, "Brokered delegation handle returned by cred_delegate."],
        url: Annotated[str, "Full HTTPS API URL to call."],
        method: Annotated[str, "HTTP method: GET, POST, PUT, PATCH, or DELETE."],
        body: Annotated[Optional[dict[str, Any]], "Optional JSON request body."] = None,
        extra_headers: Annotated[Optional[dict[str, str]], "Optional service-specific headers."] = None,
    ) -> str:
        """Make an authenticated API call through Cred using a brokered delegation handle."""
        result = cred.use(
            delegation_id=delegation_id,
            url=url,
            method=method,
            body=body,
            extra_headers=extra_headers,
        )
        return json.dumps({
            "status": result.status,
            "ok": result.ok,
            "content_type": result.content_type,
            "body": result.body,
            "truncated": result.truncated,
            "truncated_at": result.truncated_at,
        })

    return FunctionTool(use, name="cred_use", description=(
        "Make an authenticated API call through Cred using a brokered delegation handle. "
        "The provider access token stays on the Cred server."
    ))
