"""Cred OpenAI Agents SDK integration.

Returns a FunctionTool that agents can call to get delegated OAuth tokens.
The tool schema matches the Cred MCP tool spec (Move 5):

    name:   cred_delegate
    params: { service: str, scopes: list[str] | None }

user_id and app_client_id are pre-configured at factory time — they come from
the authenticated user context and are not agent-controlled inputs.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from agents import FunctionTool, RunContextWrapper

from cred import Cred
from cred.exceptions import ConsentRequiredError

# JSON schema for the tool's input parameters
_PARAMS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "service": {
            "type": "string",
            "description": (
                "Service slug to get a token for "
                "(e.g. 'google', 'github', 'google-calendar')."
            ),
        },
        "scopes": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "OAuth scopes to request (e.g. ['calendar.readonly']). "
                "Pass an empty list to use all consented scopes."
            ),
        },
    },
    "required": ["service", "scopes"],
    "additionalProperties": False,
}


def cred_delegate_tool(
    agent_token: str,
    user_id: str,
    app_client_id: str,
    base_url: str = "https://api.cred.ninja",
) -> FunctionTool:
    """Create an OpenAI Agents SDK FunctionTool for credential delegation.

    The returned tool is pre-configured with the user's identity and app context.
    At runtime, the agent supplies ``service`` and ``scopes``.

    Args:
        agent_token:    Agent token issued by Cred (starts with ``cred_at_``).
        user_id:        The user whose credentials to delegate.
        app_client_id:  The Cred app client ID to delegate for.
        base_url:       Override the API base URL.

    Returns:
        A ``FunctionTool`` ready to pass to ``Agent(tools=[...])``.

    Raises:
        ConsentRequiredError: (from the tool at runtime) when the user hasn't
            connected the requested service. The error message includes
            ``consent_url`` so the caller can redirect the user.

    Example::

        from cred_openai_agents import cred_delegate_tool
        from agents import Agent

        tool = cred_delegate_tool(
            agent_token=os.environ["CRED_AGENT_TOKEN"],
            user_id="user_123",
            app_client_id="my_app",
        )
        agent = Agent(name="assistant", tools=[tool])
    """
    cred = Cred(agent_token=agent_token, base_url=base_url)

    async def on_invoke_tool(
        ctx: RunContextWrapper[Any],
        args_json: str,
    ) -> str:
        args: dict[str, Any] = json.loads(args_json)
        service: str = args["service"]
        scopes: Optional[list[str]] = args.get("scopes") or None

        # Cred SDK is sync — run in thread pool to avoid blocking event loop
        result = await asyncio.to_thread(
            cred.delegate,
            service=service,
            user_id=user_id,
            app_client_id=app_client_id,
            scopes=scopes,
        )

        return json.dumps({
            "access_token": result.access_token,
            "token_type": result.token_type,
            "expires_in": result.expires_in,
            "service": result.service,
            "scopes": result.scopes,
            "delegation_id": result.delegation_id,
        })

    return FunctionTool(
        name="cred_delegate",
        description=(
            "Get a delegated OAuth access token for a third-party service "
            "on behalf of the current user. "
            "Returns access_token, token_type, expires_in, service, and scopes. "
            "Raises an error with consent_url if the user hasn't connected the service."
        ),
        params_json_schema=_PARAMS_SCHEMA,
        on_invoke_tool=on_invoke_tool,
        strict_json_schema=False,  # allow scopes to be omitted at agent discretion
    )
