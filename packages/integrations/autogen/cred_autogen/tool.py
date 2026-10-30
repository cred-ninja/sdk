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
import time
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Optional

from autogen_core.tools import FunctionTool

from cred import Cred

if TYPE_CHECKING:
    from cred import DpopSigningIdentity


def _identity_kwargs(agent_identity: Any) -> dict[str, Any]:
    """``agent_identity=`` for the SDK call, only when one is configured."""
    return {"agent_identity": agent_identity} if agent_identity is not None else {}


# ── Delegation token store ────────────────────────────────────────────────────
#
# The model only ever sees ``delegation_id``. The Delegation Token that
# ``cred_use`` needs stays in this in-process mapping (delegation_id ->
# (token, expiry)), populated by the delegate tool and read by the use tool.

_DELEGATION_TOKENS: dict[str, tuple[str, float, str, str, Optional[str]]] = {}


def _agent_did(agent_identity: Any) -> str:
    return getattr(agent_identity, "did", "") or ""


def _remember_delegation_token(
    delegation_id: str,
    token: str,
    expires_at: float,
    *,
    base_url: str,
    agent_did: str,
    user_id: Optional[str] = None,
) -> None:
    """Store a token with the server, agent and user it was issued for."""
    now = time.time()
    for key in [k for k, entry in _DELEGATION_TOKENS.items() if entry[1] <= now]:
        del _DELEGATION_TOKENS[key]
    _DELEGATION_TOKENS[delegation_id] = (token, expires_at, base_url.rstrip("/"), agent_did, user_id)


def _lookup_delegation_token(
    delegation_id: str,
    *,
    base_url: str,
    agent_did: str,
    user_id: Optional[str] = None,
) -> str:
    """Return the token only to a tool configured for the same server, agent and user.

    User rule (fail closed when both are set): if the use tool was configured with a
    ``user_id`` it must equal the user the delegation was remembered for, otherwise
    ``ValueError``. A use tool with no ``user_id`` skips the user check so single-user
    setups keep working; processes serving several users must pass ``user_id``.
    """
    entry = _DELEGATION_TOKENS.get(delegation_id)
    if entry is None or entry[1] <= time.time():
        _DELEGATION_TOKENS.pop(delegation_id, None)
        raise ValueError("Unknown or expired delegation: call the delegate tool first")
    _, _, entry_base_url, entry_agent_did, entry_user_id = entry
    if (
        entry_base_url != base_url.rstrip("/")
        or entry_agent_did != agent_did
        or (user_id is not None and entry_user_id != user_id)
    ):
        raise ValueError("This delegation was issued for a different server, agent or user")
    return entry[0]


def _expiry_epoch(result: Any) -> float:
    expires_at = getattr(result, "expires_at", None)
    if isinstance(expires_at, datetime):
        return expires_at.timestamp()
    expires_in = getattr(result, "expires_in", 0)
    return time.time() + (expires_in if isinstance(expires_in, (int, float)) else 0)


def cred_delegate_tool(
    agent_token: str,
    user_id: str,
    app_client_id: str,
    base_url: str,
    token_format: str = "raw",
    *,
    agent_identity: Optional[DpopSigningIdentity] = None,
) -> FunctionTool:
    """Create an AutoGen FunctionTool for credential delegation.

    The returned tool is pre-configured with the user's identity and app context.
    At runtime, the agent supplies ``service`` and ``scopes``.

    Args:
        agent_token:    Agent token issued by Cred (starts with ``cred_at_``).
        user_id:        The user whose credentials to delegate.
        app_client_id:  The Cred app client ID to delegate for.
        base_url:       Override the API base URL.
        token_format:   ``"raw"`` (access token) or ``"handle"`` (brokered handle).
        agent_identity: The agent's own identity (an ``AgentIdentity`` from
                        ``cred``). Brokered handles are bound to this key: the
                        Cred server requires a DPoP proof by it to issue a
                        handle and to use one. The key stays in your process;
                        it is never sent to the model or the server.

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
            base_url=os.environ["CRED_BASE_URL"],
            token_format="handle",
            agent_identity=identity,  # an AgentIdentity; never shown to the model
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
                **_identity_kwargs(agent_identity),
            )
            _remember_delegation_token(
                result.delegation_id, result.token, _expiry_epoch(result),
                base_url=base_url, agent_did=_agent_did(agent_identity), user_id=user_id,
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
    *,
    agent_identity: Optional[DpopSigningIdentity] = None,
    user_id: Optional[str] = None,
) -> FunctionTool:
    """Create an AutoGen FunctionTool for brokered upstream API calls.

    user_id: when set, only delegations issued for this user can be used. Pass it
    in any process that serves more than one user.
    """
    cred = Cred(agent_token=agent_token, base_url=base_url)

    def use(
        delegation_id: Annotated[str, "Brokered delegation handle returned by cred_delegate."],
        url: Annotated[str, "Full HTTPS API URL to call."],
        method: Annotated[str, "HTTP method: GET, POST, PUT, PATCH, or DELETE."],
        body: Annotated[Optional[dict[str, Any]], "Optional JSON request body."] = None,
        extra_headers: Annotated[Optional[dict[str, str]], "Optional service-specific headers."] = None,
    ) -> str:
        """Make an authenticated API call through Cred using a brokered delegation handle."""
        if agent_identity is None:
            raise ValueError(
                "cred_use requires an agent_identity: the delegation token is bound to the agent's key. "
                "Pass agent_identity= to cred_use_tool().",
            )
        token = _lookup_delegation_token(
            delegation_id, base_url=base_url, agent_did=_agent_did(agent_identity),
            user_id=user_id,
        )
        result = cred.use(
            token,
            url=url,
            method=method,
            body=body,
            extra_headers=extra_headers,
            agent_identity=agent_identity,
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
