"""Cred Semantic Kernel Plugin.

Provides a kernel function that delegates OAuth credentials for AI agents.
The plugin is pre-configured with agent identity and app context at construction.
At runtime, the agent provides ``service`` and ``scopes`` as function parameters.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Optional

from semantic_kernel.functions import kernel_function

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

_DELEGATION_TOKENS: dict[str, tuple[str, float]] = {}


def _remember_delegation_token(delegation_id: str, token: str, expires_at: float) -> None:
    now = time.time()
    for key in [k for k, (_, exp) in _DELEGATION_TOKENS.items() if exp <= now]:
        del _DELEGATION_TOKENS[key]
    _DELEGATION_TOKENS[delegation_id] = (token, expires_at)


def _lookup_delegation_token(delegation_id: str) -> str:
    entry = _DELEGATION_TOKENS.get(delegation_id)
    if entry is None or entry[1] <= time.time():
        _DELEGATION_TOKENS.pop(delegation_id, None)
        raise ValueError("Unknown or expired delegation: call the delegate tool first")
    return entry[0]


def _expiry_epoch(result: Any) -> float:
    expires_at = getattr(result, "expires_at", None)
    if isinstance(expires_at, datetime):
        return expires_at.timestamp()
    expires_in = getattr(result, "expires_in", 0)
    return time.time() + (expires_in if isinstance(expires_in, (int, float)) else 0)


class CredPlugin:
    """Semantic Kernel plugin for Cred credential delegation.

    Pre-configured at construction with the agent token, user ID, and
    app client ID. Exposes a single ``delegate`` kernel function.

    Example::

        from cred_semantic_kernel import CredPlugin
        import semantic_kernel as sk

        kernel = sk.Kernel()
        plugin = CredPlugin(
            agent_token=os.environ["CRED_AGENT_TOKEN"],
            user_id="user_123",
            app_client_id="my_app",
            base_url=os.environ["CRED_BASE_URL"],
            token_format="handle",
            agent_identity=identity,  # an AgentIdentity; never shown to the model
        )
        kernel.add_plugin(plugin, plugin_name="cred")

    Raises:
        ConsentRequiredError: (from delegate at runtime) when the user hasn't
            connected the requested service. The error message includes
            ``consent_url`` so the caller can redirect the user.
    """

    def __init__(
        self,
        agent_token: str,
        user_id: str,
        app_client_id: str,
        base_url: str,
        token_format: str = "raw",
        *,
        agent_identity: Optional[DpopSigningIdentity] = None,
    ) -> None:
        """
        Args:
            agent_identity: The agent's own identity (an ``AgentIdentity`` from
                ``cred``). Brokered handles are bound to this key: the Cred server
                requires a DPoP proof by it to issue a handle and to use one. The
                key stays in your process; it is never sent to the model or the server.
        """
        if token_format not in {"raw", "handle"}:
            raise ValueError("token_format must be 'raw' or 'handle'")
        self._cred = Cred(agent_token=agent_token, base_url=base_url)
        self._user_id = user_id
        self._app_client_id = app_client_id
        self._token_format = token_format
        # The agent's DPoP signing identity; never part of a kernel function's
        # parameters or result.
        self._agent_identity = agent_identity

    @kernel_function(
        name="delegate",
        description=(
            "Get delegated OAuth access for a third-party service "
            "on behalf of the current user. "
            "Returns JSON with either access_token or a brokered delegation_id, plus expiry, service, and scopes. "
            "Raises an error with consent_url if the user hasn't connected the service."
        ),
    )
    def delegate(
        self,
        service: Annotated[str, "Service slug to get a token for (e.g. 'google', 'github', 'google-calendar')."],
        scopes: Annotated[str, "Comma-separated OAuth scopes to request (e.g. 'calendar.readonly,calendar.events'). Pass empty string to use all consented scopes."],
    ) -> str:
        """Delegate credentials and return JSON result."""
        scope_list: Optional[list[str]] = None
        if scopes:
            scope_list = [s.strip() for s in scopes.split(",") if s.strip()]

        if self._token_format == "handle":
            result = self._cred.delegate_handle(
                service=service,
                user_id=self._user_id,
                app_client_id=self._app_client_id,
                scopes=scope_list if scope_list else None,
                **_identity_kwargs(self._agent_identity),
            )
            _remember_delegation_token(result.delegation_id, result.token, _expiry_epoch(result))
            return json.dumps({
                "token_type": result.token_type,
                "expires_in": result.expires_in,
                "service": result.service,
                "user_id": result.user_id,
                "scopes": result.scopes,
                "delegation_id": result.delegation_id,
                "note": "Pass delegation_id to use to make authenticated API calls.",
            })

        result = self._cred.delegate(
            service=service,
            user_id=self._user_id,
            app_client_id=self._app_client_id,
            scopes=scope_list if scope_list else None,
        )
        return json.dumps({
            "access_token": result.access_token,
            "token_type": result.token_type,
            "expires_in": result.expires_in,
            "service": result.service,
            "scopes": result.scopes,
            "delegation_id": result.delegation_id,
        })

    @kernel_function(
        name="use",
        description=(
            "Make an authenticated API call through Cred using a brokered delegation handle. "
            "The provider access token stays on the Cred server."
        ),
    )
    def use(
        self,
        delegation_id: Annotated[str, "Brokered delegation handle returned by delegate."],
        url: Annotated[str, "Full HTTPS API URL to call."],
        method: Annotated[str, "HTTP method: GET, POST, PUT, PATCH, or DELETE."],
        body: Annotated[str, "Optional JSON request body. Pass empty string when unused."] = "",
        extra_headers: Annotated[str, "Optional JSON object of service-specific headers. Pass empty string when unused."] = "",
    ) -> str:
        """Broker an upstream API request and return JSON result."""
        if self._agent_identity is None:
            raise ValueError(
                "use requires an agent_identity: the delegation token is bound to the agent's key. "
                "Pass agent_identity= to CredPlugin.",
            )
        parsed_body = json.loads(body) if body else None
        parsed_headers = json.loads(extra_headers) if extra_headers else None
        token = _lookup_delegation_token(delegation_id)
        result = self._cred.use(
            token,
            url=url,
            method=method,
            body=parsed_body,
            extra_headers=parsed_headers,
            agent_identity=self._agent_identity,
        )
        return json.dumps({
            "status": result.status,
            "ok": result.ok,
            "content_type": result.content_type,
            "body": result.body,
            "truncated": result.truncated,
            "truncated_at": result.truncated_at,
        })
