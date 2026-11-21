"""Cred tools using CrewAI's native tool contract for the installed framework."""

from __future__ import annotations

import time
import json
from typing import TYPE_CHECKING, Any, Optional, Type

from crewai import tools as crewai_tools

if hasattr(crewai_tools, "BaseTool"):
    from crewai.tools import BaseTool
else:
    # CrewAI 0.11 uses LangChain tools; newer releases own their tool base.
    from langchain_core.tools import BaseTool

if hasattr(BaseTool, "model_fields"):
    from pydantic import BaseModel, Field, PrivateAttr
else:
    try:
        from pydantic.v1 import BaseModel, Field, PrivateAttr
    except ImportError:  # Pydantic 1 releases before the v1 compatibility namespace
        from pydantic import BaseModel, Field, PrivateAttr

from cred import Cred
from cred.exceptions import ConsentRequiredError  # re-export for convenience

from cred.integration_support import (
    resolve_client as _resolve_client,
    identity_kwargs as _identity_kwargs,
    agent_did as _agent_did,
    expiry_epoch as _expiry_epoch,
    DelegationTokenStore,
)

if TYPE_CHECKING:
    from cred import DpopSigningIdentity


# Intentionally separate from every other integration, even in one process.
_token_store = DelegationTokenStore()
_remember_delegation_token = _token_store.remember
_lookup_delegation_token = _token_store.lookup


class _CredToolInput(BaseModel):
    """Placeholder input — CredTool has no runtime inputs; all params are pre-configured."""
    pass


class _CredUseInput(BaseModel):
    delegation_id: str = Field(description="Brokered delegation handle returned by cred_delegate")
    url: str = Field(description="Full HTTPS API URL to call")
    method: str = Field(default="GET", description="HTTP method: GET, POST, PUT, PATCH, or DELETE")
    body: Optional[dict[str, Any]] = Field(default=None, description="Optional JSON request body")
    extra_headers: Optional[dict[str, str]] = Field(default=None, description="Optional service-specific headers")


class CredTool(BaseTool):
    """A CrewAI-compatible tool that delegates credentials for a single service.

    Pre-configured at construction time with a specific service, user, and
    optional scopes. The agent calls it with no additional parameters — the
    service/user context is baked in, keeping the agent's decision surface small.

    Example::

        from cred_crewai import CredTool

        google_tool = CredTool(
            agent_token=os.environ["CRED_AGENT_TOKEN"],
            base_url=os.environ["CRED_BASE_URL"],
            user_id="user_123",
            service="google",
            app_client_id="my_app",
            scopes=["calendar.readonly"],
            token_format="handle",
            agent_identity=identity,  # an AgentIdentity; never shown to the model
        )

        # Use with CrewAI
        from crewai import Agent
        agent = Agent(role="Calendar Manager", goal="Manage the user's calendar",
                      backstory="An assistant using delegated access", tools=[google_tool])
    """

    # Framework-facing tool metadata; private configuration is not an input.
    name: str = "cred_delegate"
    description: str = "Get a delegated OAuth access token for a service"
    args_schema: Type[BaseModel] = _CredToolInput

    # Tool state — set in __init__
    _cred: Any = PrivateAttr(default=None)
    _user_id: str = PrivateAttr(default="")
    _base_url: str = PrivateAttr(default="")
    _service: str = PrivateAttr(default="")
    _app_client_id: str = PrivateAttr(default="")
    _scopes: list[str] = PrivateAttr(default_factory=list)
    _token_format: str = PrivateAttr(default="raw")
    # The agent's DPoP signing identity; never part of the tool's input or output.
    _agent_identity: Any = PrivateAttr(default=None)
    _cached_token: str | None = PrivateAttr(default=None)
    _cache_expires_at: float = PrivateAttr(default=0.0)

    def __init__(
        self,
        agent_token: Optional[str],
        user_id: str,
        service: str,
        app_client_id: str,
        base_url: Optional[str],
        scopes: Optional[list[str]] = None,
        token_format: str = "raw",
        *,
        cred: Optional[Cred] = None,
        agent_identity: Optional[DpopSigningIdentity] = None,
        **kwargs: Any,
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
        super().__init__(**kwargs)
        self._cred, base_url = _resolve_client(agent_token, base_url, cred)
        self._base_url = base_url
        self._user_id = user_id
        self._service = service
        self._app_client_id = app_client_id
        self._scopes = scopes or []
        self._token_format = token_format
        self._agent_identity = agent_identity
        # Set dynamic name and description after init
        self.name = f"cred_{service.replace('-', '_')}_delegate"
        if token_format == "handle":
            self.description = (
                f"Get a brokered OAuth delegation handle for {service} on behalf of the current user. "
                f"Returns JSON with delegation_id and expiry. Pass delegation_id to cred_use. "
                f"Raises ConsentRequiredError (with consent_url) if the user hasn't connected {service}."
            )
        else:
            self.description = (
                f"Get a delegated OAuth access token for {service} on behalf of the current user. "
                f"Returns the access token string. "
                f"Raises ConsentRequiredError (with consent_url) if the user hasn't connected {service}."
            )

    def _run(self, **kwargs: Any) -> str:
        """Delegate credentials and return an access token or brokered handle."""
        now = time.monotonic()
        if self._cached_token is not None and self._cache_expires_at > now:
            return self._cached_token

        if self._token_format == "handle":
            result = self._cred.delegate_handle(
                service=self._service,
                user_id=self._user_id,
                app_client_id=self._app_client_id,
                scopes=self._scopes if self._scopes else None,
                **_identity_kwargs(self._agent_identity),
            )
            _remember_delegation_token(
                result.delegation_id, result.token, _expiry_epoch(result),
                base_url=self._base_url, agent_did=_agent_did(self._agent_identity), user_id=self._user_id,
            )
            output = {
                "token_type": result.token_type,
                "expires_in": result.expires_in,
                "service": result.service,
                "user_id": result.user_id,
                "scopes": result.scopes,
                "delegation_id": result.delegation_id,
                "note": "Pass delegation_id to cred_use to make authenticated API calls.",
            }
            self._cached_token = json.dumps(output)
        else:
            result = self._cred.delegate(
                service=self._service,
                user_id=self._user_id,
                app_client_id=self._app_client_id,
                scopes=self._scopes if self._scopes else None,
            )
            self._cached_token = result.access_token
        expires_in = getattr(result, "expires_in", None)
        self._cache_expires_at = now + expires_in - 60 if isinstance(expires_in, int) and expires_in > 60 else 0.0
        return self._cached_token


class CredUseTool(BaseTool):
    """CrewAI-compatible brokered API caller for handles returned by CredTool."""

    name: str = "cred_use"
    description: str = (
        "Make an authenticated API call through Cred using a brokered delegation handle. "
        "The provider access token stays on the Cred server."
    )
    args_schema: Type[BaseModel] = _CredUseInput

    _cred: Any = PrivateAttr(default=None)
    _base_url: str = PrivateAttr(default="")
    # The agent's DPoP signing identity; never part of the tool's input or output.
    _agent_identity: Any = PrivateAttr(default=None)
    _use_user_id: Optional[str] = PrivateAttr(default=None)

    def __init__(
        self,
        agent_token: Optional[str],
        base_url: Optional[str],
        *,
        cred: Optional[Cred] = None,
        agent_identity: Optional[DpopSigningIdentity] = None,
        user_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Args:
            user_id: The user this tool acts for. When set, only delegations issued
                for this user can be used. Pass it in any process that serves
                more than one user.
            agent_identity: The agent's own identity (an ``AgentIdentity`` from
                ``cred``). Brokered handles are bound to this key: the Cred server
                requires a DPoP proof by it to issue a handle and to use one. The
                key stays in your process; it is never sent to the model or the server.
        """
        super().__init__(**kwargs)
        self._cred, base_url = _resolve_client(agent_token, base_url, cred)
        self._base_url = base_url
        self._agent_identity = agent_identity
        self._use_user_id = user_id

    def _run(
        self,
        delegation_id: str,
        url: str,
        method: str = "GET",
        body: Optional[dict[str, Any]] = None,
        extra_headers: Optional[dict[str, str]] = None,
        **kwargs: Any,
    ) -> str:
        if self._agent_identity is None:
            raise ValueError(
                "cred_use requires an agent_identity: the delegation token is bound to the agent's key. "
                "Pass agent_identity= to CredUseTool.",
            )
        token = _lookup_delegation_token(
            delegation_id, base_url=self._base_url, agent_did=_agent_did(self._agent_identity),
            user_id=self._use_user_id,
        )
        result = self._cred.use(
            token,
            url=url,
            method=method,
            body=body,
            extra_headers=extra_headers,
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
