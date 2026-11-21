"""Cred LangChain Tools — individual BaseTool implementations."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any, Optional, Type

from langchain_core.tools import BaseTool

# Use the native tool's model family, including core 0.2 with Pydantic v2.
if hasattr(BaseTool, "model_fields"):
    from pydantic import BaseModel, Field, PrivateAttr
else:
    try:
        from pydantic.v1 import BaseModel, Field, PrivateAttr
    except ImportError:  # Pydantic 1 releases before the v1 compatibility namespace
        from pydantic import BaseModel, Field, PrivateAttr

from cred.integration_support import (
    identity_kwargs as _identity_kwargs,
    agent_did as _agent_did,
    expiry_epoch as _expiry_epoch,
    DelegationTokenStore,
)

if TYPE_CHECKING:
    from cred import Cred


# Intentionally separate from every other integration, even in one process.
_token_store = DelegationTokenStore(unknown_message="Unknown or expired delegation: call cred_delegate first")
_remember_delegation_token = _token_store.remember
_lookup_delegation_token = _token_store.lookup


# ── Input schemas ─────────────────────────────────────────────────────────────

class DelegateInput(BaseModel):
    service: str = Field(description="Service slug to get a token for (e.g. 'google', 'github')")
    app_client_id: str = Field(description="The Cred app client ID to delegate for")
    scopes: list[str] = Field(
        default_factory=list,
        description="OAuth scopes to request (e.g. ['calendar.readonly']). "
                    "Leave empty to use all consented scopes.",
    )


class UseInput(BaseModel):
    delegation_id: str = Field(description="Brokered delegation handle returned by cred_delegate")
    url: str = Field(description="Full HTTPS API URL to call")
    method: str = Field(
        default="GET",
        description="HTTP method: GET, POST, PUT, PATCH, or DELETE",
    )
    body: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional JSON request body for POST, PUT, or PATCH",
    )
    extra_headers: Optional[dict[str, str]] = Field(
        default=None,
        description="Optional service-specific headers",
    )


class RevokeInput(BaseModel):
    service: str = Field(description="Service slug to revoke (e.g. 'google', 'github')")
    app_client_id: Optional[str] = Field(
        default=None,
        description="Optional app client ID to scope the revocation.",
    )


# ── Tools ─────────────────────────────────────────────────────────────────────

class CredDelegateTool(BaseTool):
    """Get an OAuth access token for a third-party service on behalf of the current user."""

    name: str = "cred_delegate"
    description: str = (
        "Get an OAuth access token for a third-party service on behalf of the current user. "
        "Returns the access token, expiry, service name, and granted scopes. "
        "Raises ConsentRequiredError (with consent_url) if the user hasn't connected the service."
    )
    args_schema: Type[BaseModel] = DelegateInput

    # Injected by CredToolkit
    _cred: Any = PrivateAttr(default=None)
    _user_id: str = PrivateAttr(default="")
    _token_format: str = PrivateAttr(default="raw")
    _base_url: str = PrivateAttr(default="")
    # The agent's DPoP signing identity; never part of the tool's input or output.
    _agent_identity: Any = PrivateAttr(default=None)
    _cache: dict[tuple[str, str, str, str, tuple[str, ...]], tuple[Any, float]] = PrivateAttr(default_factory=dict)

    def _get_delegation_result(
        self,
        service: str,
        app_client_id: str,
        scopes: Optional[list[str]],
    ) -> Any:
        resolved_scopes = scopes or []
        # A handle is bound to the agent's key, so the key is part of the cache key.
        agent_did = getattr(self._agent_identity, "did", "")
        cache_key = (self._token_format, agent_did, service, app_client_id, tuple(resolved_scopes))
        cached = self._cache.get(cache_key)
        now = time.monotonic()
        if cached and cached[1] > now:
            return cached[0]

        if self._token_format == "handle":
            result = self._cred.delegate_handle(
                service=service,
                user_id=self._user_id,
                app_client_id=app_client_id,
                scopes=resolved_scopes,
                **_identity_kwargs(self._agent_identity),
            )
        else:
            result = self._cred.delegate(
                service=service,
                user_id=self._user_id,
                app_client_id=app_client_id,
                scopes=resolved_scopes,
            )

        expires_in = getattr(result, "expires_in", None)
        refresh_deadline = 0.0
        if isinstance(expires_in, int) and expires_in > 60:
            refresh_deadline = now + expires_in - 60
        self._cache[cache_key] = (result, refresh_deadline)
        return result

    def _run(
        self,
        service: str,
        app_client_id: str,
        scopes: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> str:
        result = self._get_delegation_result(service, app_client_id, scopes)
        if self._token_format == "handle":
            _remember_delegation_token(
                result.delegation_id, result.token, _expiry_epoch(result),
                base_url=self._base_url, agent_did=_agent_did(self._agent_identity), user_id=self._user_id,
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
        return json.dumps({
            "access_token": result.access_token,
            "token_type": result.token_type,
            "expires_in": result.expires_in,
            "service": result.service,
            "scopes": result.scopes,
            "delegation_id": result.delegation_id,
        })


class CredUseTool(BaseTool):
    """Broker an upstream API request through Cred without exposing provider tokens."""

    name: str = "cred_use"
    description: str = (
        "Make an authenticated API call through Cred using a brokered delegation handle. "
        "The provider access token stays on the Cred server."
    )
    args_schema: Type[BaseModel] = UseInput

    _cred: Any = PrivateAttr(default=None)
    _base_url: str = PrivateAttr(default="")
    _user_id: str = PrivateAttr(default="")
    # The agent's DPoP signing identity; never part of the tool's input or output.
    _agent_identity: Any = PrivateAttr(default=None)

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
                "Pass agent_identity= to CredToolkit.",
            )
        token = _lookup_delegation_token(
            delegation_id, base_url=self._base_url, agent_did=_agent_did(self._agent_identity), user_id=self._user_id,
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


class CredStatusTool(BaseTool):
    """Check which third-party services the current user has connected."""

    name: str = "cred_status"
    description: str = (
        "Check which third-party services the current user has connected via OAuth. "
        "Returns a list of connected services with their granted scopes."
    )

    # Injected by CredToolkit
    _cred: Any = PrivateAttr(default=None)
    _user_id: str = PrivateAttr(default="")

    def _run(self, **kwargs: Any) -> str:
        connections = self._cred.get_user_connections(self._user_id)
        return json.dumps([
            {
                "slug": c.slug,
                "scopes_granted": c.scopes_granted,
                "app_client_id": c.app_client_id,
                "consented_at": c.consented_at,
            }
            for c in connections
        ])


class CredRevokeTool(BaseTool):
    """Revoke the current user's connection to a third-party service."""

    name: str = "cred_revoke"
    description: str = (
        "Revoke the current user's OAuth connection to a third-party service. "
        "Use this when the user wants to disconnect a service."
    )
    args_schema: Type[BaseModel] = RevokeInput

    # Injected by CredToolkit
    _cred: Any = PrivateAttr(default=None)
    _user_id: str = PrivateAttr(default="")

    def _run(
        self,
        service: str,
        app_client_id: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        self._cred.revoke(
            service=service,
            user_id=self._user_id,
            app_client_id=app_client_id,
        )
        return json.dumps({"revoked": True, "service": service})
