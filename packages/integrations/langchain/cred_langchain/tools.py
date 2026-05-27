"""Cred LangChain Tools — individual BaseTool implementations."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any, Optional, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from cred import Cred


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
    _cred: Any = None
    _user_id: str = ""
    _token_format: str = "raw"
    _cache: dict[tuple[str, str, str, tuple[str, ...]], tuple[Any, float]] = {}

    def _get_delegation_result(
        self,
        service: str,
        app_client_id: str,
        scopes: Optional[list[str]],
    ) -> Any:
        resolved_scopes = scopes or []
        cache_key = (self._token_format, service, app_client_id, tuple(resolved_scopes))
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

    _cred: Any = None

    def _run(
        self,
        delegation_id: str,
        url: str,
        method: str = "GET",
        body: Optional[dict[str, Any]] = None,
        extra_headers: Optional[dict[str, str]] = None,
        **kwargs: Any,
    ) -> str:
        result = self._cred.use(
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


class CredStatusTool(BaseTool):
    """Check which third-party services the current user has connected."""

    name: str = "cred_status"
    description: str = (
        "Check which third-party services the current user has connected via OAuth. "
        "Returns a list of connected services with their granted scopes."
    )

    # Injected by CredToolkit
    _cred: Any = None
    _user_id: str = ""

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
    _cred: Any = None
    _user_id: str = ""

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
