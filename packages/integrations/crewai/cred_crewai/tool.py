"""Cred CrewAI Tool — pre-configured delegation tool for a single service.

CrewAI's BaseTool is langchain_core.tools.BaseTool under the hood
(verified in crewai 0.11.x source). We import from langchain_core so this
package works in environments where crewai is installed alongside langchain,
without requiring crewai as a hard build dependency at import time.

When crewai is installed, pass CredTool instances directly to Agent(tools=[...]).
"""

from __future__ import annotations

import time
import json
from typing import Any, Optional, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from cred import Cred
from cred.exceptions import ConsentRequiredError  # re-export for convenience


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
        )

        # Use with CrewAI
        from crewai import Agent
        agent = Agent(role="Calendar Manager", tools=[google_tool])
    """

    # langchain_core requires these as class-level annotations
    name: str = "cred_delegate"
    description: str = "Get a delegated OAuth access token for a service"
    args_schema: Type[BaseModel] = _CredToolInput

    # Tool state — set in __init__
    _cred: Any = None
    _user_id: str = ""
    _service: str = ""
    _app_client_id: str = ""
    _scopes: list[str] = []
    _token_format: str = "raw"
    _cached_token: str | None = None
    _cache_expires_at: float = 0.0

    def __init__(
        self,
        agent_token: str,
        user_id: str,
        service: str,
        app_client_id: str,
        base_url: str,
        scopes: Optional[list[str]] = None,
        token_format: str = "raw",
        **kwargs: Any,
    ) -> None:
        if token_format not in {"raw", "handle"}:
            raise ValueError("token_format must be 'raw' or 'handle'")
        super().__init__(**kwargs)
        self._cred = Cred(agent_token=agent_token, base_url=base_url)
        self._user_id = user_id
        self._service = service
        self._app_client_id = app_client_id
        self._scopes = scopes or []
        self._token_format = token_format
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

    _cred: Any = None

    def __init__(
        self,
        agent_token: str,
        base_url: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._cred = Cred(agent_token=agent_token, base_url=base_url)

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
