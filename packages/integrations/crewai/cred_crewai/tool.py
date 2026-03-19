"""Cred CrewAI Tool — pre-configured delegation tool for a single service.

CrewAI's BaseTool is langchain_core.tools.BaseTool under the hood
(verified in crewai 0.11.x source). We import from langchain_core so this
package works in environments where crewai is installed alongside langchain,
without requiring crewai as a hard build dependency at import time.

When crewai is installed, pass CredTool instances directly to Agent(tools=[...]).
"""

from __future__ import annotations

import time
from typing import Any, Optional, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from cred import Cred
from cred.exceptions import ConsentRequiredError  # re-export for convenience


class _CredToolInput(BaseModel):
    """Placeholder input — CredTool has no runtime inputs; all params are pre-configured."""
    pass


class CredTool(BaseTool):
    """A CrewAI-compatible tool that delegates credentials for a single service.

    Pre-configured at construction time with a specific service, user, and
    optional scopes. The agent calls it with no additional parameters — the
    service/user context is baked in, keeping the agent's decision surface small.

    Example::

        from cred_crewai import CredTool

        google_tool = CredTool(
            agent_token=os.environ["CRED_AGENT_TOKEN"],
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
    _cached_token: str | None = None
    _cache_expires_at: float = 0.0

    def __init__(
        self,
        agent_token: str,
        user_id: str,
        service: str,
        app_client_id: str,
        scopes: Optional[list[str]] = None,
        base_url: str = "https://api.cred.ninja",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._cred = Cred(agent_token=agent_token, base_url=base_url)
        self._user_id = user_id
        self._service = service
        self._app_client_id = app_client_id
        self._scopes = scopes or []
        # Set dynamic name and description after init
        self.name = f"cred_{service.replace('-', '_')}_delegate"
        self.description = (
            f"Get a delegated OAuth access token for {service} on behalf of the current user. "
            f"Returns the access token string. "
            f"Raises ConsentRequiredError (with consent_url) if the user hasn't connected {service}."
        )

    def _run(self, **kwargs: Any) -> str:
        """Delegate credentials and return the access token string."""
        now = time.monotonic()
        if self._cached_token is not None and self._cache_expires_at > now:
            return self._cached_token

        result = self._cred.delegate(
            service=self._service,
            user_id=self._user_id,
            app_client_id=self._app_client_id,
            scopes=self._scopes if self._scopes else None,
        )
        self._cached_token = result.access_token
        expires_in = getattr(result, "expires_in", None)
        self._cache_expires_at = now + expires_in - 60 if isinstance(expires_in, int) and expires_in > 60 else 0.0
        return result.access_token
