"""Cred Semantic Kernel Plugin.

Provides a kernel function that delegates OAuth credentials for AI agents.
The plugin is pre-configured with agent identity and app context at construction.
At runtime, the agent provides ``service`` and ``scopes`` as function parameters.
"""

from __future__ import annotations

import json
from typing import Annotated, Optional

from semantic_kernel.functions import kernel_function

from cred import Cred


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
        base_url: str = "https://api.cred.ninja",
    ) -> None:
        self._cred = Cred(agent_token=agent_token, base_url=base_url)
        self._user_id = user_id
        self._app_client_id = app_client_id

    @kernel_function(
        name="delegate",
        description=(
            "Get a delegated OAuth access token for a third-party service "
            "on behalf of the current user. "
            "Returns JSON with access_token, token_type, expires_in, service, scopes, "
            "and delegation_id. "
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
