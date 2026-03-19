"""Cred LangChain Toolkit — bundles all Cred tools for use with LangChain agents."""

from __future__ import annotations

from typing import Optional

from langchain_core.tools import BaseTool

from cred import Cred
from .tools import CredDelegateTool, CredStatusTool, CredRevokeTool


class CredToolkit:
    """LangChain toolkit that provides Cred credential delegation tools.

    Instantiate once per agent invocation with the target user's ID.
    All tools share the same Cred client and user context.

    Example::

        from cred_langchain import CredToolkit

        toolkit = CredToolkit(
            agent_token=os.environ["CRED_AGENT_TOKEN"],
            user_id="user_123",
        )
        tools = toolkit.get_tools()
        # Pass tools to your LangChain AgentExecutor
    """

    def __init__(
        self,
        agent_token: str,
        user_id: str,
        base_url: str = "https://api.cred.ninja",
    ) -> None:
        self._cred = Cred(agent_token=agent_token, base_url=base_url)
        self._user_id = user_id

    def get_tools(self) -> list[BaseTool]:
        """Return all Cred tools pre-configured with this toolkit's user context."""
        delegate = CredDelegateTool()
        delegate._cred = self._cred
        delegate._user_id = self._user_id

        status = CredStatusTool()
        status._cred = self._cred
        status._user_id = self._user_id

        revoke = CredRevokeTool()
        revoke._cred = self._cred
        revoke._user_id = self._user_id

        return [delegate, status, revoke]
