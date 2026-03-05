# cred-langchain

LangChain integration for [Cred](https://cred.ninja). OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-langchain
```

## Quick Start

```python
import os
from cred_langchain import CredToolkit
from cred import ConsentRequiredError

toolkit = CredToolkit(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    user_id="user_123",
)
tools = toolkit.get_tools()
# tools = [CredDelegateTool, CredStatusTool, CredRevokeTool]

# Use with any LangChain agent
from langchain.agents import AgentExecutor
agent = AgentExecutor(agent=..., tools=tools)
```

## Tools

| Tool | Name | Description |
|------|------|-------------|
| `CredDelegateTool` | `cred_delegate` | Get an OAuth access token for a service |
| `CredStatusTool` | `cred_status` | List user's connected services |
| `CredRevokeTool` | `cred_revoke` | Revoke a service connection |

## Handling Consent

When a user hasn't connected a service yet, `CredDelegateTool` raises `ConsentRequiredError`.
Catch it and redirect the user to `e.consent_url` to complete the OAuth flow.

## Cred Cloud

Managed token refresh, multi-tenant storage, and audit logs → [cred.ninja](https://cred.ninja).
