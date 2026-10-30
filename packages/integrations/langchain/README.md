# cred-langchain

LangChain integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-langchain
```

## Quick Start

```python
import os
from cred_langchain import CredToolkit
from cred import ConsentRequiredError
from cred import AgentIdentity

# The agent's own did:key identity, created once with cred.generate_agent_identity()
# and persisted with identity.export(); load_agent_identity() stands for your own
# secret store lookup returning that dict.
identity = AgentIdentity.from_export(load_agent_identity())

toolkit = CredToolkit(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    base_url=os.environ["CRED_BASE_URL"],
    user_id="user_123",
    token_format="handle",
    agent_identity=identity,
)
tools = toolkit.get_tools()
# tools = [CredDelegateTool, CredStatusTool, CredRevokeTool, CredUseTool]

# Use with any LangChain agent
from langchain.agents import AgentExecutor
agent = AgentExecutor(agent=..., tools=tools)
```

## Tools

| Tool | Name | Description |
|------|------|-------------|
| `CredDelegateTool` | `cred_delegate` | Get OAuth access for a service |
| `CredUseTool` | `cred_use` | Broker an API call through Cred with a delegation id |
| `CredStatusTool` | `cred_status` | List user's connected services |
| `CredRevokeTool` | `cred_revoke` | Revoke a service connection |

`CredToolkit(..., token_format="handle")` returns brokered delegation ids from `cred_delegate` and includes `cred_use` so provider access tokens stay on the Cred server. The default `token_format="raw"` remains available for backwards compatibility.

`agent_identity` is required with `token_format="handle"`. The Cred server issues a Delegation Token (a DPoP-bound JWT) to the agent's own key and accepts it only with a DPoP proof signed by that key. The key stays in your process; it is never sent to the model or the server, and it is not a tool argument. The model only sees `delegation_id`: the token itself is kept in an in-process map (`delegation_id` to token and expiry), filled by the delegate tool and read by the use tool, so it never appears in tool output. The use tool raises a clear error if no `agent_identity` is configured or the `delegation_id` is unknown or expired (call the delegate tool again).

## Handling Consent

When a user hasn't connected a service yet, `CredDelegateTool` raises `ConsentRequiredError`.
Catch it and redirect the user to `e.consent_url` to complete the OAuth flow.

## Brokered Server Mode

Point `CRED_BASE_URL` at your self-hosted `@credninja/server` deployment and set `token_format="handle"` when you want the agent to receive delegation ids instead of provider access tokens.
