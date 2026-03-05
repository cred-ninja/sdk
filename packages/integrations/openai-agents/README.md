# cred-openai-agents

OpenAI Agents SDK integration for [Cred](https://cred.ninja). OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-openai-agents
```

## Quick Start

```python
import os
from cred_openai_agents import cred_delegate_tool
from agents import Agent

tool = cred_delegate_tool(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    user_id="user_123",
    app_client_id="my_app_client_id",
)

agent = Agent(
    name="assistant",
    tools=[tool],
)
```

## Tool Schema

The `cred_delegate` tool matches the Cred MCP tool spec:

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `string` | Service slug (e.g. `google`, `github`) |
| `scopes` | `string[]` | OAuth scopes to request |

`user_id` and `app_client_id` are pre-configured at factory time, not agent-controlled.

## Handling Consent

When the user hasn't connected the service, the tool raises `ConsentRequiredError`.
The error's `consent_url` attribute contains the URL to redirect the user.

## Cred Cloud

Managed token refresh, multi-tenant storage, and audit logs → [cred.ninja](https://cred.ninja).
