# cred-openai-agents

OpenAI Agents SDK integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-openai-agents
```

## Quick Start

```python
import os
from cred_openai_agents import cred_delegate_tool, cred_use_tool
from agents import Agent

tool = cred_delegate_tool(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    base_url=os.environ["CRED_BASE_URL"],
    user_id="user_123",
    app_client_id="my_app_client_id",
    token_format="handle",
)

agent = Agent(
    name="assistant",
    tools=[tool, cred_use_tool(
        agent_token=os.environ["CRED_AGENT_TOKEN"],
        base_url=os.environ["CRED_BASE_URL"],
    )],
)
```

## Tool Schema

The `cred_delegate` tool matches the Cred MCP tool spec:

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `string` | Service slug (e.g. `google`, `github`) |
| `scopes` | `string[]` | OAuth scopes to request |

`user_id` and `app_client_id` are pre-configured at factory time, not agent-controlled.

By default, `cred_delegate_tool` returns a legacy access token for backwards compatibility. Set `token_format="handle"` to return a brokered delegation handle, then use `cred_use_tool` to make allowed service API calls without exposing provider access tokens.

## Handling Consent

When the user hasn't connected the service, the tool raises `ConsentRequiredError`.
The error's `consent_url` attribute contains the URL to redirect the user.

## Brokered Server Mode

Point `CRED_BASE_URL` at your self-hosted `@credninja/server` deployment and set `token_format="handle"` when you want the agent to receive delegation handles instead of provider access tokens.
