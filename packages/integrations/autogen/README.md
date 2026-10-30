# cred-autogen

Microsoft AutoGen integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-autogen
```

## Quick Start

```python
import os
from cred_autogen import cred_delegate_tool, cred_use_tool
from cred import AgentIdentity

# The agent's own did:key identity, created once with cred.generate_agent_identity()
# and persisted with identity.export(); load_agent_identity() stands for your own
# secret store lookup returning that dict.
identity = AgentIdentity.from_export(load_agent_identity())

tool = cred_delegate_tool(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    base_url=os.environ["CRED_BASE_URL"],
    user_id="user_123",
    app_client_id="my_app_client_id",
    token_format="handle",
    agent_identity=identity,
)

# Register with an AutoGen AssistantAgent
from autogen_agentchat.agents import AssistantAgent

agent = AssistantAgent(
    name="assistant",
    tools=[tool, cred_use_tool(
        agent_token=os.environ["CRED_AGENT_TOKEN"],
        base_url=os.environ["CRED_BASE_URL"],
        agent_identity=identity,
    )],
)
```

## Tool Schema

The `cred_delegate` tool accepts:

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `string` | Service slug (e.g. `google`, `github`) |
| `scopes` | `string[]` | OAuth scopes to request |

`user_id` and `app_client_id` are pre-configured at factory time, not agent-controlled.

By default, `cred_delegate_tool` returns a legacy access token for backwards compatibility. Set `token_format="handle"` to return a brokered delegation handle, then use `cred_use_tool` to make allowed service API calls without exposing provider access tokens.

`agent_identity` binds brokered handles to the agent's own key: the Cred server (which requires DPoP by default) issues and accepts a handle only with a DPoP proof signed by it. The key stays in your process; it is never sent to the model or the server, and it is not a tool argument.

## Handling Consent

When the user hasn't connected the service, the tool raises `ConsentRequiredError`.
The error's `consent_url` attribute contains the URL to redirect the user.

```python
from cred import ConsentRequiredError

try:
    result = await tool.run_json(
        {"service": "google", "scopes": ["calendar.readonly"]},
        cancellation_token,
    )
except ConsentRequiredError as e:
    print(f"Redirect user to: {e.consent_url}")
```

## Brokered Server Mode

Point `CRED_BASE_URL` at your self-hosted `@credninja/server` deployment and set `token_format="handle"` when you want the agent to receive delegation handles instead of provider access tokens.
