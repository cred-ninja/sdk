# cred-autogen

Microsoft AutoGen integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-autogen
```

## Quick Start

```python
import os
from cred_autogen import cred_delegate_tool

tool = cred_delegate_tool(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    user_id="user_123",
    app_client_id="my_app_client_id",
)

# Register with an AutoGen AssistantAgent
from autogen_agentchat.agents import AssistantAgent

agent = AssistantAgent(
    name="assistant",
    tools=[tool],
)
```

## Tool Schema

The `cred_delegate` tool accepts:

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `string` | Service slug (e.g. `google`, `github`) |
| `scopes` | `string[]` | OAuth scopes to request |

`user_id` and `app_client_id` are pre-configured at factory time, not agent-controlled.

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

## Cred Cloud (Coming Soon)

Managed cloud delegation is coming. [Join the waitlist](https://cred.ninja/waitlist).
