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

agent = Agent(
    name="assistant",
    tools=[tool, cred_use_tool(
        agent_token=os.environ["CRED_AGENT_TOKEN"],
        base_url=os.environ["CRED_BASE_URL"],
        agent_identity=identity,
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

By default, `cred_delegate_tool` returns a legacy access token for backwards compatibility. Set `token_format="handle"` to return a brokered delegation id, then use `cred_use_tool` to make allowed service API calls without exposing provider access tokens.

`agent_identity` is required with `token_format="handle"`. The Cred server issues a Delegation Token (a DPoP-bound JWT) to the agent's own key and accepts it only with a DPoP proof signed by that key. The key stays in your process; it is never sent to the model or the server, and it is not a tool argument. The model only sees `delegation_id`: the token itself is kept in an in-process map (`delegation_id` to token and expiry), filled by the delegate tool and read by the use tool, so it never appears in tool output. The use tool raises a clear error if no `agent_identity` is configured or the `delegation_id` is unknown or expired (call the delegate tool again). In a process that serves more than one user, pass `user_id=` to the use tool as well: a use tool configured with a `user_id` refuses delegations issued for any other user. Without it, the user is not checked.

## Handling Consent

When the user hasn't connected the service, the tool raises `ConsentRequiredError`.
The error's `consent_url` attribute contains the URL to redirect the user.

## Brokered Server Mode

Point `CRED_BASE_URL` at your self-hosted `@credninja/server` deployment and set `token_format="handle"` when you want the agent to receive delegation ids instead of provider access tokens.
