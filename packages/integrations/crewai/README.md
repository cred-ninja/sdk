# cred-crewai

CrewAI integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-crewai
```

## Quick Start

```python
import os
from cred_crewai import CredTool, CredUseTool
from crewai import Agent
from cred import AgentIdentity

# The agent's own did:key identity, created once with cred.generate_agent_identity()
# and persisted with identity.export(); load_agent_identity() stands for your own
# secret store lookup returning that dict.
identity = AgentIdentity.from_export(load_agent_identity())

# Create a pre-configured tool for Google Calendar
google_tool = CredTool(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    base_url=os.environ["CRED_BASE_URL"],
    user_id="user_123",
    service="google",
    app_client_id="my_app_client_id",
    scopes=["calendar.readonly"],
    token_format="handle",
    agent_identity=identity,
)
use_tool = CredUseTool(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    base_url=os.environ["CRED_BASE_URL"],
    agent_identity=identity,
)

# Use with CrewAI agent
agent = Agent(
    role="Calendar Manager",
    goal="Manage user's calendar",
    tools=[google_tool, use_tool],
)
```

## Key Differences from LangChain

**LangChain integration** (`cred-langchain`):
- `CredToolkit` returns 3 generic tools: delegate, status, revoke
- Best for agents that need full credential management

**CrewAI integration** (`cred-crewai`):
- `CredTool` is pre-configured for a **single service**
- Tool name auto-generated: `cred_google_delegate`, `cred_github_delegate`, etc.
- Best for specialized agents (e.g., a "Calendar Manager" agent only needs Google tokens)

Set `token_format="handle"` to return a brokered delegation id instead of a provider access token. Pair it with `CredUseTool` when the agent needs to call service APIs through Cred.

`agent_identity` is required with `token_format="handle"`. The Cred server issues a Delegation Token (a DPoP-bound JWT) to the agent's own key and accepts it only with a DPoP proof signed by that key. The key stays in your process; it is never sent to the model or the server, and it is not a tool argument. The model only sees `delegation_id`: the token itself is kept in an in-process map (`delegation_id` to token and expiry), filled by the delegate tool and read by the use tool, so it never appears in tool output. The use tool raises a clear error if no `agent_identity` is configured or the `delegation_id` is unknown or expired (call the delegate tool again). In a process that serves more than one user, pass `user_id=` to the use tool as well: a use tool configured with a `user_id` refuses delegations issued for any other user. Without it, the user is not checked.

One `CredTool` per service per agent = clearer intent, smaller decision space for the LLM.

## Handling Consent

When a user hasn't connected the service yet, `_run()` raises `ConsentRequiredError`.
Catch it and redirect the user to `e.consent_url` to complete the OAuth flow.

## Brokered Server Mode

Point `CRED_BASE_URL` at your self-hosted `@credninja/server` deployment and set `token_format="handle"` when you want the agent to receive delegation ids instead of provider access tokens.
