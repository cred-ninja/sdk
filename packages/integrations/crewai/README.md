# cred-crewai

CrewAI integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-crewai
```

## Quick Start

```python
import os
from cred_crewai import CredTool
from crewai import Agent

# Create a pre-configured tool for Google Calendar
google_tool = CredTool(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    base_url=os.environ["CRED_BASE_URL"],
    user_id="user_123",
    service="google",
    app_client_id="my_app_client_id",
    scopes=["calendar.readonly"],
    token_format="handle",
)

# Use with CrewAI agent
agent = Agent(
    role="Calendar Manager",
    goal="Manage user's calendar",
    tools=[google_tool],
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

Set `token_format="handle"` to return a brokered delegation handle instead of a provider access token. Pair it with `CredUseTool` when the agent needs to call service APIs through Cred.

One `CredTool` per service per agent = clearer intent, smaller decision space for the LLM.

## Handling Consent

When a user hasn't connected the service yet, `_run()` raises `ConsentRequiredError`.
Catch it and redirect the user to `e.consent_url` to complete the OAuth flow.

## Brokered Server Mode

Point `CRED_BASE_URL` at your self-hosted `@credninja/server` deployment and set `token_format="handle"` when you want the agent to receive delegation handles instead of provider access tokens.
