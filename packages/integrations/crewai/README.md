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
    user_id="user_123",
    service="google",
    app_client_id="my_app_client_id",
    scopes=["calendar.readonly"],
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

One `CredTool` per service per agent = clearer intent, smaller decision space for the LLM.

## Handling Consent

When a user hasn't connected the service yet, `_run()` raises `ConsentRequiredError`.
Catch it and redirect the user to `e.consent_url` to complete the OAuth flow.

## Cred Cloud (Coming Soon)

Managed cloud delegation is coming. [Join the waitlist](https://cred.ninja/waitlist).
