# Cred

**OAuth2 credential delegation for AI agents.**

Cred lets AI agents request OAuth tokens on behalf of users — without ever handling refresh tokens, storing secrets, or requiring users to paste API keys into prompts.

```typescript
import { Cred, ConsentRequiredError } from '@credninja/sdk';

const cred = new Cred({ agentToken: process.env.CRED_AGENT_TOKEN });

try {
  const { accessToken } = await cred.delegate({
    userId: 'user_123',
    appClientId: 'your_app_id',
    service: 'google',
    scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
  });
  // use accessToken — it's never stored by your agent
} catch (err) {
  if (err instanceof ConsentRequiredError) {
    // redirect user to err.consentUrl to authorize
  }
}
```

## How it works

1. **User consents** — once, via a hosted consent page
2. **Cred stores the refresh token** — encrypted at rest, never returned to agents
3. **Agent requests access** — Cred issues a fresh access token on demand
4. **Token is used and discarded** — your agent never persists credentials

## Packages

| Package | Language | Install |
|---------|----------|---------|
| [`@credninja/sdk`](./packages/sdk) | TypeScript / Node.js | `npm install @credninja/sdk` |
| [`cred-auth`](./packages/sdk-python) | Python | `pip install cred-auth` |
| [`cred-langchain`](./packages/integrations/langchain) | Python / LangChain | `pip install cred-langchain` |
| [`cred-crewai`](./packages/integrations/crewai) | Python / CrewAI | `pip install cred-crewai` |
| [`cred-openai-agents`](./packages/integrations/openai-agents) | Python / OpenAI Agents SDK | `pip install cred-openai-agents` |
| [`@credninja/mcp`](./packages/mcp) | MCP Server (Claude Desktop) | `npx @credninja/mcp` |

## Quickstart

### TypeScript

```typescript
import { Cred } from '@credninja/sdk';

const cred = new Cred({ agentToken: 'your_agent_token' });

const { accessToken } = await cred.delegate({
  userId: 'user_123',
  appClientId: 'your_app_id',
  service: 'github',
  scopes: ['repo'],
});
```

### Python

```python
from cred_auth import Cred, ConsentRequiredError

cred = Cred(agent_token="your_agent_token")

try:
    result = cred.delegate(
        user_id="user_123",
        app_client_id="your_app_id",
        service="google",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    access_token = result.access_token
except ConsentRequiredError as e:
    print(f"User needs to authorize: {e.consent_url}")
```

### LangChain

```python
from cred_langchain import CredToolkit
from langchain.agents import initialize_agent

toolkit = CredToolkit(
    agent_token="your_agent_token",
    user_id="user_123",
)
tools = toolkit.get_tools()
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
```

### CrewAI

```python
from cred_crewai import CredTool

tool = CredTool(
    agent_token="your_agent_token",
    user_id="user_123",
    service="google",
    app_client_id="your_app_id",
    scopes=["https://www.googleapis.com/auth/calendar.readonly"],
)
```

### OpenAI Agents SDK

```python
from cred_openai_agents import cred_delegate_tool
from agents import Agent

tool = cred_delegate_tool(
    agent_token="your_agent_token",
    user_id="user_123",
    app_client_id="your_app_id",
)
agent = Agent(name="my_agent", tools=[tool])
```

## Supported services

| Service | Scopes |
|---------|--------|
| Google | Gmail, Calendar, Drive, and all Google OAuth scopes |
| GitHub | repo, read:user, and all GitHub OAuth scopes |
| Slack | channels:read, chat:write, and all Slack OAuth scopes |
| Notion | read_content, update_content, and all Notion OAuth scopes |
| Salesforce | api, refresh_token, and all Salesforce OAuth scopes |

## Self-hosting

Cred is split into two parts:

- **This repo** (MIT) — SDKs and integrations. Use these with the hosted Cred API or your own deployment.
- **Cred API + Portal** (proprietary) — The hosted service at [cred.ninja](https://cred.ninja). Handles token storage, encryption, consent flows, and OAuth provider management.

To use the hosted service, sign up at [cred.ninja](https://cred.ninja) and grab an agent token.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). All SDK and integration contributions welcome.

## Security

See [SECURITY.md](./SECURITY.md) for our vulnerability disclosure policy.

## License

MIT — see [LICENSE](./LICENSE).
