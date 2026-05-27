# @credninja/ai

Vercel AI SDK integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
npm install @credninja/ai @credninja/sdk ai zod
```

## Quick Start

```typescript
import { credDelegateTool, credUseTool } from '@credninja/ai';
import { generateText } from 'ai';
import { openai } from '@ai-sdk/openai';

const tool = credDelegateTool({
  agentToken: process.env.CRED_AGENT_TOKEN!,
  baseUrl: process.env.CRED_BASE_URL!,
  userId: 'user_123',
  appClientId: 'my_app_client_id',
  tokenFormat: 'handle',
});

const result = await generateText({
  model: openai('gpt-4o'),
  tools: {
    cred_delegate: tool,
    cred_use: credUseTool({
      agentToken: process.env.CRED_AGENT_TOKEN!,
      baseUrl: process.env.CRED_BASE_URL!,
    }),
  },
  prompt: 'Get my Google Calendar events for today',
});
```

## Tool Schema

The `cred_delegate` tool accepts:

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `string` | Service slug (e.g. `google`, `github`) |
| `scopes` | `string[]` | OAuth scopes to request |

`userId` and `appClientId` are pre-configured at factory time, not agent-controlled.

By default, returns an object with `accessToken`, `tokenType`, `expiresIn`, `service`, `scopes`, and `delegationId` for backwards compatibility.

Set `tokenFormat: "handle"` to return a brokered delegation handle instead of a provider access token. Pair it with `credUseTool()` so the model can call allowed service APIs without seeing the token.

### `cred_use`

The `cred_use` tool accepts:

| Parameter | Type | Description |
|-----------|------|-------------|
| `delegationId` | `string` | Brokered handle returned by `cred_delegate` |
| `url` | `string` | Full HTTPS API URL |
| `method` | `GET`, `POST`, `PUT`, `PATCH`, or `DELETE` | HTTP method |
| `body` | `object` | Optional JSON body |
| `extraHeaders` | `object` | Optional service-specific headers |

The Cred server enforces service URL allowlists, delegated scopes, and configured Guard policies before forwarding brokered requests.

## Handling Consent

When the user hasn't connected the service, the tool throws a `ConsentRequiredError`.
The error's `consentUrl` property contains the URL to redirect the user.

```typescript
import { ConsentRequiredError } from '@credninja/sdk';

try {
  const result = await tool.execute({ service: 'google', scopes: ['calendar.readonly'] });
} catch (e) {
  if (e instanceof ConsentRequiredError) {
    console.log(`Redirect user to: ${e.consentUrl}`);
  }
}
```

## Brokered Server Mode

Point `baseUrl` at your self-hosted `@credninja/server` deployment and set `tokenFormat: "handle"` when you want the model to receive delegation handles instead of provider access tokens.
