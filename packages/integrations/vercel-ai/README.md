# @credninja/ai

Vercel AI SDK integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
npm install @credninja/ai @credninja/sdk ai zod
```

## Quick Start

```typescript
import { credDelegateTool } from '@credninja/ai';
import { generateText } from 'ai';
import { openai } from '@ai-sdk/openai';

const tool = credDelegateTool({
  agentToken: process.env.CRED_AGENT_TOKEN!,
  userId: 'user_123',
  appClientId: 'my_app_client_id',
});

const result = await generateText({
  model: openai('gpt-4o'),
  tools: { cred_delegate: tool },
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

Returns an object with `accessToken`, `tokenType`, `expiresIn`, `service`, `scopes`, and `delegationId`.

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

## Cred Cloud (Coming Soon)

Managed cloud delegation is coming. [Join the waitlist](https://cred.ninja/waitlist).
