# @deli/sdk

TypeScript/JavaScript SDK for integrating Deli OAuth and API proxy into your applications.

## Installation

```bash
npm install @deli/sdk
```

## Quick Start

### 1. Initialize the Client

```typescript
import { DeliClient } from '@deli/sdk';

const client = new DeliClient({
  clientId: 'your_client_id',
  clientSecret: 'your_client_secret', // Optional for public clients
  redirectUri: 'https://yourapp.com/auth/callback',
  apiUrl: 'https://api.withdeli.com', // Optional, defaults to https://api.withdeli.com
});
```

### 2. Start OAuth Flow

```typescript
// Generate authorization URL
const { url, state } = client.getAuthorizationUrl('openai anthropic');

// Store the state (codeVerifier and state) securely
// Redirect user to the authorization URL
res.redirect(url);
```

### 3. Handle Callback

```typescript
// In your /auth/callback route
const { code, state: returnedState } = req.query;

// Verify state matches (CSRF protection)
if (returnedState !== storedState.state) {
  throw new Error('Invalid state');
}

// Exchange code for tokens
const tokens = await client.exchangeCodeForToken(
  code,
  storedState.codeVerifier
);

// tokens = {
//   access_token: '...',
//   refresh_token: '...',
//   expires_in: 3600,
//   token_type: 'Bearer',
//   scope: 'openai anthropic'
// }
```

### 4. Make API Requests

```typescript
// Create API client
const api = client.createAPI(tokens.access_token);

// OpenAI example
const chatResponse = await api.openai.chatCompletions({
  model: 'gpt-4',
  messages: [
    { role: 'user', content: 'Hello!' }
  ]
});

// Anthropic example
const anthropicResponse = await api.anthropic.messages({
  model: 'claude-3-opus-20240229',
  max_tokens: 1024,
  messages: [
    { role: 'user', content: 'Hello!' }
  ]
});

// Stripe example
const customer = await api.stripe.customers.create({
  email: 'customer@example.com',
  name: 'John Doe'
});

// GitHub example
const user = await api.github.user();
```

### 5. Generic Requests

For services without helpers, use the generic `request` method:

```typescript
const response = await api.request('openai', '/models', {
  method: 'GET'
});

const completion = await api.request('openai', '/chat/completions', {
  method: 'POST',
  body: {
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'Hello!' }]
  }
});
```

### 6. Token Refresh

```typescript
// When access token expires, refresh it
const newTokens = await client.refreshAccessToken(tokens.refresh_token);

// Update stored tokens
updateStoredTokens(newTokens);
```

### 7. Revoke Tokens

```typescript
// Revoke access token
await client.revokeToken(tokens.access_token, 'access_token');

// Revoke refresh token
await client.revokeToken(tokens.refresh_token, 'refresh_token');
```

## API Reference

### `DeliClient`

Main OAuth client for authorization flow.

#### Constructor

```typescript
new DeliClient(config: DeliClientConfig)
```

**Config Options:**
- `clientId` (required): Your Deli app client ID
- `clientSecret` (optional): Your client secret (for confidential clients)
- `redirectUri` (required): OAuth callback URL
- `apiUrl` (optional): Deli API base URL (default: `https://api.withdeli.com`)

#### Methods

##### `getAuthorizationUrl(scope?: string)`

Generate authorization URL for user to visit.

**Returns:** `{ url: string, state: OAuthState }`
- Store `state` securely (contains `codeVerifier` and CSRF `state`)
- Redirect user to `url`

##### `exchangeCodeForToken(code: string, codeVerifier: string)`

Exchange authorization code for access token.

**Returns:** `Promise<TokenResponse>`

##### `refreshAccessToken(refreshToken: string)`

Refresh an expired access token.

**Returns:** `Promise<TokenResponse>`

##### `revokeToken(token: string, tokenTypeHint?: string)`

Revoke an access or refresh token.

**Returns:** `Promise<void>`

##### `createAPI(accessToken: string)`

Create a DeliAPI instance for making proxied requests.

**Returns:** `DeliAPI`

---

### `DeliAPI`

API client for making proxied requests to external services.

#### Constructor

```typescript
new DeliAPI(config: DeliAPIConfig)
```

**Config Options:**
- `accessToken` (required): OAuth access token
- `apiUrl` (optional): Deli API base URL

#### Generic Methods

##### `request<T>(service: string, path: string, options?: RequestOptions)`

Make a proxied request to any service.

**Parameters:**
- `service`: Service slug (e.g., `'openai'`, `'stripe'`)
- `path`: Path relative to service base URL (e.g., `'/chat/completions'`)
- `options`: Request options (method, headers, body, params)

**Returns:** `Promise<T>`

##### `get<T>(service: string, path: string, params?: Record<string, string>)`

Convenience method for GET requests.

##### `post<T>(service: string, path: string, body: any)`

Convenience method for POST requests.

##### `put<T>(service: string, path: string, body: any)`

Convenience method for PUT requests.

##### `patch<T>(service: string, path: string, body: any)`

Convenience method for PATCH requests.

##### `delete<T>(service: string, path: string)`

Convenience method for DELETE requests.

#### Service Helpers

##### OpenAI

```typescript
api.openai.chatCompletions(body)
api.openai.completions(body)
api.openai.embeddings(body)
```

##### Anthropic

```typescript
api.anthropic.messages(body)
```

##### Stripe

```typescript
api.stripe.customers.create(body)
api.stripe.customers.retrieve(id)
api.stripe.customers.list(params)
api.stripe.charges.create(body)
api.stripe.charges.retrieve(id)
```

##### GitHub

```typescript
api.github.user()
api.github.repos(username)
```

## Error Handling

```typescript
import { DeliAPIError } from '@deli/sdk';

try {
  const response = await api.openai.chatCompletions({ ... });
} catch (error) {
  if (error instanceof DeliAPIError) {
    console.error('Status:', error.status);
    console.error('Error:', error.data);
  }
}
```

## Full Example: Express App

```typescript
import express from 'express';
import { DeliClient } from '@deli/sdk';

const app = express();
const client = new DeliClient({
  clientId: process.env.DELI_CLIENT_ID!,
  clientSecret: process.env.DELI_CLIENT_SECRET,
  redirectUri: 'http://localhost:3000/auth/callback',
});

// In-memory session storage (use Redis in production)
const sessions = new Map();

// Start OAuth flow
app.get('/auth/login', (req, res) => {
  const { url, state } = client.getAuthorizationUrl('openai');
  
  // Store state in session
  const sessionId = Math.random().toString(36);
  sessions.set(sessionId, state);
  res.cookie('session', sessionId);
  
  res.redirect(url);
});

// Handle OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  const sessionId = req.cookies.session;
  const storedState = sessions.get(sessionId);
  
  // Verify state
  if (!storedState || state !== storedState.state) {
    return res.status(400).send('Invalid state');
  }
  
  // Exchange code for token
  const tokens = await client.exchangeCodeForToken(
    code as string,
    storedState.codeVerifier
  );
  
  // Store tokens
  sessions.set(sessionId, { ...storedState, tokens });
  
  res.redirect('/dashboard');
});

// Use the API
app.get('/api/chat', async (req, res) => {
  const sessionId = req.cookies.session;
  const session = sessions.get(sessionId);
  
  if (!session?.tokens) {
    return res.status(401).send('Not authenticated');
  }
  
  const api = client.createAPI(session.tokens.access_token);
  
  const response = await api.openai.chatCompletions({
    model: 'gpt-4',
    messages: [{ role: 'user', content: req.query.message }]
  });
  
  res.json(response);
});

app.listen(3000);
```

## Security Best Practices

1. **Store tokens securely** - Use encrypted session storage or database
2. **Verify state parameter** - Prevents CSRF attacks
3. **Use HTTPS** - Always use HTTPS in production for redirect URIs
4. **Rotate refresh tokens** - Implement refresh token rotation
5. **Handle token expiration** - Automatically refresh when access token expires
6. **Revoke on logout** - Call `revokeToken()` when user logs out

## TypeScript Support

The SDK is written in TypeScript and includes full type definitions.

```typescript
import { DeliClient, TokenResponse, OAuthState } from '@deli/sdk';

const client: DeliClient = new DeliClient({ ... });
const tokens: TokenResponse = await client.exchangeCodeForToken(...);
```

## License

MIT
