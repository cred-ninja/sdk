# Deli SDK Usage Examples

## Basic Express.js Integration

```typescript
import express from 'express';
import session from 'express-session';
import { DeliClient } from '@deli/sdk';

const app = express();

// Session middleware
app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: false,
}));

// Initialize Deli client
const deli = new DeliClient({
  clientId: process.env.DELI_CLIENT_ID!,
  clientSecret: process.env.DELI_CLIENT_SECRET,
  redirectUri: 'http://localhost:3000/auth/callback',
  apiUrl: 'https://api.deli.ai',
});

// Start OAuth flow
app.get('/auth/login', (req, res) => {
  const { url, state } = deli.getAuthorizationUrl('openai stripe');
  
  // Store OAuth state in session
  req.session.oauthState = state;
  
  res.redirect(url);
});

// Handle OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  const storedState = req.session.oauthState;
  
  // Verify state (CSRF protection)
  if (!storedState || state !== storedState.state) {
    return res.status(400).send('Invalid state parameter');
  }
  
  try {
    // Exchange authorization code for tokens
    const tokens = await deli.exchangeCodeForToken(
      code as string,
      storedState.codeVerifier
    );
    
    // Store tokens in session
    req.session.tokens = tokens;
    delete req.session.oauthState;
    
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Token exchange failed:', error);
    res.status(500).send('Authentication failed');
  }
});

// Protected route - OpenAI chat
app.get('/api/chat', async (req, res) => {
  if (!req.session.tokens) {
    return res.status(401).send('Not authenticated');
  }
  
  const api = deli.createAPI(req.session.tokens.access_token);
  
  try {
    const response = await api.openai.chatCompletions({
      model: 'gpt-4',
      messages: [
        { role: 'user', content: req.query.message as string }
      ]
    });
    
    res.json(response);
  } catch (error) {
    console.error('OpenAI request failed:', error);
    res.status(500).json({ error: 'Chat request failed' });
  }
});

// Logout
app.get('/auth/logout', async (req, res) => {
  if (req.session.tokens) {
    try {
      await deli.revokeToken(req.session.tokens.access_token);
      await deli.revokeToken(req.session.tokens.refresh_token);
    } catch (error) {
      console.error('Token revocation failed:', error);
    }
  }
  
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

## Next.js Integration

### API Route: `/pages/api/auth/login.ts`

```typescript
import type { NextApiRequest, NextApiResponse } from 'next';
import { DeliClient } from '@deli/sdk';

const deli = new DeliClient({
  clientId: process.env.DELI_CLIENT_ID!,
  clientSecret: process.env.DELI_CLIENT_SECRET,
  redirectUri: process.env.DELI_REDIRECT_URI!,
  apiUrl: process.env.DELI_API_URL,
});

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const { url, state } = deli.getAuthorizationUrl('openai anthropic stripe');
  
  // Store state in cookie (or session)
  res.setHeader('Set-Cookie', `oauth_state=${JSON.stringify(state)}; Path=/; HttpOnly; Secure; SameSite=Lax`);
  
  res.redirect(302, url);
}
```

### API Route: `/pages/api/auth/callback.ts`

```typescript
import type { NextApiRequest, NextApiResponse } from 'next';
import { DeliClient } from '@deli/sdk';
import cookie from 'cookie';

const deli = new DeliClient({
  clientId: process.env.DELI_CLIENT_ID!,
  clientSecret: process.env.DELI_CLIENT_SECRET,
  redirectUri: process.env.DELI_REDIRECT_URI!,
  apiUrl: process.env.DELI_API_URL,
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { code, state } = req.query;
  
  // Retrieve stored state from cookie
  const cookies = cookie.parse(req.headers.cookie || '');
  const storedState = JSON.parse(cookies.oauth_state || '{}');
  
  // Verify state
  if (!storedState.state || state !== storedState.state) {
    return res.status(400).json({ error: 'Invalid state' });
  }
  
  try {
    // Exchange code for tokens
    const tokens = await deli.exchangeCodeForToken(
      code as string,
      storedState.codeVerifier
    );
    
    // Store tokens (use encrypted cookie or database in production)
    res.setHeader('Set-Cookie', [
      `access_token=${tokens.access_token}; Path=/; HttpOnly; Secure; SameSite=Lax`,
      `refresh_token=${tokens.refresh_token}; Path=/; HttpOnly; Secure; SameSite=Lax`,
      'oauth_state=; Path=/; Max-Age=0', // Clear state cookie
    ]);
    
    res.redirect(302, '/dashboard');
  } catch (error) {
    console.error('Token exchange failed:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
}
```

### API Route: `/pages/api/openai/chat.ts`

```typescript
import type { NextApiRequest, NextApiResponse } from 'next';
import { DeliClient } from '@deli/sdk';
import cookie from 'cookie';

const deli = new DeliClient({
  clientId: process.env.DELI_CLIENT_ID!,
  redirectUri: process.env.DELI_REDIRECT_URI!,
  apiUrl: process.env.DELI_API_URL,
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // Get access token from cookie
  const cookies = cookie.parse(req.headers.cookie || '');
  const accessToken = cookies.access_token;
  
  if (!accessToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const api = deli.createAPI(accessToken);
  
  try {
    const response = await api.openai.chatCompletions({
      model: 'gpt-4',
      messages: [
        { role: 'user', content: req.body.message }
      ]
    });
    
    res.json(response);
  } catch (error) {
    console.error('OpenAI request failed:', error);
    res.status(500).json({ error: 'Chat request failed' });
  }
}
```

## Automatic Token Refresh

```typescript
class TokenManager {
  private client: DeliClient;
  private tokens: TokenResponse;
  private refreshPromise: Promise<TokenResponse> | null = null;
  
  constructor(client: DeliClient, initialTokens: TokenResponse) {
    this.client = client;
    this.tokens = initialTokens;
  }
  
  async getAccessToken(): Promise<string> {
    // Check if token is expired or about to expire
    const expiresAt = Date.now() + (this.tokens.expires_in * 1000);
    const shouldRefresh = expiresAt - Date.now() < 60000; // Refresh if < 1 minute
    
    if (shouldRefresh) {
      await this.refreshToken();
    }
    
    return this.tokens.access_token;
  }
  
  private async refreshToken(): Promise<void> {
    // Prevent concurrent refresh requests
    if (this.refreshPromise) {
      await this.refreshPromise;
      return;
    }
    
    try {
      this.refreshPromise = this.client.refreshAccessToken(this.tokens.refresh_token);
      this.tokens = await this.refreshPromise;
      
      // Persist updated tokens (database, session, etc.)
      await this.saveTokens(this.tokens);
    } finally {
      this.refreshPromise = null;
    }
  }
  
  private async saveTokens(tokens: TokenResponse): Promise<void> {
    // Implement token persistence logic
    // e.g., save to database, update session, etc.
  }
}

// Usage
const tokenManager = new TokenManager(deli, initialTokens);
const accessToken = await tokenManager.getAccessToken();
const api = deli.createAPI(accessToken);
```

## Error Handling

```typescript
import { DeliAPIError } from '@deli/sdk';

async function makeRequest() {
  const api = deli.createAPI(accessToken);
  
  try {
    const response = await api.openai.chatCompletions({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hello!' }]
    });
    
    return response;
  } catch (error) {
    if (error instanceof DeliAPIError) {
      // Handle Deli API errors
      console.error('API Error:', error.status, error.data);
      
      if (error.status === 401) {
        // Token expired - redirect to login
        window.location.href = '/auth/login';
      } else if (error.status === 403) {
        // Service not authorized
        console.error('App not authorized for this service');
      } else if (error.status === 429) {
        // Rate limited
        console.error('Rate limit exceeded');
      }
    } else {
      // Handle other errors
      console.error('Unexpected error:', error);
    }
    
    throw error;
  }
}
```

## Environment Variables

Create a `.env.local` file:

```bash
# Deli Configuration
DELI_CLIENT_ID=deli_your_client_id_here
DELI_CLIENT_SECRET=your_client_secret_here
DELI_REDIRECT_URI=http://localhost:3000/auth/callback
DELI_API_URL=https://api.deli.ai

# Session Secret (for express-session)
SESSION_SECRET=your-random-session-secret
```

## Testing

```typescript
import { DeliClient } from '@deli/sdk';

// Mock for testing
const mockClient = new DeliClient({
  clientId: 'test_client_id',
  redirectUri: 'http://localhost:3000/callback',
  apiUrl: 'http://localhost:4000',
});

describe('Deli Integration', () => {
  it('generates authorization URL', () => {
    const { url, state } = mockClient.getAuthorizationUrl('openai');
    
    expect(url).toContain('/oauth/authorize');
    expect(url).toContain('client_id=test_client_id');
    expect(state.codeVerifier).toBeTruthy();
    expect(state.state).toBeTruthy();
  });
});
```
