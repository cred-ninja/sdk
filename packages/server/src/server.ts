/**
 * @credninja/server — Self-hosted credential delegation server
 *
 * A complete, runnable HTTP server that stores OAuth tokens in an encrypted
 * vault and serves delegated access tokens to authenticated agents.
 *
 * Designed to run on a separate host from the AI agent for true credential
 * isolation. In production, place behind a TLS reverse proxy (Caddy/nginx).
 *
 * Endpoints:
 *   GET  /health                          — liveness check
 *   GET  /providers                       — list configured providers
 *   GET  /connect/:provider               — start OAuth flow (browser)
 *   GET  /connect/:provider/callback      — OAuth callback (browser)
 *   GET  /api/token/:provider             — get delegated token (agent, Bearer auth)
 *   DELETE /api/token/:provider           — revoke stored token (agent, Bearer auth)
 */

import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { CredVault } from '@credninja/vault';
import { OAuthClient, createAdapter } from '@credninja/oauth';
import type { BuiltinAdapterSlug } from '@credninja/oauth';
import { ServerConfig, ProviderConfig } from './config.js';

// ── Types ────────────────────────────────────────────────────────────────────

interface PendingOAuth {
  provider: string;
  state: string;
  codeVerifier?: string;
  createdAt: number;
}

// ── Server factory ───────────────────────────────────────────────────────────

export function createServer(config: ServerConfig) {
  const app = express();
  app.use(express.json());

  // ── State ──────────────────────────────────────────────────────────────────

  const vault = new CredVault({
    passphrase: config.vaultPassphrase,
    storage: config.vaultStorage,
    path: config.vaultPath,
  });

  // In-memory map of provider slug → ProviderConfig
  const providerMap = new Map<string, ProviderConfig>();
  for (const p of config.providers) {
    providerMap.set(p.slug, p);
  }

  // Pending OAuth sessions (state → PendingOAuth). Cleaned up after 10 min.
  const pendingOAuth = new Map<string, PendingOAuth>();

  // Hash the agent token once at startup for constant-time comparison
  const agentTokenHash = crypto.createHash('sha256').update(config.agentToken).digest('hex');

  // ── Helpers ────────────────────────────────────────────────────────────────

  function getProviderConfig(slug: string): ProviderConfig | undefined {
    return providerMap.get(slug);
  }

  function makeOAuthClient(providerConfig: ProviderConfig): OAuthClient {
    const adapter = createAdapter(providerConfig.slug);
    return new OAuthClient({
      adapter,
      clientId: providerConfig.clientId,
      clientSecret: providerConfig.clientSecret,
      redirectUri: `${config.redirectBaseUri}/connect/${providerConfig.slug}/callback`,
    });
  }

  /**
   * Validate agent Bearer token. Constant-time comparison via hash.
   */
  function validateAgentToken(req: Request): boolean {
    const auth = req.headers.authorization ?? '';
    if (!auth.startsWith('Bearer ')) return false;
    const token = auth.slice(7).trim();
    if (!token) return false;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(tokenHash, 'hex'), Buffer.from(agentTokenHash, 'hex'));
  }

  /**
   * Agent auth middleware for /api/* routes.
   */
  function requireAgentAuth(req: Request, res: Response, next: NextFunction) {
    if (!validateAgentToken(req)) {
      res.status(401).json({ error: 'Unauthorized. Provide a valid Bearer token.' });
      return;
    }
    next();
  }

  /**
   * Clean up expired pending OAuth sessions (older than 10 minutes).
   */
  function cleanPendingOAuth() {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [state, pending] of pendingOAuth) {
      if (pending.createdAt < cutoff) {
        pendingOAuth.delete(state);
      }
    }
  }

  // ── Routes ─────────────────────────────────────────────────────────────────

  /**
   * GET /health — liveness check
   */
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      providers: config.providers.map((p) => p.slug),
      vault: config.vaultStorage,
    });
  });

  /**
   * GET /providers — list configured providers and connection status
   */
  app.get('/providers', async (_req: Request, res: Response) => {
    try {
      const entries = await vault.list({ userId: 'default' });
      const connected = new Set(entries.map((e) => e.provider));

      const providers = config.providers.map((p) => ({
        slug: p.slug,
        connected: connected.has(p.slug),
      }));

      res.json({ providers });
    } catch (err) {
      console.error('[/providers] Error:', err);
      res.status(500).json({ error: 'Failed to list providers' });
    }
  });

  /**
   * GET /connect/:provider — start OAuth flow
   *
   * Opens in a browser. Redirects to the provider's authorization page.
   * Scopes can be specified via ?scopes=calendar.readonly,gmail.readonly
   */
  app.get('/connect/:provider', async (req: Request, res: Response) => {
    try {
      const slug = req.params.provider;
      const providerConfig = getProviderConfig(slug);
      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${slug}' not configured. Available: ${config.providers.map((p) => p.slug).join(', ')}` });
        return;
      }

      const client = makeOAuthClient(providerConfig);

      // Parse scopes from query string, or use a sensible empty array
      const scopesParam = req.query.scopes as string | undefined;
      const scopes = scopesParam ? scopesParam.split(',').map((s) => s.trim()) : [];

      const { url, state, codeVerifier } = await client.getAuthorizationUrl({ scopes });

      // Store pending session
      cleanPendingOAuth();
      pendingOAuth.set(state, {
        provider: slug,
        state,
        codeVerifier,
        createdAt: Date.now(),
      });

      res.redirect(url);
    } catch (err) {
      console.error('[/connect] Error:', err);
      res.status(500).json({ error: 'Failed to start OAuth flow' });
    }
  });

  /**
   * GET /connect/:provider/callback — OAuth callback
   *
   * Handles the redirect from the provider, exchanges the code for tokens,
   * and stores them encrypted in the vault.
   */
  app.get('/connect/:provider/callback', async (req: Request, res: Response) => {
    try {
      const slug = req.params.provider;
      const { code, state, error: oauthError } = req.query as Record<string, string>;

      if (oauthError) {
        res.status(400).send(`<h2>OAuth Error</h2><p>${oauthError}</p><p><a href="/providers">Back</a></p>`);
        return;
      }

      if (!code || !state) {
        res.status(400).json({ error: 'Missing code or state parameter' });
        return;
      }

      // Look up pending session
      const pending = pendingOAuth.get(state);
      if (!pending || pending.provider !== slug) {
        res.status(400).json({ error: 'Invalid or expired OAuth state. Try connecting again.' });
        return;
      }
      pendingOAuth.delete(state);

      const providerConfig = getProviderConfig(slug);
      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${slug}' not configured` });
        return;
      }

      const client = makeOAuthClient(providerConfig);
      const tokens = await client.exchangeCode({
        code,
        codeVerifier: pending.codeVerifier,
      });

      // Store in vault
      const expiresAt = tokens.expires_in
        ? new Date(Date.now() + tokens.expires_in * 1000)
        : undefined;

      const scopes = tokens.scope ? tokens.scope.split(/[\s,]+/) : [];

      await vault.store({
        provider: slug,
        userId: 'default',
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt,
        scopes,
      });

      console.log(`[connect] ✅ ${slug} connected successfully`);

      res.send(`
        <html>
        <body style="background:#0a0a0a;color:#fff;font-family:monospace;padding:40px;text-align:center;">
          <h2>✅ ${slug} connected</h2>
          <p>Tokens stored in encrypted vault.</p>
          <p style="color:#888;">You can close this window.</p>
          <p><a href="/providers" style="color:#4ade80;">← Back to providers</a></p>
        </body>
        </html>
      `);
    } catch (err) {
      console.error('[/callback] Error:', err);
      res.status(500).send(`<h2>Connection Failed</h2><p>${err instanceof Error ? err.message : 'Unknown error'}</p><p><a href="/providers">Try again</a></p>`);
    }
  });

  /**
   * GET /api/token/:provider — Delegation endpoint (agent-facing)
   *
   * Returns a valid access token for the requested provider.
   * Auto-refreshes expired tokens using the stored refresh token.
   *
   * Auth: Bearer cred_at_<token>
   */
  app.get('/api/token/:provider', requireAgentAuth, async (req: Request, res: Response) => {
    try {
      const slug = req.params.provider;
      const providerConfig = getProviderConfig(slug);

      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${slug}' not configured` });
        return;
      }

      // Retrieve from vault with auto-refresh
      const adapter = createAdapter(providerConfig.slug as BuiltinAdapterSlug);
      const entry = await vault.get({
        provider: slug,
        userId: 'default',
        adapter: {
          refreshAccessToken: async (refreshToken, clientId, clientSecret) => {
            const client = new OAuthClient({
              adapter,
              clientId,
              clientSecret,
              redirectUri: `${config.redirectBaseUri}/connect/${slug}/callback`,
            });
            const result = await client.refreshToken(refreshToken);
            return {
              accessToken: result.access_token,
              refreshToken: result.refresh_token,
              expiresIn: result.expires_in,
            };
          },
        },
        clientId: providerConfig.clientId,
        clientSecret: providerConfig.clientSecret,
      });

      if (!entry) {
        res.status(404).json({
          error: `No credentials stored for '${slug}'. Connect first: GET /connect/${slug}`,
        });
        return;
      }

      // Return the delegated token — never the refresh token
      res.json({
        provider: slug,
        accessToken: entry.accessToken,
        expiresAt: entry.expiresAt?.toISOString() ?? null,
        scopes: entry.scopes ?? [],
      });
    } catch (err) {
      console.error(`[/api/token/${req.params.provider}] Error:`, err);
      res.status(500).json({ error: 'Failed to retrieve token' });
    }
  });

  /**
   * DELETE /api/token/:provider — Revoke stored credentials
   *
   * Deletes the provider's tokens from the vault.
   * Auth: Bearer cred_at_<token>
   */
  app.delete('/api/token/:provider', requireAgentAuth, async (req: Request, res: Response) => {
    try {
      const slug = req.params.provider;
      await vault.delete({ provider: slug, userId: 'default' });
      res.status(204).send();
    } catch (err) {
      console.error(`[DELETE /api/token/${req.params.provider}] Error:`, err);
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  return { app, vault };
}
