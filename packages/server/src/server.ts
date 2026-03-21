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
 *   POST /api/v1/subdelegate              — sub-delegate from a parent receipt (agent, Bearer auth)
 *   DELETE /api/token/:provider           — revoke stored token (agent, Bearer auth)
 */

import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { CredVault, validateSubDelegation, DelegationChainError } from '@credninja/vault';
import { OAuthClient, createAdapter } from '@credninja/oauth';
import type { BuiltinAdapterSlug } from '@credninja/oauth';
import { ServerConfig, ProviderConfig } from './config.js';
import { createExpressMiddleware } from '@credninja/guard';

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

  function writeAuditEventIfSupported(event: Parameters<CredVault['writeAuditEvent']>[0]) {
    try {
      vault.writeAuditEvent(event);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('not supported')) {
        return;
      }
      throw err;
    }
  }

  // ── Receipt helpers (Ed25519, same key derivation as SDK local mode) ──────

  function getReceiptSigningKey() {
    const seed = crypto.createHash('sha256')
      .update(`cred-local-receipt:${config.vaultPassphrase}`)
      .digest();
    return createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        seed,
      ]),
      format: 'der',
      type: 'pkcs8',
    });
  }

  function getReceiptPublicKey() {
    const publicKey = createPublicKey(getReceiptSigningKey());
    return publicKey;
  }

  function createReceipt(input: {
    agentDid: string;
    service: string;
    userId: string;
    appClientId: string;
    scopes: string[];
    delegationId: string;
    chainDepth: number;
    parentDelegationId?: string;
    parentReceiptHash?: string;
  }): string {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:key:local-cred',
      sub: input.agentDid,
      iat: Math.floor(Date.now() / 1000),
      service: input.service,
      scopes: input.scopes,
      userId: input.userId,
      appClientId: input.appClientId,
      delegationId: input.delegationId,
      chainDepth: input.chainDepth,
      ...(input.parentDelegationId ? { parentDelegationId: input.parentDelegationId } : {}),
      ...(input.parentReceiptHash ? { parentReceiptHash: input.parentReceiptHash } : {}),
    })).toString('base64url');

    const signatureInput = Buffer.from(`${header}.${payload}`, 'utf8');
    const signature = sign(null, signatureInput, getReceiptSigningKey()).toString('base64url');
    return `${header}.${payload}.${signature}`;
  }

  function parseAndVerifyReceipt(receipt: string): {
    sub: string;
    service: string;
    scopes: string[];
    userId: string;
    appClientId: string;
    delegationId: string;
    chainDepth: number;
  } {
    const parts = receipt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid receipt format');
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Verify signature
    const signatureInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
    const signatureBuffer = Buffer.from(signatureB64, 'base64url');
    const valid = verify(null, signatureInput, getReceiptPublicKey(), signatureBuffer);
    if (!valid) {
      throw new Error('Invalid receipt signature');
    }

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (!payload.delegationId) {
      throw new Error('Receipt is missing delegationId');
    }

    return {
      sub: payload.sub,
      service: payload.service,
      scopes: payload.scopes ?? [],
      userId: payload.userId ?? 'default',
      appClientId: payload.appClientId ?? 'local',
      delegationId: payload.delegationId,
      chainDepth: payload.chainDepth ?? 0,
    };
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
   * GET /connect — Admin UI for managing provider connections
   *
   * Lists all configured providers with connection status, scope selection,
   * and connect/disconnect buttons.
   */
  app.get('/connect', async (_req: Request, res: Response) => {
    try {
      const entries = await vault.list({ userId: 'default' });
      const connected = new Map(entries.map((e) => [e.provider, e]));

      const COMMON_SCOPES: Record<string, { label: string; value: string }[]> = {
        google: [
          { label: 'OpenID', value: 'openid' },
          { label: 'Email', value: 'email' },
          { label: 'Profile', value: 'profile' },
          { label: 'Gmail (read)', value: 'gmail.readonly' },
          { label: 'Gmail (send)', value: 'gmail.send' },
          { label: 'Gmail (compose)', value: 'gmail.compose' },
          { label: 'Calendar (read)', value: 'calendar.readonly' },
          { label: 'Calendar (events)', value: 'calendar.events' },
          { label: 'Drive (read)', value: 'drive.readonly' },
          { label: 'Drive (full)', value: 'drive' },
          { label: 'Sheets', value: 'spreadsheets' },
          { label: 'Docs', value: 'documents' },
        ],
        github: [
          { label: 'Repos (public)', value: 'public_repo' },
          { label: 'Repos (all)', value: 'repo' },
          { label: 'User', value: 'user' },
          { label: 'Gists', value: 'gist' },
          { label: 'Notifications', value: 'notifications' },
          { label: 'Workflow', value: 'workflow' },
        ],
        slack: [
          { label: 'Chat (write)', value: 'chat:write' },
          { label: 'Channels (read)', value: 'channels:read' },
          { label: 'Users (read)', value: 'users:read' },
          { label: 'Files (write)', value: 'files:write' },
        ],
        notion: [
          { label: 'Read content', value: 'read_content' },
          { label: 'Update content', value: 'update_content' },
          { label: 'Insert content', value: 'insert_content' },
        ],
        salesforce: [
          { label: 'API', value: 'api' },
          { label: 'Refresh token', value: 'refresh_token' },
        ],
        linear: [
          { label: 'Read', value: 'read' },
          { label: 'Write', value: 'write' },
          { label: 'Issues (create)', value: 'issues:create' },
        ],
        hubspot: [
          { label: 'CRM (objects)', value: 'crm.objects.contacts.read' },
          { label: 'CRM (write)', value: 'crm.objects.contacts.write' },
        ],
      };

      const providerCards = config.providers.map((p) => {
        const conn = connected.get(p.slug);
        const isConnected = !!conn;
        const scopes = COMMON_SCOPES[p.slug] ?? [];
        const defaultChecked = p.defaultScopes;

        return `
          <div class="provider-card ${isConnected ? 'connected' : ''}">
            <div class="provider-header">
              <h3>${p.slug}</h3>
              <span class="status ${isConnected ? 'status-ok' : 'status-none'}">
                ${isConnected ? '● Connected' : '○ Not connected'}
              </span>
            </div>
            ${isConnected && conn?.scopes?.length ? `<div class="current-scopes">Current scopes: <code>${conn.scopes.join(', ')}</code></div>` : ''}
            <form class="scope-form" action="/connect/${p.slug}" method="GET" onsubmit="buildScopes(event, '${p.slug}')">
              <div class="scope-grid">
                ${scopes.map((s) => `
                  <label class="scope-item">
                    <input type="checkbox" name="scope" value="${s.value}"
                      ${defaultChecked.includes(s.value) ? 'checked' : ''}>
                    <span class="scope-label">${s.label}</span>
                    <code class="scope-value">${s.value}</code>
                  </label>
                `).join('')}
              </div>
              <div class="custom-scope">
                <input type="text" name="customScopes" placeholder="Additional scopes (comma-separated)">
              </div>
              <div class="actions">
                <button type="submit" class="btn btn-connect">${isConnected ? 'Reconnect' : 'Connect'}</button>
                ${isConnected ? `<button type="button" class="btn btn-revoke" onclick="revoke('${p.slug}')">Revoke</button>` : ''}
              </div>
            </form>
          </div>
        `;
      }).join('');

      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cred — Provider Connections</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #0a0a0a;
    color: #e0e0e0;
    padding: 32px 24px;
    min-height: 100vh;
  }
  .container { max-width: 720px; margin: 0 auto; }
  h1 { font-size: 24px; font-weight: 600; margin-bottom: 4px; }
  .subtitle { color: #888; font-size: 14px; margin-bottom: 32px; }
  .provider-card {
    background: #141414;
    border: 1px solid #222;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 20px;
    transition: border-color 0.2s;
  }
  .provider-card.connected { border-color: #1a3a2a; }
  .provider-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  .provider-header h3 {
    font-size: 18px;
    font-weight: 600;
    text-transform: capitalize;
  }
  .status { font-size: 13px; font-family: monospace; }
  .status-ok { color: #4ade80; }
  .status-none { color: #666; }
  .current-scopes {
    font-size: 12px;
    color: #888;
    margin-bottom: 16px;
    padding: 8px 12px;
    background: #0d0d0d;
    border-radius: 6px;
  }
  .current-scopes code { color: #d4a73a; font-size: 11px; }
  .scope-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 8px;
    margin-bottom: 12px;
  }
  .scope-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: #1a1a1a;
    border: 1px solid #252525;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.15s;
    font-size: 13px;
  }
  .scope-item:hover { border-color: #444; background: #1f1f1f; }
  .scope-item input[type="checkbox"] { accent-color: #4ade80; }
  .scope-label { flex: 1; }
  .scope-value { font-size: 10px; color: #555; }
  .custom-scope { margin-bottom: 16px; }
  .custom-scope input {
    width: 100%;
    padding: 8px 12px;
    background: #1a1a1a;
    border: 1px solid #252525;
    border-radius: 6px;
    color: #e0e0e0;
    font-size: 13px;
    font-family: monospace;
  }
  .custom-scope input:focus { outline: none; border-color: #4ade80; }
  .custom-scope input::placeholder { color: #444; }
  .actions { display: flex; gap: 10px; }
  .btn {
    padding: 8px 20px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
  }
  .btn-connect { background: #166534; color: #fff; }
  .btn-connect:hover { background: #15803d; }
  .btn-revoke { background: #1a1a1a; color: #f87171; border: 1px solid #7f1d1d; }
  .btn-revoke:hover { background: #2a1010; }
  .health { font-size: 12px; color: #444; text-align: center; margin-top: 32px; font-family: monospace; }
  .health a { color: #555; }
</style>
</head>
<body>
<div class="container">
  <h1>Cred</h1>
  <p class="subtitle">Credential delegation for AI agents</p>
  ${providerCards}
  <p class="health"><a href="/health">/health</a> · <a href="/providers">/providers</a></p>
</div>
<script>
function buildScopes(e, provider) {
  e.preventDefault();
  const form = e.target;
  const checked = [...form.querySelectorAll('input[name="scope"]:checked')].map(i => i.value);
  const custom = form.querySelector('input[name="customScopes"]').value;
  if (custom) checked.push(...custom.split(',').map(s => s.trim()).filter(Boolean));
  if (checked.length === 0) {
    alert('Select at least one scope');
    return;
  }
  window.location.href = '/connect/' + provider + '?scopes=' + encodeURIComponent(checked.join(','));
}
async function revoke(provider) {
  if (!confirm('Revoke ' + provider + ' credentials?')) return;
  const token = prompt('Enter agent token to confirm revocation:');
  if (!token) return;
  const res = await fetch('/api/token/' + provider, {
    method: 'DELETE',
    headers: { 'Authorization': 'Bearer ' + token }
  });
  if (res.ok) { alert('Revoked'); location.reload(); }
  else { alert('Failed: ' + res.status); }
}
</script>
</body>
</html>`);
    } catch (err) {
      console.error('[/connect] Error:', err);
      res.status(500).json({ error: 'Failed to render admin UI' });
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

      // Parse scopes from query string, fall back to provider's default scopes from config
      const scopesParam = req.query.scopes as string | undefined;
      const scopes = scopesParam
        ? scopesParam.split(',').map((s) => s.trim())
        : providerConfig.defaultScopes;

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

  // ── Guard middleware (optional) ─────────────────────────────────────────

  /**
   * If a CredGuard instance is provided in config, mount its express middleware
   * on the token delegation route. Guard runs after agent auth, before token
   * retrieval. Denied requests get 403 with policy details.
   */
  const guardMiddleware = config.guard
    ? createExpressMiddleware(config.guard, {
        onDeny: (_req, res, decision) => {
          // Log guard denials for audit
          console.warn(
            `[guard] DENIED — policy: ${decision.deniedBy?.policy}, reason: ${decision.deniedBy?.reason}`
          );
          res.status(403).json({
            error: 'Request denied by guard policy',
            policy: decision.deniedBy?.policy,
            reason: decision.deniedBy?.reason,
          });
        },
      })
    : null;

  /**
   * GET /api/token/:provider — Delegation endpoint (agent-facing)
   *
   * Returns a valid access token for the requested provider.
   * Auto-refreshes expired tokens using the stored refresh token.
   * When guard is configured, policies are evaluated before token retrieval.
   *
   * Auth: Bearer cred_at_<token>
   */
  const tokenRouteHandlers: Array<express.RequestHandler> = [requireAgentAuth];
  if (guardMiddleware) {
    tokenRouteHandlers.push(guardMiddleware);
  }

  app.get('/api/token/:provider', ...tokenRouteHandlers, async (req: Request, res: Response) => {
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
      const guardDecision = (req as any).guardDecision;
      const effectiveScopes = guardDecision?.effectiveScopes ?? entry.scopes ?? [];

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: 'server-agent' },
        action: 'access',
        resource: { type: 'connection', id: `${slug}/default` },
        outcome: 'success',
        scopesGranted: effectiveScopes,
        correlationId: crypto.randomUUID(),
      });

      res.json({
        provider: slug,
        accessToken: entry.accessToken,
        expiresAt: entry.expiresAt?.toISOString() ?? null,
        scopes: effectiveScopes,
        ...(guardDecision && {
          guard: {
            allowed: guardDecision.allowed,
            evaluationMs: guardDecision.evaluationMs,
            policies: guardDecision.results.map((r: any) => ({
              name: r.policy,
              decision: r.decision,
            })),
          },
        }),
      });
    } catch (err) {
      console.error(`[/api/token/${req.params.provider}] Error:`, err);
      res.status(500).json({ error: 'Failed to retrieve token' });
    }
  });

  /**
   * GET /api/v1/audit — query audit events when the vault backend supports audit.
   *
   * Requires Bearer auth. This OSS server stores a single logical user (`default`),
   * so user_id is accepted for SDK parity and filtered against that user.
   */
  app.get('/api/v1/audit', requireAgentAuth, async (req: Request, res: Response) => {
    try {
      const userId = typeof req.query.user_id === 'string' ? req.query.user_id : 'default';
      const service = typeof req.query.service === 'string' ? req.query.service : undefined;
      const limitRaw = typeof req.query.limit === 'string' ? req.query.limit : undefined;
      const limit = limitRaw ? Number.parseInt(limitRaw, 10) : 50;

      if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
        res.status(400).json({ error: 'Invalid limit: must be between 1 and 200' });
        return;
      }

      if (userId !== 'default') {
        res.json({ entries: [] });
        return;
      }

      let events;
      try {
        events = vault.queryAuditEvents({ limit });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('not supported')) {
          res.status(501).json({ error: 'Audit query not supported by this vault backend' });
          return;
        }
        throw err;
      }

      const entries = events
        .filter((event) => {
          const [eventService, eventUserId] = event.resource.id.split('/');
          if (eventUserId !== 'default') return false;
          if (service && eventService !== service) return false;
          return true;
        })
        .map((event) => {
          const [eventService, eventUserId] = event.resource.id.split('/');
          return {
            id: event.id,
            action: event.action,
            service: eventService ?? '',
            userId: eventUserId ?? 'default',
            timestamp: event.timestamp.toISOString(),
            metadata: {
              outcome: event.outcome,
              scopesRequested: event.scopesRequested,
              scopesGranted: event.scopesGranted,
              correlationId: event.correlationId,
              errorMessage: event.errorMessage,
            },
          };
        });

      res.json({ entries });
    } catch (err) {
      console.error('[/api/v1/audit] Error:', err);
      res.status(500).json({ error: 'Failed to fetch audit log' });
    }
  });

  /**
   * POST /api/v1/subdelegate — Sub-delegate from a verified parent receipt
   *
   * Verifies the parent receipt signature, validates delegation chain constraints
   * (scope attenuation, depth limits, service/user/app matching), retrieves a
   * fresh token from the vault, and issues a signed child receipt.
   *
   * Request body:
   *   parent_receipt  — signed parent delegation receipt (JWS)
   *   agent_did       — DID of the child agent
   *   service         — provider slug (must match parent)
   *   user_id         — logical user (must match parent)
   *   appClientId     — app context (must match parent)
   *   scopes          — optional subset of parent scopes
   *
   * Auth: Bearer cred_at_<token>
   */
  app.post('/api/v1/subdelegate', requireAgentAuth, async (req: Request, res: Response) => {
    const correlationId = crypto.randomUUID();
    try {
      const {
        parent_receipt: parentReceipt,
        agent_did: agentDid,
        service,
        user_id: userId = 'default',
        appClientId = 'local',
        scopes: requestedScopes,
      } = req.body as {
        parent_receipt?: string;
        agent_did?: string;
        service?: string;
        user_id?: string;
        appClientId?: string;
        scopes?: string[];
      };

      // ── Input validation ──────────────────────────────────────────────────

      if (!parentReceipt || typeof parentReceipt !== 'string') {
        res.status(400).json({ error: 'parent_receipt is required' });
        return;
      }
      if (!agentDid || typeof agentDid !== 'string') {
        res.status(400).json({ error: 'agent_did is required' });
        return;
      }
      if (!service || typeof service !== 'string') {
        res.status(400).json({ error: 'service is required' });
        return;
      }

      // ── Verify parent receipt ─────────────────────────────────────────────

      let parent;
      try {
        parent = parseAndVerifyReceipt(parentReceipt);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Invalid receipt';
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'delegation', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: message,
          correlationId,
        });
        res.status(403).json({ error: message });
        return;
      }

      // ── Context matching (service, user, app) ────────────────────────────

      if (parent.service !== service) {
        res.status(403).json({ error: 'Service does not match parent receipt' });
        return;
      }
      if (parent.userId !== userId) {
        res.status(403).json({ error: 'User does not match parent receipt' });
        return;
      }
      if (parent.appClientId !== appClientId) {
        res.status(403).json({ error: 'App does not match parent receipt' });
        return;
      }

      // ── Agent status check (if vault supports agents) ────────────────────

      let agentRecord: { id: string; status: string; scopeCeiling: string[] } | null = null;
      if (vault.getAgentByDid) {
        agentRecord = await vault.getAgentByDid(agentDid);
      }
      if (agentRecord?.status === 'revoked') {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'delegation', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: 'Agent is revoked',
          correlationId,
        });
        res.status(403).json({ error: 'Agent has been revoked' });
        return;
      }
      if (agentRecord?.status === 'suspended') {
        res.status(403).json({ error: 'Agent is suspended' });
        return;
      }

      // ── Permission lookup ────────────────────────────────────────────────

      const agentId = agentRecord?.id ?? agentDid;
      const permission = await vault.getPermission?.(agentId, service) ?? null;
      if (!permission) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'delegation', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: `No permission for ${service}`,
          correlationId,
        });
        res.status(403).json({ error: `Agent has no permission for ${service}` });
        return;
      }

      // ── Validate delegation chain ────────────────────────────────────────

      let validation;
      try {
        validation = validateSubDelegation({
          parent: {
            delegationId: parent.delegationId,
            agentDid: parent.sub,
            service: parent.service,
            userId: parent.userId,
            appClientId: parent.appClientId,
            scopesGranted: parent.scopes,
            chainDepth: parent.chainDepth,
          },
          childAgentDid: agentDid,
          service,
          userId,
          appClientId,
          requestedScopes,
          permission: {
            allowedScopes: permission.allowedScopes,
            delegatable: permission.delegatable,
            maxDelegationDepth: permission.maxDelegationDepth,
          },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Delegation chain validation failed';
        const code = err instanceof DelegationChainError ? err.code : 'validation_failed';
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'delegation', id: `${service}/${userId}` },
          outcome: 'denied',
          scopesRequested: requestedScopes,
          errorMessage: message,
          correlationId,
        });
        res.status(403).json({ error: message, code });
        return;
      }

      // ── Retrieve token from vault ────────────────────────────────────────

      const providerConfig = getProviderConfig(service);
      const getOpts: Parameters<typeof vault.get>[0] = {
        provider: service,
        userId: 'default',
      };
      if (providerConfig) {
        const adapter = createAdapter(providerConfig.slug as BuiltinAdapterSlug);
        getOpts.adapter = {
          refreshAccessToken: async (refreshToken, clientId, clientSecret) => {
            const client = new OAuthClient({
              adapter,
              clientId,
              clientSecret,
              redirectUri: `${config.redirectBaseUri}/connect/${service}/callback`,
            });
            const result = await client.refreshToken(refreshToken);
            return {
              accessToken: result.access_token,
              refreshToken: result.refresh_token,
              expiresIn: result.expires_in,
            };
          },
        };
        getOpts.clientId = providerConfig.clientId;
        getOpts.clientSecret = providerConfig.clientSecret;
      }

      const entry = await vault.get(getOpts);
      if (!entry) {
        res.status(404).json({
          error: `No credentials stored for '${service}'. Connect first: GET /connect/${service}`,
        });
        return;
      }

      // ── Issue child receipt ──────────────────────────────────────────────

      const delegationId = `del_${crypto.randomUUID().replace(/-/g, '')}`;
      const parentReceiptHash = crypto.createHash('sha256').update(parentReceipt).digest('hex');

      const receipt = createReceipt({
        agentDid,
        service,
        userId,
        appClientId,
        scopes: validation.grantedScopes,
        delegationId,
        chainDepth: validation.chainDepth,
        parentDelegationId: validation.parentDelegationId,
        parentReceiptHash,
      });

      // ── Audit event ──────────────────────────────────────────────────────

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: agentDid },
        action: 'delegate',
        resource: { type: 'delegation', id: delegationId },
        outcome: 'success',
        scopesRequested: requestedScopes,
        scopesGranted: validation.grantedScopes,
        delegationChain: [
          { delegatorId: parent.sub, delegateeId: agentDid, scopes: validation.grantedScopes },
        ],
        correlationId,
      });

      // ── Response ─────────────────────────────────────────────────────────

      const DEFAULT_TTL_SECONDS = 900;
      const expiresIn = entry.expiresAt
        ? Math.max(0, Math.floor((entry.expiresAt.getTime() - Date.now()) / 1000))
        : DEFAULT_TTL_SECONDS;

      res.json({
        access_token: entry.accessToken,
        token_type: 'Bearer',
        expires_in: expiresIn,
        service,
        scopes: validation.grantedScopes,
        delegation_id: delegationId,
        receipt,
        chain_depth: validation.chainDepth,
        parent_delegation_id: validation.parentDelegationId,
      });
    } catch (err) {
      console.error('[POST /api/v1/subdelegate] Error:', err);
      res.status(500).json({ error: 'Sub-delegation failed' });
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

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: 'server-agent' },
        action: 'revoke',
        resource: { type: 'connection', id: `${slug}/default` },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
      });

      res.status(204).send();
    } catch (err) {
      console.error(`[DELETE /api/token/${req.params.provider}] Error:`, err);
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  return { app, vault };
}
