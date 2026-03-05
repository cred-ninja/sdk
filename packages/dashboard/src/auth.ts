import { Router } from 'express';
import { OAuthClient, createAdapter } from '@credninja/oauth';
import type { CredVault } from '@credninja/vault';
import type { TokenResponse } from '@credninja/oauth';
import { getProvider, getRedirectUri } from './config';

interface PendingAuth {
  provider: string;
  codeVerifier?: string;
}

// In-memory store for pending OAuth flows (keyed by state param)
const pendingFlows = new Map<string, PendingAuth>();

export function createAuthRouter(vault: CredVault): Router {
  const router = Router();

  // GET /connect/:provider - Start OAuth flow
  router.get('/connect/:provider', async (req, res) => {
    try {
      const providerConfig = getProvider(req.params.provider);
      if (!providerConfig) {
        res.redirect('/?flash=error&msg=Unknown+or+unconfigured+provider');
        return;
      }

      const adapter = createAdapter(providerConfig.slug);
      const client = new OAuthClient({
        adapter,
        clientId: providerConfig.clientId,
        clientSecret: providerConfig.clientSecret,
        redirectUri: getRedirectUri(),
      });

      const { url, state, codeVerifier } = await client.getAuthorizationUrl({
        scopes: providerConfig.scopes,
      });

      pendingFlows.set(state, {
        provider: providerConfig.slug,
        codeVerifier,
      });

      // Clean up stale flows after 10 minutes
      setTimeout(() => pendingFlows.delete(state), 10 * 60 * 1000);

      res.redirect(url);
    } catch (err) {
      console.error('Connect error:', err);
      res.redirect('/?flash=error&msg=Failed+to+start+OAuth+flow');
    }
  });

  // GET /callback - OAuth callback
  router.get('/callback', async (req, res) => {
    try {
      const { code, state, error } = req.query as Record<string, string>;

      if (error) {
        res.redirect(`/?flash=error&msg=OAuth+error:+${encodeURIComponent(error)}`);
        return;
      }

      if (!code || !state) {
        res.redirect('/?flash=error&msg=Missing+code+or+state+parameter');
        return;
      }

      const pending = pendingFlows.get(state);
      if (!pending) {
        res.redirect('/?flash=error&msg=Invalid+or+expired+state+parameter');
        return;
      }

      pendingFlows.delete(state);

      const providerConfig = getProvider(pending.provider);
      if (!providerConfig) {
        res.redirect('/?flash=error&msg=Provider+config+not+found');
        return;
      }

      const adapter = createAdapter(providerConfig.slug);
      const client = new OAuthClient({
        adapter,
        clientId: providerConfig.clientId,
        clientSecret: providerConfig.clientSecret,
        redirectUri: getRedirectUri(),
      });

      const tokens: TokenResponse = await client.exchangeCode({
        code,
        codeVerifier: pending.codeVerifier,
      });

      // Calculate expiry
      const expiresAt = tokens.expires_in
        ? new Date(Date.now() + tokens.expires_in * 1000)
        : undefined;

      // Parse scopes
      const scopes = tokens.scope ? tokens.scope.split(/[\s,]+/).filter(Boolean) : providerConfig.scopes;

      // Store in vault
      await vault.store({
        provider: pending.provider,
        userId: 'local',
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt,
        scopes,
      });

      // For Salesforce, store instance_url in a separate metadata entry
      if (tokens.instance_url && pending.provider === 'salesforce') {
        // Store instance URL as a simple credential entry we can retrieve later
        await vault.store({
          provider: 'salesforce_meta',
          userId: 'local',
          accessToken: tokens.instance_url, // abuse accessToken field for metadata
          scopes: ['instance_url'],
        });
      }

      res.redirect(`/?flash=success&msg=${encodeURIComponent(providerConfig.name)}+connected+successfully`);
    } catch (err) {
      console.error('Callback error:', err);
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.redirect(`/?flash=error&msg=${encodeURIComponent('Token exchange failed: ' + message)}`);
    }
  });

  return router;
}
