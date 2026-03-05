import { Router } from 'express';
import { OAuthClient, createAdapter } from '@credninja/oauth';
import type { CredVault } from '@credninja/vault';
import { getConfiguredProviders, getProvider, getRedirectUri, getAgentToken } from './config';
import { renderDashboard, renderTestResult } from './render';

// Test endpoint configs per provider
const TEST_ENDPOINTS: Record<string, {
  method: 'GET' | 'POST';
  url: string | ((instanceUrl: string) => string);
  headers?: Record<string, string>;
  needsInstanceUrl?: boolean;
}> = {
  google: {
    method: 'GET',
    url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events?maxResults=5',
  },
  github: {
    method: 'GET',
    url: 'https://api.github.com/user/repos?per_page=5',
    headers: {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  },
  slack: {
    method: 'POST',
    url: 'https://slack.com/api/auth.test',
  },
  notion: {
    method: 'GET',
    url: 'https://api.notion.com/v1/users/me',
    headers: {
      'Notion-Version': '2022-06-28',
    },
  },
  salesforce: {
    method: 'GET',
    url: (instanceUrl: string) => `${instanceUrl}/services/data/v59.0/sobjects`,
    needsInstanceUrl: true,
  },
};

export function createDashboardRouter(vault: CredVault): Router {
  const router = Router();

  // GET / - Main dashboard
  router.get('/', async (req, res) => {
    try {
      const providers = getConfiguredProviders();
      const credentials = await vault.list({ userId: 'local' });

      // Filter out metadata entries
      const realCredentials = credentials.filter(c => !c.provider.endsWith('_meta'));

      // Parse flash messages from query
      let flash: { type: string; message: string } | undefined;
      if (req.query.flash && req.query.msg) {
        flash = {
          type: req.query.flash as string,
          message: decodeURIComponent(req.query.msg as string),
        };
      }

      res.send(renderDashboard(providers, realCredentials, flash));
    } catch (err) {
      console.error('Dashboard error:', err);
      res.status(500).send('Internal server error');
    }
  });

  // GET /refresh/:provider - Refresh token
  router.get('/refresh/:provider', async (req, res) => {
    try {
      const providerSlug = req.params.provider;
      const providerConfig = getProvider(providerSlug);
      if (!providerConfig) {
        res.redirect('/?flash=error&msg=Unknown+provider');
        return;
      }

      const entry = await vault.get({ provider: providerSlug, userId: 'local' });
      if (!entry || !entry.refreshToken) {
        res.redirect('/?flash=error&msg=No+refresh+token+available');
        return;
      }

      const adapter = createAdapter(providerConfig.slug);
      const client = new OAuthClient({
        adapter,
        clientId: providerConfig.clientId,
        clientSecret: providerConfig.clientSecret,
        redirectUri: getRedirectUri(),
      });

      const refreshed = await client.refreshToken(entry.refreshToken);

      const expiresAt = refreshed.expires_in
        ? new Date(Date.now() + refreshed.expires_in * 1000)
        : undefined;

      await vault.store({
        provider: providerSlug,
        userId: 'local',
        accessToken: refreshed.access_token,
        refreshToken: refreshed.refresh_token || entry.refreshToken,
        expiresAt,
        scopes: entry.scopes,
      });

      res.redirect(`/?flash=success&msg=${encodeURIComponent(providerConfig.name)}+token+refreshed`);
    } catch (err) {
      console.error('Refresh error:', err);
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.redirect(`/?flash=error&msg=${encodeURIComponent('Refresh failed: ' + message)}`);
    }
  });

  // GET /revoke/:provider - Revoke and delete credential
  router.get('/revoke/:provider', async (req, res) => {
    try {
      const providerSlug = req.params.provider;
      const providerConfig = getProvider(providerSlug);
      if (!providerConfig) {
        res.redirect('/?flash=error&msg=Unknown+provider');
        return;
      }

      const entry = await vault.get({ provider: providerSlug, userId: 'local' });
      if (entry) {
        // Try to revoke at provider (best effort)
        try {
          const adapter = createAdapter(providerConfig.slug);
          const client = new OAuthClient({
            adapter,
            clientId: providerConfig.clientId,
            clientSecret: providerConfig.clientSecret,
            redirectUri: getRedirectUri(),
          });
          await client.revokeToken(entry.accessToken);
        } catch {
          // Revocation is best-effort
        }
      }

      // Delete from vault regardless
      await vault.delete({ provider: providerSlug, userId: 'local' });

      // Clean up metadata if present
      if (providerSlug === 'salesforce') {
        await vault.delete({ provider: 'salesforce_meta', userId: 'local' });
      }

      res.redirect(`/?flash=success&msg=${encodeURIComponent(providerConfig.name)}+credential+revoked`);
    } catch (err) {
      console.error('Revoke error:', err);
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.redirect(`/?flash=error&msg=${encodeURIComponent('Revoke failed: ' + message)}`);
    }
  });

  // GET /test/:provider - Test API call
  router.get('/test/:provider', async (req, res) => {
    try {
      const providerSlug = req.params.provider;
      const providerConfig = getProvider(providerSlug);
      if (!providerConfig) {
        res.send(renderTestResult(providerSlug, null, 'Unknown or unconfigured provider'));
        return;
      }

      const entry = await vault.get({ provider: providerSlug, userId: 'local' });
      if (!entry) {
        res.send(renderTestResult(providerConfig.name, null, 'No credentials stored for this provider'));
        return;
      }

      const testConfig = TEST_ENDPOINTS[providerSlug];
      if (!testConfig) {
        res.send(renderTestResult(providerConfig.name, null, 'No test endpoint configured'));
        return;
      }

      let url: string;
      if (typeof testConfig.url === 'function') {
        // Need instance URL (Salesforce)
        const meta = await vault.get({ provider: 'salesforce_meta', userId: 'local' });
        if (!meta) {
          res.send(renderTestResult(providerConfig.name, null, 'No instance URL stored. Reconnect Salesforce.'));
          return;
        }
        url = testConfig.url(meta.accessToken);
      } else {
        url = testConfig.url;
      }

      const headers: Record<string, string> = {
        'Authorization': `Bearer ${entry.accessToken}`,
        'User-Agent': 'cred-dashboard/1.0',
        ...testConfig.headers,
      };

      const response = await fetch(url, {
        method: testConfig.method,
        headers,
      });

      const data = await response.json();
      res.send(renderTestResult(providerConfig.name, data));
    } catch (err) {
      console.error('Test error:', err);
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.send(renderTestResult(req.params.provider, null, `API call failed: ${message}`));
    }
  });

  // GET /api/token/:provider — agent-callable token endpoint
  // Returns a valid access token for the requested provider, auto-refreshing if expired.
  // Requires: Authorization: Bearer <AGENT_TOKEN>
  router.get('/api/token/:provider', async (req, res) => {
    // Auth check
    const agentToken = getAgentToken();
    if (!agentToken) {
      res.status(403).json({ error: 'Agent token API is disabled. Set AGENT_TOKEN to enable.' });
      return;
    }
    const authHeader = req.headers['authorization'] || '';
    const provided = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (provided !== agentToken) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    try {
      const providerSlug = req.params.provider;
      const providerConfig = getProvider(providerSlug);
      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${providerSlug}' not configured` });
        return;
      }

      let entry = await vault.get({ provider: providerSlug, userId: 'local' });
      if (!entry) {
        res.status(404).json({ error: `No credentials stored for provider '${providerSlug}'. Connect via the dashboard first.` });
        return;
      }

      // Auto-refresh if expired or expiring within 5 minutes
      const expiresAt = entry.expiresAt ? new Date(entry.expiresAt) : null;
      const isExpiring = expiresAt ? expiresAt.getTime() - Date.now() < 5 * 60 * 1000 : false;

      if (isExpiring && entry.refreshToken) {
        try {
          const adapter = createAdapter(providerConfig.slug);
          const client = new OAuthClient({
            adapter,
            clientId: providerConfig.clientId,
            clientSecret: providerConfig.clientSecret,
            redirectUri: getRedirectUri(),
          });
          const refreshed = await client.refreshToken(entry.refreshToken);
          const newExpiresAt = refreshed.expires_in
            ? new Date(Date.now() + refreshed.expires_in * 1000)
            : undefined;
          await vault.store({
            provider: providerSlug,
            userId: 'local',
            accessToken: refreshed.access_token,
            refreshToken: refreshed.refresh_token || entry.refreshToken,
            expiresAt: newExpiresAt,
            scopes: entry.scopes,
          });
          // Re-fetch updated entry
          const refreshedEntry = await vault.get({ provider: providerSlug, userId: 'local' });
          if (!refreshedEntry) throw new Error('Entry disappeared after refresh');
          entry = refreshedEntry;
        } catch (refreshErr) {
          console.error('Auto-refresh failed:', refreshErr);
          // Fall through and return the existing (possibly expired) token
          // Let the agent decide how to handle it
        }
      }

      res.json({
        provider: providerSlug,
        accessToken: entry.accessToken,
        expiresAt: entry.expiresAt ?? null,
        scopes: entry.scopes ?? [],
      });
    } catch (err) {
      console.error('Token API error:', err);
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(500).json({ error: message });
    }
  });

  return router;
}
