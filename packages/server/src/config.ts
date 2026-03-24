/**
 * @credninja/server — Configuration
 *
 * Loads server configuration from environment variables.
 * Call loadConfig() after dotenv (or process.env is populated).
 */

import type { BuiltinAdapterSlug } from '@credninja/oauth';
import type { CredGuard } from '@credninja/guard';

export interface ProviderConfig {
  slug: BuiltinAdapterSlug;
  clientId: string;
  clientSecret: string;
  defaultScopes: string[];
}

export interface ServerConfig {
  port: number;
  host: string;

  // Vault
  vaultPassphrase: string;
  vaultStorage: 'sqlite' | 'file';
  vaultPath: string;

  // TOFU identity storage
  tofuStorage: 'sqlite' | 'file';
  tofuPath: string;

  // Agent auth
  agentToken: string;

  // OAuth providers (only those with both clientId and clientSecret)
  providers: ProviderConfig[];

  // Redirect base URI (e.g. http://localhost:3456 or https://cred.example.com)
  redirectBaseUri: string;

  // Guard — optional policy engine for credential delegation guardrails
  // When provided, evaluates policies before serving delegated tokens.
  guard?: CredGuard;

  // Web Bot Auth ingress verification mode
  webBotAuthMode?: 'off' | 'optional' | 'require';
  webBotAuthNonceStore?: 'memory' | 'sqlite';
  webBotAuthNoncePath?: string;
}

const KNOWN_PROVIDERS: { env: string; slug: BuiltinAdapterSlug }[] = [
  { env: 'GOOGLE', slug: 'google' },
  { env: 'GITHUB', slug: 'github' },
  { env: 'SLACK', slug: 'slack' },
  { env: 'NOTION', slug: 'notion' },
  { env: 'SALESFORCE', slug: 'salesforce' },
  { env: 'LINEAR', slug: 'linear' },
  { env: 'HUBSPOT', slug: 'hubspot' },
];

export function loadConfig(): ServerConfig {
  const port = parseInt(process.env.PORT ?? '3456', 10);
  const host = process.env.HOST ?? '127.0.0.1';

  const vaultPassphrase = process.env.VAULT_PASSPHRASE;
  if (!vaultPassphrase) {
    throw new Error('VAULT_PASSPHRASE is required. Generate one: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }

  const vaultStorage = (process.env.VAULT_STORAGE ?? 'file') as 'sqlite' | 'file';
  const vaultPath = process.env.VAULT_PATH ?? './data/vault.json';
  const tofuStorage = (process.env.TOFU_STORAGE ?? vaultStorage) as 'sqlite' | 'file';
  const tofuPath = process.env.TOFU_PATH ?? (tofuStorage === 'sqlite' ? './data/tofu.sqlite' : './data/tofu.json');

  const agentToken = process.env.AGENT_TOKEN;
  if (!agentToken) {
    throw new Error(
      'AGENT_TOKEN is required. Generate one: node -e "console.log(\'cred_at_\' + require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  if (!agentToken.startsWith('cred_at_')) {
    throw new Error('AGENT_TOKEN must start with cred_at_');
  }

  const redirectBaseUri = process.env.REDIRECT_BASE_URI ?? `http://localhost:${port}`;
  const webBotAuthMode = (process.env.WEB_BOT_AUTH_MODE ?? 'off') as 'off' | 'optional' | 'require';
  if (!['off', 'optional', 'require'].includes(webBotAuthMode)) {
    throw new Error('WEB_BOT_AUTH_MODE must be one of: off, optional, require');
  }
  const webBotAuthNonceStore = (process.env.WEB_BOT_AUTH_NONCE_STORE ?? 'memory') as 'memory' | 'sqlite';
  if (!['memory', 'sqlite'].includes(webBotAuthNonceStore)) {
    throw new Error('WEB_BOT_AUTH_NONCE_STORE must be one of: memory, sqlite');
  }
  const webBotAuthNoncePath = process.env.WEB_BOT_AUTH_NONCE_PATH
    ?? (webBotAuthNonceStore === 'sqlite' ? './data/web-bot-auth-nonces.sqlite' : undefined);

  // Discover configured providers from environment
  const providers: ProviderConfig[] = [];
  for (const { env, slug } of KNOWN_PROVIDERS) {
    const clientId = process.env[`${env}_CLIENT_ID`];
    const clientSecret = process.env[`${env}_CLIENT_SECRET`];
    if (clientId && clientSecret) {
      const defaultScopesRaw = process.env[`${env}_DEFAULT_SCOPES`] ?? '';
      const defaultScopes = defaultScopesRaw
        ? defaultScopesRaw.split(',').map((s) => s.trim()).filter(Boolean)
        : [];
      providers.push({ slug, clientId, clientSecret, defaultScopes });
    }
  }

  return {
    port,
    host,
    vaultPassphrase,
    vaultStorage,
    vaultPath,
    tofuStorage,
    tofuPath,
    agentToken,
    providers,
    redirectBaseUri,
    webBotAuthMode,
    webBotAuthNonceStore,
    webBotAuthNoncePath,
  };
}
