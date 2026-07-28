/**
 * @credninja/server — Configuration
 *
 * Loads server configuration from environment variables.
 * Call loadConfig() after dotenv (or process.env is populated).
 */

import type { BuiltinAdapterSlug } from '@credninja/oauth';
import type { CredGuard } from '@credninja/guard';
import type { Request } from 'express';

export interface ProviderConfig {
  slug: BuiltinAdapterSlug;
  clientId: string;
  clientSecret: string;
  defaultScopes: string[];
}

export interface RequestAgentPrincipal {
  type: string;
  principalId?: string;
  metadata?: Record<string, unknown>;
}

export type AgentRequestAuthResult =
  | { ok: true; principal?: RequestAgentPrincipal }
  | { ok: false; status?: number; error?: string };

export type AgentRequestVerifier =
  (req: Request) => AgentRequestAuthResult | Promise<AgentRequestAuthResult>;

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
  adminToken: string;
  agentToken?: string;
  agentRequestVerifier?: AgentRequestVerifier;

  // OAuth providers (only those with both clientId and clientSecret)
  providers: ProviderConfig[];

  // Redirect base URI (e.g. http://localhost:3456 or https://cred.example.com)
  redirectBaseUri: string;

  // Delegation receipt TTL, in seconds. Controls the `exp` claim minted onto
  // new receipts, and the age at which legacy receipts (no `exp` claim) are
  // treated as expired. Defaults to 3600 (1 hour) when unset.
  receiptTtlSeconds?: number;

  // Delegation receipt audience (`aud` claim). Defaults to redirectBaseUri
  // when unset.
  receiptAudience?: string;

  // Guard — optional policy engine for credential delegation guardrails
  // When provided, evaluates policies before serving delegated tokens.
  guard?: CredGuard;

  // Web Bot Auth ingress verification mode
  webBotAuthMode?: 'off' | 'optional' | 'require';
  webBotAuthNonceStore?: 'memory' | 'sqlite';
  webBotAuthNoncePath?: string;
  webBotAuthAllowedOrigins?: string[];
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

  const vaultStorage = (process.env.VAULT_STORAGE ?? 'sqlite') as 'sqlite' | 'file';
  const vaultPath = process.env.VAULT_PATH ?? (vaultStorage === 'sqlite' ? './data/vault.sqlite' : './data/vault.json');
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

  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    throw new Error(
      'ADMIN_TOKEN is required. Generate one: node -e "console.log(\'cred_admin_\' + require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  if (!adminToken.startsWith('cred_admin_')) {
    throw new Error('ADMIN_TOKEN must start with cred_admin_');
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
  const webBotAuthAllowedOrigins = (process.env.WEB_BOT_AUTH_ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  const receiptTtlSecondsRaw = process.env.RECEIPT_TTL_SECONDS;
  let receiptTtlSeconds: number | undefined;
  if (receiptTtlSecondsRaw !== undefined) {
    receiptTtlSeconds = parseInt(receiptTtlSecondsRaw, 10);
    if (!Number.isFinite(receiptTtlSeconds) || receiptTtlSeconds <= 0) {
      throw new Error('RECEIPT_TTL_SECONDS must be a positive integer');
    }
  }
  const receiptAudience = process.env.RECEIPT_AUDIENCE || undefined;

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
    adminToken,
    agentToken,
    providers,
    redirectBaseUri,
    receiptTtlSeconds,
    receiptAudience,
    webBotAuthMode,
    webBotAuthNonceStore,
    webBotAuthNoncePath,
    webBotAuthAllowedOrigins,
  };
}
