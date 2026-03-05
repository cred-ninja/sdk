import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

export interface ProviderConfig {
  slug: 'google' | 'github' | 'slack' | 'notion' | 'salesforce';
  name: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  testDescription: string;
}

const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3456/callback';

function env(key: string): string {
  return process.env[key] || '';
}

const ALL_PROVIDERS: ProviderConfig[] = [
  {
    slug: 'google',
    name: 'Google',
    clientId: env('GOOGLE_CLIENT_ID'),
    clientSecret: env('GOOGLE_CLIENT_SECRET'),
    scopes: ['calendar.readonly', 'gmail.readonly'],
    testDescription: 'List 5 calendar events',
  },
  {
    slug: 'github',
    name: 'GitHub',
    clientId: env('GITHUB_CLIENT_ID'),
    clientSecret: env('GITHUB_CLIENT_SECRET'),
    scopes: ['repo', 'read:user'],
    testDescription: 'List 5 repos',
  },
  {
    slug: 'slack',
    name: 'Slack',
    clientId: env('SLACK_CLIENT_ID'),
    clientSecret: env('SLACK_CLIENT_SECRET'),
    scopes: ['identity.basic'],
    testDescription: 'Auth test',
  },
  {
    slug: 'notion',
    name: 'Notion',
    clientId: env('NOTION_CLIENT_ID'),
    clientSecret: env('NOTION_CLIENT_SECRET'),
    scopes: [],
    testDescription: 'Get current user',
  },
  {
    slug: 'salesforce',
    name: 'Salesforce',
    clientId: env('SALESFORCE_CLIENT_ID'),
    clientSecret: env('SALESFORCE_CLIENT_SECRET'),
    scopes: ['api', 'refresh_token'],
    testDescription: 'List SObjects',
  },
];

/** Only providers with both clientId and clientSecret configured */
export function getConfiguredProviders(): ProviderConfig[] {
  return ALL_PROVIDERS.filter(p => p.clientId && p.clientSecret);
}

export function getProvider(slug: string): ProviderConfig | undefined {
  return ALL_PROVIDERS.find(p => p.slug === slug && p.clientId && p.clientSecret);
}

export function getRedirectUri(): string {
  return REDIRECT_URI;
}

export function getVaultPassphrase(): string {
  return process.env.VAULT_PASSPHRASE || 'default-dev-passphrase';
}

/**
 * Shared secret agents include as a Bearer token to call /api/token/:provider.
 * If not set, the token API is disabled (returns 403).
 */
export function getAgentToken(): string | null {
  return process.env.AGENT_TOKEN || null;
}
