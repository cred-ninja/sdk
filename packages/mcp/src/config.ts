/**
 * Cred MCP Server — Configuration
 *
 * Loads configuration from environment variables.
 * Supports cloud mode (default) and local mode (CRED_MODE=local).
 */

export interface CredMcpCloudConfig {
  mode: 'cloud';
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** Your Cred app's client ID */
  appClientId: string;
  /** Your Cred server URL (e.g. https://cred.example.com) */
  baseUrl: string;
}

export interface CredMcpLocalConfig {
  mode: 'local';
  /** Passphrase for vault encryption */
  vaultPassphrase: string;
  /** Path to vault file */
  vaultPath: string;
  /** Storage backend: 'sqlite' or 'file' */
  vaultStorage: 'sqlite' | 'file';
  /** Provider credentials: { google: { clientId, clientSecret }, ... } */
  providers: Record<string, { clientId: string; clientSecret: string }>;
}

export type CredMcpConfig = CredMcpCloudConfig | CredMcpLocalConfig;

// No default — users must provide their server URL

function validateBaseUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid CRED_BASE_URL: "${url}" — must be a valid HTTPS URL`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(
      `Invalid CRED_BASE_URL: "${url}" — must use HTTPS. HTTP is not permitted (agent tokens would be sent in plaintext).`,
    );
  }
  return url.replace(/\/$/, '');
}

/**
 * Parse CRED_PROVIDERS env var.
 * Format: "google:clientId:clientSecret,github:clientId:clientSecret"
 */
function parseProviders(raw: string): Record<string, { clientId: string; clientSecret: string }> {
  const providers: Record<string, { clientId: string; clientSecret: string }> = {};
  for (const entry of raw.split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(':');
    if (parts.length < 3) {
      throw new Error(
        `Invalid CRED_PROVIDERS entry: "${trimmed}". Format: "provider:clientId:clientSecret"`,
      );
    }
    const [name, clientId, ...rest] = parts;
    // clientSecret may contain colons (some providers do this)
    const clientSecret = rest.join(':');
    providers[name] = { clientId, clientSecret };
  }
  return providers;
}

export function loadConfig(args?: string[]): CredMcpConfig {
  const isLocal =
    process.env.CRED_MODE === 'local' ||
    (args ?? process.argv).includes('--local');

  if (isLocal) {
    const vaultPassphrase = process.env.CRED_VAULT_PASSPHRASE;
    if (!vaultPassphrase) {
      throw new Error('CRED_VAULT_PASSPHRASE environment variable is required for local mode');
    }

    const vaultPath = process.env.CRED_VAULT_PATH ?? './cred-vault.json';
    const vaultStorage = (process.env.CRED_VAULT_STORAGE ?? 'file') as 'sqlite' | 'file';

    const providersRaw = process.env.CRED_PROVIDERS ?? '';
    const providers = parseProviders(providersRaw);

    return {
      mode: 'local',
      vaultPassphrase,
      vaultPath,
      vaultStorage,
      providers,
    };
  }

  // Cloud mode (existing behavior)
  const agentToken = process.env.CRED_AGENT_TOKEN;
  const appClientId = process.env.CRED_APP_CLIENT_ID;
  const rawBaseUrl = process.env.CRED_BASE_URL;
  if (!rawBaseUrl) {
    throw new Error('CRED_BASE_URL environment variable is required. Set it to your Cred server URL (e.g. https://cred.example.com)');
  }

  if (!agentToken) {
    throw new Error('CRED_AGENT_TOKEN environment variable is required');
  }
  if (!appClientId) {
    throw new Error('CRED_APP_CLIENT_ID environment variable is required');
  }

  const baseUrl = validateBaseUrl(rawBaseUrl);

  return {
    mode: 'cloud',
    agentToken,
    appClientId,
    baseUrl,
  };
}
