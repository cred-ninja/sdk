/**
 * Cred MCP Server — Configuration
 *
 * Loads configuration from environment variables.
 */

export interface CredMcpConfig {
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** Your Cred app's client ID */
  appClientId: string;
  /** Override the API base URL. Defaults to https://api.cred.ninja */
  baseUrl: string;
}

const DEFAULT_BASE_URL = 'https://api.cred.ninja';

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

export function loadConfig(): CredMcpConfig {
  const agentToken = process.env.CRED_AGENT_TOKEN;
  const appClientId = process.env.CRED_APP_CLIENT_ID;
  const rawBaseUrl = process.env.CRED_BASE_URL ?? DEFAULT_BASE_URL;

  if (!agentToken) {
    throw new Error('CRED_AGENT_TOKEN environment variable is required');
  }
  if (!appClientId) {
    throw new Error('CRED_APP_CLIENT_ID environment variable is required');
  }

  const baseUrl = validateBaseUrl(rawBaseUrl);

  return {
    agentToken,
    appClientId,
    baseUrl,
  };
}
