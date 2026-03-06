/**
 * Cred SDK — Main client class
 *
 * Cloud mode: Uses fetch (Node 18+ built-in). Zero runtime dependencies.
 * Local mode: Uses @credninja/oauth + @credninja/vault (optional peer deps).
 */

import {
  CredConfig,
  CredCloudConfig,
  CredLocalConfig,
  DelegateParams,
  DelegationResult,
  Connection,
  GetConsentUrlParams,
  RevokeParams,
} from './types';
import { CredError, ConsentRequiredError } from './errors';

// No default base URL — users must explicitly set their server URL.

/**
 * Type helpers for dynamic imports (avoids requiring these at module load).
 */
interface VaultModule {
  CredVault: new (opts: { passphrase: string; storage: 'sqlite' | 'file'; path: string }) => VaultInstance;
}

interface VaultInstance {
  init(): Promise<void>;
  get(input: {
    provider: string;
    userId: string;
    adapter?: unknown;
    clientId?: string;
    clientSecret?: string;
  }): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresAt?: Date;
    scopes?: string[];
    provider: string;
    userId: string;
  } | null>;
  store(input: {
    provider: string;
    userId: string;
    accessToken: string;
    refreshToken?: string;
    expiresAt?: Date;
    scopes?: string[];
  }): Promise<void>;
  list(input: { userId: string }): Promise<Array<{
    provider: string;
    userId: string;
    accessToken: string;
    refreshToken?: string;
    expiresAt?: Date;
    scopes?: string[];
  }>>;
  delete(input: { provider: string; userId: string }): Promise<void>;
}

interface OAuthModule {
  createAdapter(name: string): { refreshAccessToken(refreshToken: string, clientId: string, clientSecret: string): Promise<{ accessToken: string; refreshToken?: string; expiresIn?: number; scopes?: string[] }> };
}

function isLocalConfig(config: CredConfig): config is CredLocalConfig {
  return (config as CredLocalConfig).mode === 'local';
}

export class Cred {
  // ── Cloud mode fields ───────────────────────────────────────────────────────
  private readonly agentToken?: string;
  private readonly baseUrl?: string;

  // ── Local mode fields ───────────────────────────────────────────────────────
  private readonly localConfig?: CredLocalConfig;
  private vault?: VaultInstance;
  private vaultInitPromise?: Promise<void>;
  private readonly isLocal: boolean;

  constructor(config: CredConfig) {
    if (isLocalConfig(config)) {
      // ── Local mode ──────────────────────────────────────────────────────────
      this.isLocal = true;
      this.localConfig = config;
      if (!config.vault?.passphrase) {
        throw new CredError('vault.passphrase is required for local mode', 'invalid_config', 0);
      }
      if (!config.vault?.path) {
        throw new CredError('vault.path is required for local mode', 'invalid_config', 0);
      }
    } else {
      // ── Cloud mode (existing behavior — ZERO changes) ───────────────────────
      this.isLocal = false;
      if (!config.agentToken) {
        throw new CredError('agentToken is required', 'invalid_config', 0);
      }
      if (!config.baseUrl) {
        throw new CredError(
          'baseUrl is required. Set it to your Cred server URL (e.g. https://cred.example.com or http://localhost:3456 for local dev).',
          'invalid_config',
          0,
        );
      }
      this.agentToken = config.agentToken;
      this.baseUrl = Cred.validateBaseUrl(config.baseUrl);
    }
  }

  private static validateBaseUrl(url: string): string {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new CredError(`Invalid baseUrl: "${url}" — must be a valid URL`, 'invalid_config', 0);
    }
    // Allow HTTP for localhost/127.0.0.1 (standard secure context),
    // require HTTPS for all other hosts.
    const isLocalhost =
      parsed.hostname === 'localhost' ||
      parsed.hostname === '127.0.0.1' ||
      parsed.hostname === '::1';

    if (parsed.protocol !== 'https:' && !isLocalhost) {
      throw new CredError(
        `Invalid baseUrl: must use HTTPS for remote servers — HTTP is only permitted for localhost. ` +
        `Agent tokens would be sent in plaintext over HTTP.`,
        'invalid_config',
        0,
      );
    }
    return url.replace(/\/$/, '');
  }

  // ── Local mode: lazy vault initialization ───────────────────────────────────

  private async ensureVault(): Promise<VaultInstance> {
    if (this.vault) return this.vault;

    if (this.vaultInitPromise) {
      await this.vaultInitPromise;
      return this.vault!;
    }

    this.vaultInitPromise = this.initVault();
    await this.vaultInitPromise;
    return this.vault!;
  }

  private async initVault(): Promise<void> {
    const config = this.localConfig!;

    let vaultModule: VaultModule;
    try {
      vaultModule = await import('@credninja/vault') as unknown as VaultModule;
    } catch {
      throw new CredError(
        'Local mode requires @credninja/vault. Install it: npm install @credninja/vault',
        'missing_dependency',
        0,
      );
    }

    const vault = new vaultModule.CredVault({
      passphrase: config.vault.passphrase,
      storage: config.vault.storage ?? 'file',
      path: config.vault.path,
    });
    await vault.init();
    this.vault = vault;
  }

  private async getAdapter(service: string): Promise<{ refreshAccessToken(refreshToken: string, clientId: string, clientSecret: string): Promise<{ accessToken: string; refreshToken?: string; expiresIn?: number; scopes?: string[] }> }> {
    let oauthModule: OAuthModule;
    try {
      oauthModule = await import('@credninja/oauth') as unknown as OAuthModule;
    } catch {
      throw new CredError(
        'Local mode requires @credninja/oauth. Install it: npm install @credninja/oauth',
        'missing_dependency',
        0,
      );
    }
    return oauthModule.createAdapter(service);
  }

  // ── Core methods ────────────────────────────────────────────────────────────

  /**
   * Get a delegated access token for a service on behalf of a user.
   *
   * Cloud mode: Calls the Cred API. `appClientId` is required.
   * Local mode: Reads from the local vault. Auto-refreshes if expired.
   *
   * Throws ConsentRequiredError (with `consentUrl`) if the user hasn't
   * connected the service yet (cloud mode only).
   */
  async delegate(params: DelegateParams): Promise<DelegationResult> {
    if (this.isLocal) {
      return this.delegateLocal(params);
    }
    return this.delegateCloud(params);
  }

  private async delegateLocal(params: DelegateParams): Promise<DelegationResult> {
    const vault = await this.ensureVault();
    const config = this.localConfig!;
    const providerConfig = config.providers[params.service];

    let adapter: { refreshAccessToken(refreshToken: string, clientId: string, clientSecret: string): Promise<{ accessToken: string; refreshToken?: string; expiresIn?: number; scopes?: string[] }> } | undefined;
    let clientId: string | undefined;
    let clientSecret: string | undefined;

    if (providerConfig) {
      adapter = await this.getAdapter(params.service);
      clientId = providerConfig.clientId;
      clientSecret = providerConfig.clientSecret;
    }

    const entry = await vault.get({
      provider: params.service,
      userId: params.userId,
      adapter,
      clientId,
      clientSecret,
    });

    if (!entry) {
      throw new CredError(
        `No credentials found for ${params.service}/${params.userId} in local vault. ` +
        `Store tokens first using @credninja/vault before delegating.`,
        'not_found',
        404,
      );
    }

    const expiresIn = entry.expiresAt
      ? Math.max(0, Math.floor((entry.expiresAt.getTime() - Date.now()) / 1000))
      : undefined;

    return {
      accessToken: entry.accessToken,
      tokenType: 'Bearer',
      expiresIn,
      service: params.service,
      scopes: entry.scopes ?? [],
      delegationId: `local_${params.service}_${params.userId}`,
    };
  }

  private async delegateCloud(params: DelegateParams): Promise<DelegationResult> {
    if (!params.appClientId) {
      throw new CredError('appClientId is required for cloud mode delegation', 'invalid_config', 0);
    }
    const body: Record<string, unknown> = {
      service: params.service,
      user_id: params.userId,
      appClientId: params.appClientId,
    };
    if (params.scopes && params.scopes.length > 0) {
      body.scopes = params.scopes;
    }
    if (params.agentDid) {
      body.agent_did = params.agentDid;
    }

    const data = await this.post<{
      access_token: string;
      token_type: string;
      expires_in?: number;
      service: string;
      scopes: string[];
      delegation_id: string;
      receipt?: string;
    }>('/api/v1/delegate', body);

    return {
      accessToken: data.access_token,
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      service: data.service,
      scopes: data.scopes,
      delegationId: data.delegation_id,
      receipt: data.receipt,
    };
  }

  /**
   * List all services a user has actively connected.
   *
   * Cloud mode: Calls the Cred API.
   * Local mode: Lists from the local vault.
   */
  async getUserConnections(userId: string, appClientId?: string): Promise<Connection[]> {
    if (this.isLocal) {
      const vault = await this.ensureVault();
      const entries = await vault.list({ userId });
      return entries.map((e) => ({
        slug: e.provider,
        scopesGranted: e.scopes ?? [],
        consentedAt: null,
        appClientId: null,
      }));
    }

    const params = new URLSearchParams({ user_id: userId });
    if (appClientId) params.set('app_client_id', appClientId);

    const data = await this.get<{ connections: Connection[] }>(
      `/api/v1/connections?${params.toString()}`,
    );
    return data.connections;
  }

  /**
   * Build a consent URL to redirect a user to connect a service.
   * Pure URL construction — no HTTP call.
   * Only available in cloud mode.
   */
  getConsentUrl(params: GetConsentUrlParams): string {
    if (this.isLocal) {
      throw new CredError(
        'getConsentUrl() is not available in local mode. Use @credninja/oauth directly for OAuth flows.',
        'not_supported',
        0,
      );
    }
    const url = new URL(`${this.baseUrl}/api/connect/${params.service}/authorize`);
    url.searchParams.set('app_client_id', params.appClientId);
    url.searchParams.set('scopes', params.scopes.join(','));
    url.searchParams.set('redirect_uri', params.redirectUri);
    return url.toString();
  }

  /**
   * Revoke a user's connection to a service.
   *
   * Cloud mode: Calls the Cred API.
   * Local mode: Deletes from the local vault.
   */
  async revoke(params: RevokeParams): Promise<void> {
    if (this.isLocal) {
      const vault = await this.ensureVault();
      await vault.delete({ provider: params.service, userId: params.userId });
      return;
    }

    const query = new URLSearchParams({ user_id: params.userId });
    if (params.appClientId) query.set('app_client_id', params.appClientId);

    await this.delete(`/api/v1/connections/${params.service}?${query.toString()}`);
  }

  // ── Private HTTP helpers (cloud mode only) ──────────────────────────────────

  private headers(): Record<string, string> {
    return {
      'Authorization': `Bearer ${this.agentToken}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    return this.handleResponse<T>(res);
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: this.headers(),
    });
    return this.handleResponse<T>(res);
  }

  private async delete(path: string): Promise<void> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'DELETE',
      headers: this.headers(),
    });
    if (res.status === 204) return;
    await this.handleResponse(res);
  }

  private async handleResponse<T>(res: Response): Promise<T> {
    if (res.ok) {
      return res.json() as Promise<T>;
    }

    let body: Record<string, unknown> = {};
    try {
      const parsed: unknown = await res.json();
      if (parsed !== null && typeof parsed === 'object') {
        body = parsed as Record<string, unknown>;
      }
    } catch {
      // ignore parse errors
    }

    const message = typeof body.message === 'string'
      ? body.message
      : typeof body.error === 'string'
        ? body.error
        : `Request failed with status ${res.status}`;

    // 403 consent_required → ConsentRequiredError
    if (res.status === 403 && body.error === 'consent_required') {
      const consentUrl = typeof body.consent_url === 'string' ? body.consent_url : '';
      throw new ConsentRequiredError(message, consentUrl);
    }

    throw new CredError(message, String(body.error ?? 'unknown'), res.status);
  }
}
