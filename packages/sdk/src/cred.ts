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
  RotateParams,
  ScheduleRotationParams,
  RotationStatus,
  RotationStrategy,
} from './types';
import { CredError, ConsentRequiredError } from './errors';
import crypto from 'crypto';

const DEFAULT_BASE_URL = 'https://api.cred.ninja';

/**
 * Type helpers for dynamic imports (avoids requiring these at module load).
 */

/** Rotation shape returned by @credninja/vault (mirrors Rotation but typed locally for dynamic import). */
interface VaultRotationResult {
  id: string;
  connectionId: string;
  strategy: string;
  state: string;
  currentVersionId: string | null;
  pendingVersionId: string | null;
  previousVersionId: string | null;
  lastRotatedAt: Date | null;
  nextRotationAt: Date | null;
  failureCount: number;
  failureAction: string;
}

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
  revokeAgent?(agentId: string): Promise<void>;
  getAgentByDid?(did: string): Promise<{ status: string; scopeCeiling: string[] } | null>;
  // Rotation methods (exposed by CredVault, proxied from RotationEngine)
  startRotation?(connectionId: string, strategy: string, intervalSeconds?: number): Promise<VaultRotationResult>;
  promoteRotation?(rotationId: string): Promise<VaultRotationResult>;
  rollbackRotation?(rotationId: string): Promise<VaultRotationResult>;
  getRotationByConnection?(provider: string, userId: string): Promise<VaultRotationResult | null>;
  writeAuditEvent?(event: {
    id: string;
    timestamp: Date;
    actor: { type: 'agent' | 'user' | 'system'; id: string; fingerprint?: string };
    action: string;
    resource: { type: string; id: string };
    outcome: string;
    correlationId: string;
    scopesRequested?: string[];
    scopesGranted?: string[];
    sensitiveFieldsHmac?: Record<string, string>;
    errorMessage?: string;
  }): void;
}

interface OAuthModule {
  createAdapter(name: string): { refreshAccessToken(refreshToken: string, clientId: string, clientSecret: string): Promise<{ accessToken: string; refreshToken?: string; expiresIn?: number; scopes?: string[] }> };
}

/** Minimal audit event — matches @credninja/vault AuditEvent shape */
interface AuditEventInput {
  id: string;
  timestamp: Date;
  actor: { type: 'agent' | 'user' | 'system'; id: string; fingerprint?: string };
  action: 'delegate' | 'access' | 'rotate' | 'revoke' | 'create' | 'delete' | 'deny';
  resource: { type: 'connection' | 'token' | 'agent' | 'permission' | 'rotation'; id: string };
  outcome: 'pending' | 'success' | 'denied' | 'error';
  scopesRequested?: string[];
  scopesGranted?: string[];
  correlationId: string;
  sensitiveFieldsHmac?: Record<string, string>;
  errorMessage?: string;
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

  // ── Audit fields ────────────────────────────────────────────────────────────
  private auditHmacSecret?: string;

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
      this.agentToken = config.agentToken;
      const rawBaseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
      this.baseUrl = Cred.validateBaseUrl(rawBaseUrl);
    }
  }

  private static validateBaseUrl(url: string): string {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new CredError(`Invalid baseUrl: "${url}" — must be a valid HTTPS URL`, 'invalid_config', 0);
    }
    if (parsed.protocol !== 'https:') {
      throw new CredError(
        `Invalid baseUrl: must use HTTPS — HTTP is not permitted (agent tokens would be sent in plaintext)`,
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

    // Derive HMAC secret from vault passphrase for audit field hashing
    this.auditHmacSecret = crypto.createHash('sha256').update(`audit:${config.vault.passphrase}`).digest('hex');
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
    const correlationId = crypto.randomUUID();
    let agentRecord: { status: string; scopeCeiling: string[] } | null = null;

    // Check agent status and scope ceiling before delegation
    if (params.agentDid && vault.getAgentByDid) {
      agentRecord = await vault.getAgentByDid(params.agentDid);
      if (agentRecord) {
        if (agentRecord.status === 'revoked') {
          this.writeAuditEvent({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: params.agentDid },
            action: 'deny',
            resource: { type: 'token', id: `${params.service}/${params.userId}` },
            outcome: 'denied',
            scopesRequested: params.scopes ?? [],
            correlationId,
            errorMessage: 'agent_revoked',
          });
          throw new CredError(
            `Agent ${params.agentDid} has been revoked and cannot receive delegations`,
            'agent_revoked',
            403,
          );
        }
        if (agentRecord.status === 'suspended') {
          this.writeAuditEvent({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: params.agentDid },
            action: 'deny',
            resource: { type: 'token', id: `${params.service}/${params.userId}` },
            outcome: 'denied',
            scopesRequested: params.scopes ?? [],
            correlationId,
            errorMessage: 'agent_suspended',
          });
          throw new CredError(
            `Agent ${params.agentDid} is suspended`,
            'agent_suspended',
            403,
          );
        }
        if (agentRecord.scopeCeiling.length > 0 && params.scopes && params.scopes.length > 0) {
          const scopeCeiling = agentRecord.scopeCeiling;
          const unauthorizedScopes = params.scopes.filter(s => !scopeCeiling.includes(s));
          if (unauthorizedScopes.length > 0) {
            this.writeAuditEvent({
              id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
              timestamp: new Date(),
              actor: { type: 'agent', id: params.agentDid },
              action: 'deny',
              resource: { type: 'token', id: `${params.service}/${params.userId}` },
              outcome: 'denied',
              scopesRequested: params.scopes,
              correlationId,
              errorMessage: `scope_ceiling_exceeded: ${unauthorizedScopes.join(', ')}`,
            });
            throw new CredError(
              `Agent scope ceiling exceeded: ${unauthorizedScopes.join(', ')} not in ceiling`,
              'scope_ceiling_exceeded',
              403,
            );
          }
        }
      }
    }

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

    this.writeAuditEvent({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: params.userId, fingerprint: params.agentDid },
      action: 'delegate',
      resource: { type: 'token', id: `${params.service}/${params.userId}` },
      outcome: 'pending',
      scopesRequested: params.scopes ?? [],
      correlationId,
    });

    const entry = await vault.get({
      provider: params.service,
      userId: params.userId,
      adapter,
      clientId,
      clientSecret,
    });

    if (!entry) {
      const err = new CredError(
        `No credentials found for ${params.service}/${params.userId} in local vault. ` +
        `Store tokens first using @credninja/vault before delegating.`,
        'not_found',
        404,
      );
      this.writeAuditEvent({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: params.userId },
        action: 'delegate',
        resource: { type: 'token', id: `${params.service}/${params.userId}` },
        outcome: 'error',
        scopesRequested: params.scopes ?? [],
        correlationId,
        errorMessage: err.message,
      });
      throw err;
    }

    // Check if token is expired (vault.get returns null for expired, but check anyway
    // in case vault returned an entry without expiry enforcement)
    if (entry.expiresAt && entry.expiresAt.getTime() <= Date.now()) {
      const err = new CredError(
        `Token for ${params.service}/${params.userId} has expired and could not be refreshed.`,
        'token_expired',
        401,
      );
      this.writeAuditEvent({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: params.userId },
        action: 'delegate',
        resource: { type: 'token', id: `${params.service}/${params.userId}` },
        outcome: 'error',
        scopesRequested: params.scopes ?? [],
        correlationId,
        errorMessage: err.message,
      });
      throw err;
    }

    // Always set a TTL — default 900s (15 min) if no expiry info
    const DEFAULT_TTL_SECONDS = 900;
    let expiresIn: number;
    let expiresAt: Date;

    if (entry.expiresAt) {
      expiresIn = Math.max(1, Math.floor((entry.expiresAt.getTime() - Date.now()) / 1000));
      expiresAt = entry.expiresAt;
    } else {
      expiresIn = DEFAULT_TTL_SECONDS;
      expiresAt = new Date(Date.now() + DEFAULT_TTL_SECONDS * 1000);
    }

    const delegationId = `local_${params.service}_${params.userId}`;
    const grantedScopes = entry.scopes ?? [];
    const delegatedScopes = agentRecord
      && agentRecord.scopeCeiling.length > 0
      && (!params.scopes || params.scopes.length === 0)
      ? grantedScopes.filter((scope) => agentRecord!.scopeCeiling.includes(scope))
      : grantedScopes;

    // Build HMAC of token for audit (raw token never stored)
    const sensitiveFieldsHmac = this.auditHmacSecret
      ? { accessToken: crypto.createHmac('sha256', this.auditHmacSecret).update(entry.accessToken).digest('hex') }
      : undefined;

    // Write audit event — MUST succeed (fail-closed)
    this.writeAuditEvent({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: params.userId, fingerprint: params.agentDid },
      action: 'delegate',
      resource: { type: 'token', id: delegationId },
      outcome: 'success',
      scopesRequested: params.scopes ?? [],
      scopesGranted: delegatedScopes,
      correlationId,
      sensitiveFieldsHmac,
    });

    return {
      accessToken: entry.accessToken,
      tokenType: 'Bearer',
      expiresIn,
      expiresAt,
      service: params.service,
      scopes: delegatedScopes,
      delegationId,
    };
  }

  /**
   * Write audit event via vault — throws CredError('audit_failure') if write fails.
   * This is the fail-closed behavior: delegation cannot succeed without a persisted audit record.
   */
  private writeAuditEvent(event: AuditEventInput): void {
    if (!this.vault?.writeAuditEvent) {
      if (this.localConfig?.requireAudit) {
        throw new CredError(
          'Audit backend required, but the configured vault storage does not support audit writes',
          'audit_not_supported',
          500,
        );
      }
      return;
    }
    try {
      this.vault.writeAuditEvent(event);
    } catch (err) {
      throw new CredError(
        `Audit write failure — delegation aborted for compliance (fail-closed): ${err instanceof Error ? err.message : String(err)}`,
        'audit_failure',
        500,
      );
    }
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

    const DEFAULT_TTL_SECONDS = 900;
    const expiresIn = data.expires_in ?? DEFAULT_TTL_SECONDS;
    const expiresAt = new Date(Date.now() + expiresIn * 1000);

    return {
      accessToken: data.access_token,
      tokenType: data.token_type,
      expiresIn,
      expiresAt,
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

      // Audit: revoke event
      this.writeAuditEvent({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'system', id: params.userId },
        action: 'revoke',
        resource: { type: 'connection', id: `${params.service}/${params.userId}` },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
      });
      return;
    }

    const query = new URLSearchParams({ user_id: params.userId });
    if (params.appClientId) query.set('app_client_id', params.appClientId);

    await this.delete(`/api/v1/connections/${params.service}?${query.toString()}`);
  }

  /**
   * Emergency revocation: marks agent as revoked.
   * After calling this, all subsequent delegate() calls with this agent's fingerprint will throw.
   * Local mode: updates vault_agents table.
   * Cloud mode: calls POST /agents/{agentId}/revoke-all.
   */
  async revokeAgent(agentId: string): Promise<void> {
    if (this.isLocal) {
      const vault = await this.ensureVault();
      if (!vault.revokeAgent) {
        throw new CredError(
          'Agent revocation not supported by this vault backend',
          'not_supported',
          0,
        );
      }
      await vault.revokeAgent(agentId);
      return;
    }
    await this.post<void>(`/api/v1/agents/${agentId}/revoke-all`, {});
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

  // ── Rotation ─────────────────────────────────────────────────────────────────

  /**
   * Start a credential rotation for a connection.
   * Local mode: Creates a vault_rotations record via RotationEngine (through vault).
   * Cloud mode: Not yet implemented on the cloud API.
   *
   * @returns RotationStatus with the new rotation ID and initial state
   */
  async rotate(params: RotateParams): Promise<RotationStatus> {
    if (!this.isLocal) {
      throw new CredError(
        'rotate() is only supported in local mode in this version',
        'not_supported',
        501,
      );
    }

    const vault = await this.ensureVault();
    const strategy: RotationStrategy = params.strategy ?? 'dual_active';

    if (!vault.startRotation) {
      throw new CredError(
        'Vault backend does not support rotation. Use SQLite storage backend.',
        'not_supported',
        501,
      );
    }

    const rotation = await vault.startRotation(params.connectionId, strategy, params.intervalSeconds);
    return this.toRotationStatus(rotation);
  }

  /**
   * Schedule an automatic rotation for a connection.
   * Equivalent to rotate() — creates a rotation with the given interval.
   */
  async scheduleRotation(params: ScheduleRotationParams): Promise<RotationStatus> {
    return this.rotate({
      connectionId: params.connectionId,
      strategy: params.strategy,
      intervalSeconds: params.intervalSeconds,
    });
  }

  /**
   * Promote the pending rotation to current.
   * Dual-active: pending → current, old current → previous.
   * Local mode only.
   */
  async promoteRotation(rotationId: string): Promise<RotationStatus> {
    if (!this.isLocal) {
      throw new CredError(
        'promoteRotation() is only supported in local mode in this version',
        'not_supported',
        501,
      );
    }

    const vault = await this.ensureVault();
    if (!vault.promoteRotation) {
      throw new CredError(
        'Vault backend does not support rotation. Use SQLite storage backend.',
        'not_supported',
        501,
      );
    }

    const rotation = await vault.promoteRotation(rotationId);
    return this.toRotationStatus(rotation);
  }

  /**
   * Roll back a rotation — revert to previous version.
   * Local mode only.
   */
  async rollbackRotation(rotationId: string): Promise<RotationStatus> {
    if (!this.isLocal) {
      throw new CredError(
        'rollbackRotation() is only supported in local mode in this version',
        'not_supported',
        501,
      );
    }

    const vault = await this.ensureVault();
    if (!vault.rollbackRotation) {
      throw new CredError(
        'Vault backend does not support rotation. Use SQLite storage backend.',
        'not_supported',
        501,
      );
    }

    const rotation = await vault.rollbackRotation(rotationId);
    return this.toRotationStatus(rotation);
  }

  private toRotationStatus(rotation: VaultRotationResult): RotationStatus {
    return {
      id: rotation.id,
      connectionId: rotation.connectionId,
      strategy: rotation.strategy as RotationStrategy,
      state: rotation.state,
      currentVersionId: rotation.currentVersionId,
      pendingVersionId: rotation.pendingVersionId,
      previousVersionId: rotation.previousVersionId,
      lastRotatedAt: rotation.lastRotatedAt,
      nextRotationAt: rotation.nextRotationAt,
      failureCount: rotation.failureCount,
      failureAction: rotation.failureAction,
    };
  }
}
