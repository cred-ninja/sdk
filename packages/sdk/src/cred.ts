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
  TofuDelegateParams,
  DelegationResult,
  SubDelegateParams,
  SubDelegationResult,
  Connection,
  AuditEntry,
  AuditParams,
  GetConsentUrlParams,
  RevokeParams,
  RotateParams,
  ScheduleRotationParams,
  RotationStatus,
  RotationStrategy,
} from './types';
import { CredError, ConsentRequiredError } from './errors';
import crypto from 'crypto';

// No default base URL — users must explicitly set their server URL.

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
  validateSubDelegation?: (input: {
    parent: {
      delegationId: string;
      agentDid: string;
      service: string;
      userId: string;
      appClientId: string;
      scopesGranted: string[];
      chainDepth: number;
    };
    childAgentDid: string;
    service: string;
    userId: string;
    appClientId: string;
    requestedScopes?: string[];
    permission: {
      allowedScopes: string[];
      delegatable: boolean;
      maxDelegationDepth: number;
    };
  }) => {
    parentDelegationId: string;
    chainDepth: number;
    grantedScopes: string[];
  };
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
  getPermission?(agentId: string, connectionId: string): Promise<{
    id: string;
    allowedScopes: string[];
    rateLimit?: { maxRequests: number; windowMs: number };
    ttlOverride?: number;
    requiresApproval: boolean;
    delegatable: boolean;
    maxDelegationDepth: number;
    createdAt: Date;
    expiresAt?: Date;
    createdBy: string;
  } | null>;
  checkPermissionRateLimit?(
    permissionId: string,
    maxRequests: number,
    windowMs: number,
    now?: Date,
  ): Promise<boolean>;
  revokeAgent?(agentId: string): Promise<void>;
  getAgentByDid?(did: string): Promise<{ id: string; status: string; scopeCeiling: string[] } | null>;
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
  delegationChain?: Array<{ delegatorId: string; delegateeId: string; scopes: string[] }>;
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

  async tofuDelegate(params: TofuDelegateParams): Promise<DelegationResult> {
    if (this.isLocal) {
      throw new CredError(
        'tofuDelegate() is not supported in local mode. TOFU proof verification is server-side only.',
        'local_mode_unsupported',
        0,
      );
    }

    const appClientId = params.appClientId ?? 'local';
    const sortedScopes = params.scopes && params.scopes.length > 0
      ? [...params.scopes].sort()
      : undefined;
    const payload = {
      service: params.service,
      userId: params.userId,
      appClientId,
      ...(sortedScopes ? { scopes: sortedScopes } : {}),
      timestamp: new Date().toISOString(),
    };
    const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
    const privateKey = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.from(params.privateKeyBytes),
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const signature = crypto.sign(null, payloadBytes, privateKey);

    const body: Record<string, unknown> = {
      service: params.service,
      user_id: params.userId,
      appClientId,
      tofu_fingerprint: params.fingerprint,
      tofu_payload: payloadBytes.toString('base64'),
      tofu_signature: signature.toString('base64'),
    };
    if (sortedScopes) {
      body.scopes = sortedScopes;
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

  async subDelegate(params: SubDelegateParams): Promise<SubDelegationResult> {
    if (this.isLocal) {
      return this.subDelegateLocal(params);
    }

    const body: Record<string, unknown> = {
      parent_receipt: params.parentReceipt,
      service: params.service,
      user_id: params.userId,
      appClientId: params.appClientId,
      agent_did: params.agentDid,
    };
    if (params.scopes && params.scopes.length > 0) {
      body.scopes = params.scopes;
    }

    const data = await this.post<{
      access_token: string;
      token_type: string;
      expires_in?: number;
      service: string;
      scopes: string[];
      delegation_id: string;
      receipt: string;
      chain_depth: number;
      parent_delegation_id: string;
    }>('/api/v1/subdelegate', body);

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
      chainDepth: data.chain_depth,
      parentDelegationId: data.parent_delegation_id,
    };
  }

  private async delegateLocal(params: DelegateParams): Promise<DelegationResult> {
    const vault = await this.ensureVault();
    const correlationId = crypto.randomUUID();
    let agentRecord: { id: string; status: string; scopeCeiling: string[] } | null = null;
    let permission: {
      id: string;
      allowedScopes: string[];
      rateLimit?: { maxRequests: number; windowMs: number };
      ttlOverride?: number;
      requiresApproval: boolean;
      delegatable: boolean;
      maxDelegationDepth: number;
      createdAt: Date;
      expiresAt?: Date;
      createdBy: string;
    } | null = null;

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

    if (agentRecord) {
      permission = await vault.getPermission?.(agentRecord.id, params.service) ?? null;
      if (!permission) {
        this.writeAuditEvent({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: params.agentDid ?? agentRecord.id },
          action: 'deny',
          resource: { type: 'permission', id: `${agentRecord.id}/${params.service}` },
          outcome: 'denied',
          scopesRequested: params.scopes ?? [],
          correlationId,
          errorMessage: 'no_permission',
        });
        throw new CredError(
          `Agent ${params.agentDid ?? agentRecord.id} has no permission for ${params.service}`,
          'no_permission',
          403,
        );
      }

      if (permission.expiresAt && permission.expiresAt.getTime() < Date.now()) {
        this.writeAuditEvent({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: params.agentDid ?? agentRecord.id },
          action: 'deny',
          resource: { type: 'permission', id: permission.id },
          outcome: 'denied',
          scopesRequested: params.scopes ?? [],
          correlationId,
          errorMessage: 'permission_expired',
        });
        throw new CredError('Permission has expired', 'permission_expired', 403);
      }

      if (permission.rateLimit) {
        const allowed = await vault.checkPermissionRateLimit?.(
          permission.id,
          permission.rateLimit.maxRequests,
          permission.rateLimit.windowMs,
        );
        if (!allowed) {
          this.writeAuditEvent({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: params.agentDid ?? agentRecord.id },
            action: 'deny',
            resource: { type: 'permission', id: permission.id },
            outcome: 'denied',
            scopesRequested: params.scopes ?? [],
            correlationId,
            errorMessage: 'rate_limited',
          });
          throw new CredError('Agent rate limit exceeded', 'rate_limited', 429);
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
    let delegatedScopes = grantedScopes;

    if (permission) {
      delegatedScopes = delegatedScopes.filter((scope) => permission!.allowedScopes.includes(scope));
    }

    if (params.scopes && params.scopes.length > 0) {
      const permittedRequestedScopes = permission
        ? params.scopes.filter((scope) => permission!.allowedScopes.includes(scope))
        : params.scopes;
      delegatedScopes = delegatedScopes.filter((scope) => permittedRequestedScopes.includes(scope));
    } else if (agentRecord && agentRecord.scopeCeiling.length > 0) {
      delegatedScopes = delegatedScopes.filter((scope) => agentRecord.scopeCeiling.includes(scope));
    }

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

    const receipt = params.agentDid
      ? this.createLocalDelegationReceipt({
          agentDid: params.agentDid,
          service: params.service,
          userId: params.userId,
          appClientId: params.appClientId ?? 'local',
          scopes: delegatedScopes,
          delegationId,
          chainDepth: 0,
        })
      : undefined;

    return {
      accessToken: entry.accessToken,
      tokenType: 'Bearer',
      expiresIn,
      expiresAt,
      service: params.service,
      scopes: delegatedScopes,
      delegationId,
      receipt,
    };
  }

  private async subDelegateLocal(params: SubDelegateParams): Promise<SubDelegationResult> {
    const vault = await this.ensureVault();
    const correlationId = crypto.randomUUID();
    const vaultModule = await import('@credninja/vault') as unknown as VaultModule;
    if (!vaultModule.validateSubDelegation) {
      throw new CredError(
        'Installed @credninja/vault does not support sub-delegation validation',
        'not_supported',
        501,
      );
    }

    const parent = this.parseDelegationReceipt(params.parentReceipt);
    if (parent.service !== params.service) {
      throw new CredError('Parent receipt service does not match request', 'service_mismatch', 403);
    }
    if (parent.userId !== params.userId) {
      throw new CredError('Parent receipt user does not match request', 'user_mismatch', 403);
    }
    if (parent.appClientId !== (params.appClientId ?? 'local')) {
      throw new CredError('Parent receipt app does not match request', 'app_mismatch', 403);
    }

    let agentRecord: { id: string; status: string; scopeCeiling: string[] } | null = null;
    if (vault.getAgentByDid) {
      agentRecord = await vault.getAgentByDid(params.agentDid);
    }
    if (agentRecord?.status === 'revoked') {
      throw new CredError(`Agent ${params.agentDid} has been revoked and cannot receive delegations`, 'agent_revoked', 403);
    }
    if (agentRecord?.status === 'suspended') {
      throw new CredError(`Agent ${params.agentDid} is suspended`, 'agent_suspended', 403);
    }

    const agentId = agentRecord?.id ?? params.agentDid;
    const permission = await vault.getPermission?.(agentId, params.service) ?? null;
    if (!permission) {
      throw new CredError(`Agent ${params.agentDid} has no permission for ${params.service}`, 'no_permission', 403);
    }

    const validation = vaultModule.validateSubDelegation({
      parent: {
        delegationId: parent.delegationId,
        agentDid: parent.sub,
        service: parent.service,
        userId: parent.userId,
        appClientId: parent.appClientId,
        scopesGranted: parent.scopes,
        chainDepth: parent.chainDepth ?? 0,
      },
      childAgentDid: params.agentDid,
      service: params.service,
      userId: params.userId,
      appClientId: params.appClientId ?? 'local',
      requestedScopes: params.scopes,
      permission: {
        allowedScopes: permission.allowedScopes,
        delegatable: permission.delegatable,
        maxDelegationDepth: permission.maxDelegationDepth,
      },
    });

    const parentScopeSet = new Set(parent.scopes);
    const requestedScopes = params.scopes ?? parent.scopes;
    const childRequestedScopes = agentRecord?.scopeCeiling?.length
      ? requestedScopes.filter((scope) => agentRecord!.scopeCeiling.includes(scope))
      : requestedScopes;

    const childDelegation = await this.delegateLocal({
      service: params.service,
      userId: params.userId,
      agentDid: params.agentDid,
      appClientId: params.appClientId,
      scopes: childRequestedScopes.filter((scope) => parentScopeSet.has(scope)),
    });

    const receipt = this.createLocalDelegationReceipt({
      agentDid: params.agentDid,
      service: params.service,
      userId: params.userId,
      appClientId: params.appClientId ?? 'local',
      scopes: validation.grantedScopes,
      delegationId: childDelegation.delegationId,
      chainDepth: validation.chainDepth,
      parentDelegationId: validation.parentDelegationId,
      parentReceipt: params.parentReceipt,
    });

    this.writeAuditEvent({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: params.agentDid },
      action: 'delegate',
      resource: { type: 'token', id: childDelegation.delegationId },
      outcome: 'success',
      scopesRequested: params.scopes ?? parent.scopes,
      scopesGranted: validation.grantedScopes,
      delegationChain: [
        { delegatorId: parent.sub, delegateeId: params.agentDid, scopes: validation.grantedScopes },
      ],
      correlationId,
    });

    return {
      ...childDelegation,
      scopes: validation.grantedScopes,
      receipt,
      chainDepth: validation.chainDepth,
      parentDelegationId: validation.parentDelegationId,
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

  private createLocalDelegationReceipt(input: {
    agentDid: string;
    service: string;
    userId: string;
    appClientId: string;
    scopes: string[];
    delegationId: string;
    chainDepth: number;
    parentDelegationId?: string;
    parentReceipt?: string;
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
      ...(input.parentReceipt ? {
        parentReceiptHash: crypto.createHash('sha256').update(input.parentReceipt).digest('hex'),
      } : {}),
    })).toString('base64url');

    const signatureInput = Buffer.from(`${header}.${payload}`, 'utf8');
    const privateKey = this.getLocalReceiptSigningKey();
    const { sign } = require('node:crypto') as typeof import('node:crypto');
    const signature = sign(null, signatureInput, privateKey).toString('base64url');
    return `${header}.${payload}.${signature}`;
  }

  private parseDelegationReceipt(receipt: string): {
    sub: string;
    service: string;
    scopes: string[];
    userId: string;
    appClientId: string;
    delegationId: string;
    chainDepth?: number;
  } {
    const parts = receipt.split('.');
    if (parts.length !== 3) {
      throw new CredError('Invalid parent receipt format', 'invalid_parent', 400);
    }

    try {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as {
        sub: string;
        service: string;
        scopes: string[];
        userId: string;
        appClientId: string;
        delegationId?: string;
        chainDepth?: number;
      };

      const publicKey = this.getLocalReceiptPublicKeyHex();
      const { createPublicKey, verify } = require('node:crypto') as typeof import('node:crypto');
      const publicKeyObject = createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'),
          Buffer.from(publicKey, 'hex'),
        ]),
        format: 'der',
        type: 'spki',
      });
      const valid = verify(
        null,
        Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'),
        publicKeyObject,
        Buffer.from(parts[2], 'base64url'),
      );
      if (!valid) {
        throw new CredError('Invalid parent receipt signature', 'invalid_parent', 403);
      }
      if (!payload.delegationId) {
        throw new CredError('Parent receipt is missing delegationId', 'invalid_parent', 400);
      }
      return {
        ...payload,
        delegationId: payload.delegationId,
      };
    } catch (error) {
      if (error instanceof CredError) throw error;
      throw new CredError('Failed to parse parent receipt', 'invalid_parent', 400);
    }
  }

  private getLocalReceiptSigningKey() {
    const { createPrivateKey } = require('node:crypto') as typeof import('node:crypto');
    const seed = crypto.createHash('sha256')
      .update(`cred-local-receipt:${this.localConfig!.vault.passphrase}`)
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

  private getLocalReceiptPublicKeyHex(): string {
    const { createPublicKey } = require('node:crypto') as typeof import('node:crypto');
    const publicKey = createPublicKey(this.getLocalReceiptSigningKey());
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    return Buffer.from(spki.slice(-32)).toString('hex');
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
   * Retrieve audit log entries for a user in cloud mode.
   * OSS server currently stores a single logical user (`default`), but the
   * query param is preserved for SDK parity with hosted/server deployments.
   */
  async getAuditLog(params: AuditParams): Promise<AuditEntry[]> {
    if (this.isLocal) {
      throw new CredError(
        'getAuditLog() is only supported in cloud mode in this version',
        'not_supported',
        501,
      );
    }

    const query = new URLSearchParams({ user_id: params.userId });
    if (params.appClientId) query.set('app_client_id', params.appClientId);
    if (params.service) query.set('service', params.service);
    if (params.limit !== undefined) query.set('limit', String(params.limit));

    const data = await this.get<{ entries: AuditEntry[] }>(`/api/v1/audit?${query.toString()}`);
    return data.entries;
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
