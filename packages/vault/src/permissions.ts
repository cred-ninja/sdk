import crypto from 'crypto';
import type { StorageBackend } from './storage/interface.js';
import type { Permission, PermissionRateLimit, PermissionRow } from './types.js';

export interface CreatePermissionInput {
  agentId: string;
  connectionId: string;
  allowedScopes: string[];
  rateLimit?: PermissionRateLimit;
  ttlOverride?: number;
  requiresApproval: boolean;
  delegatable: boolean;
  maxDelegationDepth: number;
  expiresAt?: Date;
  createdBy: string;
}

export class PermissionStore {
  constructor(private readonly backend: StorageBackend) {}

  async create(permission: CreatePermissionInput): Promise<Permission> {
    const storage = this.ensureBackend();
    const createdAt = new Date();
    const record: Permission = {
      id: `perm_${crypto.randomUUID().replace(/-/g, '')}`,
      createdAt,
      ...permission,
    };

    await storage.storePermission(this.permissionToRow(record));
    return record;
  }

  async get(agentId: string, connectionId: string): Promise<Permission | null> {
    const storage = this.ensureBackend();
    const row = await storage.getPermission(agentId, connectionId);
    return row ? this.rowToPermission(row) : null;
  }

  async list(agentId: string): Promise<Permission[]> {
    const storage = this.ensureBackend();
    const rows = await storage.listPermissions(agentId);
    return rows.map((row) => this.rowToPermission(row));
  }

  async revoke(permissionId: string): Promise<void> {
    const storage = this.ensureBackend();
    await storage.revokePermission(permissionId);
  }

  async checkRateLimit(
    permissionId: string,
    maxRequests: number,
    windowMs: number,
    now = new Date(),
  ): Promise<boolean> {
    const storage = this.ensureBackend();
    return storage.checkPermissionRateLimit(permissionId, maxRequests, windowMs, now);
  }

  private ensureBackend(): Required<Pick<
    StorageBackend,
    'storePermission' | 'getPermission' | 'listPermissions' | 'revokePermission' | 'checkPermissionRateLimit'
  >> {
    if (
      !this.backend.storePermission
      || !this.backend.getPermission
      || !this.backend.listPermissions
      || !this.backend.revokePermission
      || !this.backend.checkPermissionRateLimit
    ) {
      throw new Error('Permission storage not supported by this backend');
    }

    return {
      storePermission: this.backend.storePermission.bind(this.backend),
      getPermission: this.backend.getPermission.bind(this.backend),
      listPermissions: this.backend.listPermissions.bind(this.backend),
      revokePermission: this.backend.revokePermission.bind(this.backend),
      checkPermissionRateLimit: this.backend.checkPermissionRateLimit.bind(this.backend),
    };
  }

  private permissionToRow(permission: Permission): PermissionRow {
    return {
      id: permission.id,
      agent_id: permission.agentId,
      connection_id: permission.connectionId,
      allowed_scopes: JSON.stringify(permission.allowedScopes),
      rate_limit_max: permission.rateLimit?.maxRequests ?? null,
      rate_limit_window_ms: permission.rateLimit?.windowMs ?? null,
      ttl_override: permission.ttlOverride ?? null,
      requires_approval: permission.requiresApproval ? 1 : 0,
      delegatable: permission.delegatable ? 1 : 0,
      max_delegation_depth: permission.maxDelegationDepth,
      expires_at: permission.expiresAt?.toISOString() ?? null,
      created_at: permission.createdAt.toISOString(),
      created_by: permission.createdBy,
    };
  }

  private rowToPermission(row: PermissionRow): Permission {
    const hasRateLimit = row.rate_limit_max !== null && row.rate_limit_window_ms !== null;

    return {
      id: row.id,
      agentId: row.agent_id,
      connectionId: row.connection_id,
      allowedScopes: JSON.parse(row.allowed_scopes) as string[],
      rateLimit: hasRateLimit
        ? {
            maxRequests: row.rate_limit_max!,
            windowMs: row.rate_limit_window_ms!,
          }
        : undefined,
      ttlOverride: row.ttl_override ?? undefined,
      requiresApproval: row.requires_approval === 1,
      delegatable: row.delegatable === 1,
      maxDelegationDepth: row.max_delegation_depth,
      createdAt: new Date(row.created_at),
      expiresAt: row.expires_at ? new Date(row.expires_at) : undefined,
      createdBy: row.created_by,
    };
  }
}
