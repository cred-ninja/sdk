import crypto from 'crypto';
import type { StorageBackend } from './storage/interface.js';
import type { Permission, PermissionApprover, PermissionRateLimit, PermissionRow, PermissionRowUpdate, UpdatePermissionInput } from './types.js';

export interface CreatePermissionInput {
  agentId: string;
  connectionId: string;
  allowedScopes: string[];
  rateLimit?: PermissionRateLimit;
  ttlOverride?: number;
  requiresApproval: boolean;
  approver?: PermissionApprover;
  delegatable: boolean;
  maxDelegationDepth: number;
  expiresAt?: Date;
  createdBy: string;
}

/**
 * requires_approval holds the approver too, so no column is added: 0 no
 * approval, 1 the subject (every row written before approvers existed),
 * 2 an admin, 3 both.
 */
const APPROVAL_CODES: Record<PermissionApprover, number> = { subject: 1, admin: 2, both: 3 };

function approvalCode(requiresApproval: boolean, approver: PermissionApprover | undefined): number {
  return requiresApproval ? APPROVAL_CODES[approver ?? 'subject'] : 0;
}

export class PermissionStore {
  constructor(private readonly backend: StorageBackend) {}

  async create(permission: CreatePermissionInput): Promise<Permission> {
    const storage = this.ensureBackend();
    const createdAt = new Date();
    const record: Permission = {
      id: `perm_${crypto.randomUUID().replace(/-/g, '')}`,
      createdAt,
      updatedAt: createdAt.toISOString(),
      ...permission,
    };

    await storage.storePermission(this.permissionToRow(record));
    return record;
  }

  /**
   * Atomically update a subset of an existing permission's fields.
   * Cannot move the permission to a different (agentId, connectionId) —
   * `UpdatePermissionInput` structurally excludes both. Throws a clear
   * not-found error (not a silent create) when `id` doesn't exist.
   */
  async update(id: string, input: UpdatePermissionInput): Promise<Permission> {
    if (!this.backend.updatePermission) {
      throw new Error('Permission storage not supported by this backend');
    }

    // requiresApproval and the approver share a column: turning approval on
    // without naming an approver keeps the one already set, never resetting
    // 'admin' or 'both' to 'subject'. An empty update reads the row.
    if (input.requiresApproval === true && input.approver === undefined) {
      const current = this.rowToPermission(await this.backend.updatePermission(id, {}));
      if (current.requiresApproval && current.approver) input = { ...input, approver: current.approver };
    }
    const row = await this.backend.updatePermission(id, this.updateInputToRow(input));
    return this.rowToPermission(row);
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

  /** Cred Link: all permissions on one connection, any agent. */
  async listForConnection(connectionId: string): Promise<Permission[]> {
    if (!this.backend.listPermissionsForConnection) {
      throw new Error('Permission storage not supported by this backend');
    }
    const rows = await this.backend.listPermissionsForConnection(connectionId);
    return rows.map((row) => this.rowToPermission(row));
  }

  /**
   * Cred Link: set every permission on the connection to
   * allowedScopes ∩ scopes (canonical comparison), atomically. Returns the
   * permissions whose scope set changed. Never widens.
   */
  async intersectForConnection(connectionId: string, scopes: readonly string[]): Promise<Permission[]> {
    if (!this.backend.intersectPermissionsForConnection) {
      throw new Error('Permission storage not supported by this backend');
    }
    const rows = await this.backend.intersectPermissionsForConnection(connectionId, [...scopes]);
    return rows.map((row) => this.rowToPermission(row));
  }

  /** Whether the backend implements everything Cred Link's permission port needs. */
  supportsLinkPermissions(): boolean {
    return Boolean(
      this.backend.storePermission
      && this.backend.getPermission
      && this.backend.listPermissions
      && this.backend.revokePermission
      && this.backend.checkPermissionRateLimit
      && this.backend.updatePermission
      && this.backend.listPermissionsForConnection
      && this.backend.intersectPermissionsForConnection,
    );
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
      requires_approval: approvalCode(permission.requiresApproval, permission.approver),
      delegatable: permission.delegatable ? 1 : 0,
      max_delegation_depth: permission.maxDelegationDepth,
      expires_at: permission.expiresAt?.toISOString() ?? null,
      created_at: permission.createdAt.toISOString(),
      created_by: permission.createdBy,
      updated_at: permission.updatedAt,
    };
  }

  /**
   * Convert a domain-level partial update into row-shaped column updates.
   * Uses `'field' in input` (not `!== undefined`) so an explicit
   * `{ rateLimit: undefined }` — "clear the rate limit" — is distinguished
   * from an omitted field ("don't touch it").
   */
  private updateInputToRow(input: UpdatePermissionInput): PermissionRowUpdate {
    const updates: PermissionRowUpdate = {};

    if ('allowedScopes' in input && input.allowedScopes !== undefined) {
      updates.allowed_scopes = JSON.stringify(input.allowedScopes);
    }
    if ('rateLimit' in input) {
      updates.rate_limit_max = input.rateLimit?.maxRequests ?? null;
      updates.rate_limit_window_ms = input.rateLimit?.windowMs ?? null;
    }
    if ('ttlOverride' in input) {
      updates.ttl_override = input.ttlOverride ?? null;
    }
    if ('requiresApproval' in input && input.requiresApproval !== undefined) {
      updates.requires_approval = approvalCode(input.requiresApproval, input.approver);
    }
    if ('delegatable' in input && input.delegatable !== undefined) {
      updates.delegatable = input.delegatable ? 1 : 0;
    }
    if ('maxDelegationDepth' in input && input.maxDelegationDepth !== undefined) {
      updates.max_delegation_depth = input.maxDelegationDepth;
    }
    if ('expiresAt' in input) {
      updates.expires_at = input.expiresAt ? input.expiresAt.toISOString() : null;
    }

    return updates;
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
      // Any non-zero code requires approval; an unknown code fails closed to both.
      requiresApproval: row.requires_approval !== 0,
      ...(row.requires_approval !== 0
        ? { approver: (Object.entries(APPROVAL_CODES).find(([, code]) => code === row.requires_approval)?.[0] ?? 'both') as PermissionApprover }
        : {}),
      delegatable: row.delegatable === 1,
      maxDelegationDepth: row.max_delegation_depth,
      createdAt: new Date(row.created_at),
      // Legacy rows written before the updated_at migration have NULL here.
      updatedAt: row.updated_at ?? row.created_at,
      expiresAt: row.expires_at ? new Date(row.expires_at) : undefined,
      createdBy: row.created_by,
    };
  }
}
