/**
 * Delegation records and cascading revocation.
 *
 * Receipts carry `parentDelegationId`, but until now no component kept that
 * linkage, so revoking a delegation could not reach the delegations derived
 * from it. A DelegationRecord stores one issued delegation and the id of the
 * delegation it was derived from. Revocation walks those records from one or
 * more seeds to every descendant (draft-sweeney-wimse-credential-delegation,
 * "Revocation": cascade to all descendants within 5 seconds).
 *
 * The walk is iterative breadth-first with a visited set, so a corrupt or
 * hostile parent graph (a cycle, a duplicate edge, a self-parent) terminates
 * and revokes each delegation at most once. Depth is bounded; a walk that
 * hits the bound reports `truncated` instead of silently stopping.
 */

export type DelegationStatus = 'active' | 'revoked';

/** One issued delegation, as stored. Timestamps are ISO strings, like AgentRow. */
export interface DelegationRecord {
  id: string;
  /** The delegation this one was derived from; null for a root delegation. */
  parentId: string | null;
  /** DID of the agent the delegation was issued to, when it named one. */
  agentDid: string | null;
  service: string;
  userId: string;
  chainDepth: number;
  status: DelegationStatus;
  createdAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  /** The delegation whose revocation revoked this one (itself when revoked directly). */
  revokedAncestorId: string | null;
  /**
   * What a Delegation Token for this delegation authorizes, as the server
   * needs it at exercise: absent on delegations issued without a token.
   */
  grant?: DelegationGrant;
}

/**
 * The server-side state behind a Delegation Token. None of it is secret:
 * `credentialHandle` is a random reference to the stored connection, not
 * the provider credential.
 */
export interface DelegationGrant {
  credentialHandle: string;
  consentId: string;
  /** RFC 7638 thumbprint of the key the token is bound to (`cnf.jkt`). */
  jkt: string;
  scopes: string[];
  appClientId: string;
  /** The token's `delegation_constraints`, as issued. */
  constraints?: unknown[];
  /** The token's `authorization_details`, as issued. */
  authorizationDetails?: unknown[];
  /** The token's `prf`: receipt content identifiers, root hop first. */
  prf?: string[];
  /** Cred Link binding, for delegations of a Link connection. */
  link?: Record<string, unknown>;
}

/** Input for recording a new delegation. Status is always 'active' at issue. */
export type RecordDelegationInput = Pick<DelegationRecord, 'id' | 'service' | 'userId'> & {
  parentId?: string | null;
  agentDid?: string | null;
  chainDepth?: number;
  expiresAt?: string | null;
  grant?: DelegationGrant;
};

/**
 * Where a cascade starts. `delegationIds` revokes those delegations and
 * their descendants. `agentDid` revokes every delegation issued to that
 * agent and their descendants. Both may be given.
 */
export interface DelegationRevocationSeed {
  delegationIds?: readonly string[];
  agentDid?: string;
  /**
   * Revokes every delegation of one stored connection: used when the
   * connection itself is revoked, so no token issued from it can be used
   * with a credential stored later for the same service and user.
   */
  connection?: { service: string; userId: string };
}

export interface RevokedDelegation {
  id: string;
  parentId: string | null;
  agentDid: string | null;
  service: string;
  userId: string;
  /** Hops below the seed that reached it; 0 for a seed. */
  depth: number;
  /** The seed delegation whose revocation reached this one (the root cause). */
  revokedAncestorId: string;
}

export interface DelegationRevocationResult {
  /** Delegations this call moved from active to revoked, seeds first. */
  revoked: RevokedDelegation[];
  revokedIds: string[];
  count: number;
  elapsedMs: number;
  /** True when the walk reached maxDepth with children left unvisited. */
  truncated: boolean;
}

export interface DelegationRevocationOptions {
  /** Hops below a seed the walk may follow. Defaults to DEFAULT_MAX_REVOCATION_DEPTH. */
  maxDepth?: number;
}

/**
 * Far above any chain a Permission would allow (the draft recommends a
 * maximum chain depth of 5), and low enough that a corrupt graph cannot
 * keep the walk going.
 */
export const DEFAULT_MAX_REVOCATION_DEPTH = 64;

/**
 * Thrown when a delegation is recorded under a parent, or for an agent,
 * that is already revoked. Recording checks this atomically with the
 * insert, so a child issued while its parent is being revoked can never
 * outlive the cascade.
 */
export class DelegationRevokedError extends Error {
  constructor(
    message: string,
    public readonly code: 'delegation_revoked' | 'agent_revoked',
    public readonly revokedAncestorId: string,
  ) {
    super(message);
    this.name = 'DelegationRevokedError';
  }
}

export interface SubtreeNode {
  id: string;
  depth: number;
  rootId: string;
}

/**
 * Breadth-first walk from `seeds` through `childrenOf`. Each id is visited
 * once, so cycles and duplicate edges terminate. A seed that is also a
 * descendant of another seed keeps the first root that reached it.
 */
export function collectDelegationSubtree(
  seeds: readonly string[],
  childrenOf: (id: string) => readonly string[],
  options: DelegationRevocationOptions = {},
): { nodes: SubtreeNode[]; truncated: boolean } {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_REVOCATION_DEPTH;
  const visited = new Set<string>();
  const nodes: SubtreeNode[] = [];
  let truncated = false;

  for (const seed of seeds) {
    if (visited.has(seed)) continue;
    visited.add(seed);
    nodes.push({ id: seed, depth: 0, rootId: seed });
  }

  // nodes doubles as the queue: index i is the next node to expand.
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    const children = childrenOf(node.id);
    if (children.length === 0) continue;
    if (node.depth >= maxDepth) {
      if (children.some((child) => !visited.has(child))) truncated = true;
      continue;
    }
    for (const child of children) {
      if (visited.has(child)) continue;
      visited.add(child);
      nodes.push({ id: child, depth: node.depth + 1, rootId: node.rootId });
    }
  }

  return { nodes, truncated };
}

/**
 * Validate a record before it is stored. A delegation can never be its own
 * parent; anything subtler (a longer cycle) is caught by the walk.
 */
export function assertRecordable(input: RecordDelegationInput): void {
  if (!input.id || !input.service || !input.userId) {
    throw new Error('Delegation record requires id, service and userId');
  }
  if (input.parentId && input.parentId === input.id) {
    throw new Error('A delegation cannot be its own parent');
  }
}

/**
 * Delegation storage for vault backends without a delegation table (the
 * file backend). Process-local, like the brokered handles it tracks: a
 * restart loses both together. Every method is synchronous, so a cascade
 * runs to completion without yielding to another request.
 */
export class MemoryDelegationStore {
  private readonly records = new Map<string, DelegationRecord>();
  private readonly children = new Map<string, string[]>();
  private readonly byAgent = new Map<string, string[]>();

  storeDelegation(input: RecordDelegationInput, now: string): DelegationRecord {
    assertRecordable(input);
    const existing = this.records.get(input.id);
    // First write wins: replaying an id can never re-parent it.
    if (existing) return existing;
    if (input.parentId) {
      const parent = this.records.get(input.parentId);
      if (parent?.status === 'revoked') {
        throw new DelegationRevokedError(
          `Parent delegation ${input.parentId} has been revoked`,
          'delegation_revoked',
          parent.revokedAncestorId ?? parent.id,
        );
      }
    }
    const record: DelegationRecord = {
      id: input.id,
      parentId: input.parentId ?? null,
      agentDid: input.agentDid ?? null,
      service: input.service,
      userId: input.userId,
      chainDepth: input.chainDepth ?? 0,
      status: 'active',
      createdAt: now,
      expiresAt: input.expiresAt ?? null,
      revokedAt: null,
      revokedAncestorId: null,
      ...(input.grant ? { grant: input.grant } : {}),
    };
    this.records.set(record.id, record);
    if (record.parentId) pushTo(this.children, record.parentId, record.id);
    if (record.agentDid) pushTo(this.byAgent, record.agentDid, record.id);
    return record;
  }

  getDelegation(id: string): DelegationRecord | null {
    return this.records.get(id) ?? null;
  }

  revokeDelegationTree(
    seed: DelegationRevocationSeed,
    revokedAt: string,
    options: DelegationRevocationOptions = {},
  ): { revoked: RevokedDelegation[]; truncated: boolean } {
    const byConnection = seed.connection
      ? [...this.records.values()]
          .filter((r) => r.service === seed.connection!.service && r.userId === seed.connection!.userId)
          .map((r) => r.id)
      : [];
    const seeds = [...(seed.delegationIds ?? []), ...(seed.agentDid ? this.byAgent.get(seed.agentDid) ?? [] : []), ...byConnection];
    const { nodes, truncated } = collectDelegationSubtree(seeds, (id) => this.children.get(id) ?? [], options);
    const revoked: RevokedDelegation[] = [];
    for (const node of nodes) {
      const record = this.records.get(node.id);
      if (!record || record.status === 'revoked') continue;
      record.status = 'revoked';
      record.revokedAt = revokedAt;
      record.revokedAncestorId = node.rootId;
      revoked.push(toRevoked(record, node));
    }
    return { revoked, truncated };
  }
}

function pushTo(index: Map<string, string[]>, key: string, value: string): void {
  const list = index.get(key);
  if (list) list.push(value);
  else index.set(key, [value]);
}

export function toRevoked(record: Pick<DelegationRecord, 'id' | 'parentId' | 'agentDid' | 'service' | 'userId'>, node: SubtreeNode): RevokedDelegation {
  return {
    id: record.id,
    parentId: record.parentId,
    agentDid: record.agentDid,
    service: record.service,
    userId: record.userId,
    depth: node.depth,
    revokedAncestorId: node.rootId,
  };
}
