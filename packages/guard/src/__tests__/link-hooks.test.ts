import { describe, it, expect, vi } from 'vitest';
import {
  LINK_MACHINE_ERROR_STATUS,
  LINK_PERMISSION_DEFAULTS,
  isScopeSubset,
  scopeSetsEqual,
} from '@credninja/protocol';
import type {
  ClientGrant,
  Connection,
  ConnectionId,
  GrantId,
  LinkAccessCheckInput,
  LinkClient,
  LinkCreatePermissionInput,
  LinkPermission,
  LinkPermissionPort,
  LinkStore,
  LinkUpdatePermissionInput,
} from '@credninja/protocol';
import { createLinkHooks, LINK_CHECK_ERROR_CODE } from '../link/hooks.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

const NOW = '2026-10-11T12:00:00.000Z';
const PAST = '2026-10-10T12:00:00.000Z';
const FUTURE = '2026-10-12T12:00:00.000Z';
const CONN: ConnectionId = 'conn_abc123';
const GRANT: GrantId = 'grt_abc123';
const CLIENT = 'acme-app';
const AGENT = 'agt_1';
const GOOGLE_PREFIX = 'https://www.googleapis.com/auth/';

function makeConnection(overrides: Partial<Connection> = {}): Connection {
  return {
    id: CONN,
    org_id: 'org_default',
    client_id: CLIENT,
    provider: 'google',
    audience: 'https://www.googleapis.com',
    subject: 'user-123',
    subject_type: 'user',
    provider_account_id: 'google-sub-1',
    provider_scopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
    status: 'active',
    custody: 'self',
    version: 1,
    created_at: PAST,
    updated_at: PAST,
    ...overrides,
  };
}

function makeClient(overrides: Partial<LinkClient> = {}): LinkClient {
  return {
    client_id: CLIENT,
    org_id: 'org_default',
    name: 'Acme',
    redirect_uris: ['https://app.example.com/cred/return'],
    origins: ['https://app.example.com'],
    allow_raw_tokens: false,
    status: 'active',
    created_at: PAST,
    updated_at: PAST,
    token_endpoint_auth_method: 'client_secret_basic',
    client_secret_hash: 'x'.repeat(64),
    ...overrides,
  } as LinkClient;
}

function makeGrant(overrides: Partial<ClientGrant> = {}): ClientGrant {
  return {
    id: GRANT,
    org_id: 'org_default',
    client_id: CLIENT,
    audience: 'https://www.googleapis.com',
    subject: 'user-123',
    subject_type: 'user',
    scopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
    org_policy: { usage: 'allow' },
    authorization_details_types: [],
    connection_id: CONN,
    status: 'active',
    version: 3,
    granted_at: PAST,
    updated_at: PAST,
    ...overrides,
  };
}

interface FakeStoreState {
  clients: Map<string, LinkClient>;
  connections: Map<string, Connection>;
  grants: Map<string, ClientGrant>;
  calls: string[];
  throwOn?: string;
}

/**
 * A LinkStore fake that implements only the read methods the hooks may
 * call. Any other method throws, proving the hooks never write to the
 * store and never touch transactions or secrets.
 */
function makeStore(init: { connection?: Connection | null; grant?: ClientGrant | null; client?: LinkClient | null } = {}): {
  store: LinkStore;
  state: FakeStoreState;
} {
  const state: FakeStoreState = { clients: new Map(), connections: new Map(), grants: new Map(), calls: [] };
  const client = init.client === undefined ? makeClient() : init.client;
  if (client) state.clients.set(client.client_id, client);
  const connection = init.connection === undefined ? makeConnection() : init.connection;
  const grant = init.grant === undefined ? makeGrant() : init.grant;
  if (connection) state.connections.set(connection.id, connection);
  if (grant) state.grants.set(grant.connection_id, grant);

  const impl: Partial<LinkStore> = {
    async getClient(id: string) {
      state.calls.push('getClient');
      if (state.throwOn === 'getClient') throw new Error('store down');
      return state.clients.get(id) ?? null;
    },
    async getConnection(id: string) {
      state.calls.push('getConnection');
      if (state.throwOn === 'getConnection') throw new Error('store down');
      return state.connections.get(id) ?? null;
    },
    async getClientConnection({ client_id, connection_id }) {
      state.calls.push('getClientConnection');
      if (state.throwOn === 'getClientConnection') throw new Error('store down');
      const c = state.connections.get(connection_id);
      return c && c.client_id === client_id ? c : null;
    },
    async getGrantForConnection(id: string) {
      state.calls.push('getGrantForConnection');
      if (state.throwOn === 'getGrantForConnection') throw new Error('store down');
      return state.grants.get(id) ?? null;
    },
  };
  const store = new Proxy(impl, {
    get(target, prop: string) {
      if (prop in target) return (target as Record<string, unknown>)[prop];
      if (prop === 'then') return undefined;
      return () => {
        throw new Error(`LinkStore.${prop} must not be called by policy hooks`);
      };
    },
  }) as LinkStore;
  return { store, state };
}

interface FakePortOptions {
  /** Yield between reads and writes so concurrent callers interleave. */
  yieldBetween?: boolean;
  throwOn?: keyof LinkPermissionPort;
}

/**
 * In-memory LinkPermissionPort with a strict unique (agentId, connectionId)
 * constraint: create on an existing pair throws, like a plain INSERT would.
 */
function makePort(options: FakePortOptions = {}) {
  const rows = new Map<string, LinkPermission>();
  let seq = 0;
  const key = (a: string, c: string) => `${a}::${c}`;
  const tick = () => (options.yieldBetween ? new Promise((r) => setTimeout(r, 0)) : Promise.resolve());
  const clone = (p: LinkPermission): LinkPermission => ({ ...p, allowedScopes: [...p.allowedScopes] });
  const guard = (name: keyof LinkPermissionPort) => {
    if (options.throwOn === name) throw new Error(`port ${String(name)} failed`);
  };

  const port: LinkPermissionPort = {
    async get(agentId, connectionId) {
      guard('get');
      await tick();
      const row = rows.get(key(agentId, connectionId));
      return row ? clone(row) : null;
    },
    async list(agentId) {
      guard('list');
      return [...rows.values()].filter((r) => r.agentId === agentId).map(clone);
    },
    async create(input: LinkCreatePermissionInput) {
      guard('create');
      await tick();
      const k = key(input.agentId, input.connectionId);
      if (rows.has(k)) throw new Error('UNIQUE constraint failed: vault_permissions.agent_id, connection_id');
      const createdAt = new Date();
      const row: LinkPermission = {
        id: `perm_${++seq}`,
        createdAt,
        updatedAt: createdAt.toISOString(),
        ...input,
        allowedScopes: [...input.allowedScopes],
      };
      rows.set(k, row);
      return clone(row);
    },
    async update(id: string, input: LinkUpdatePermissionInput) {
      guard('update');
      await tick();
      const row = [...rows.values()].find((r) => r.id === id);
      if (!row) throw new Error(`Permission not found: ${id}`);
      Object.assign(row, input, { updatedAt: new Date().toISOString() });
      if ('expiresAt' in input && input.expiresAt === undefined) delete row.expiresAt;
      return clone(row);
    },
    async revoke(id) {
      guard('revoke');
      for (const [k, r] of rows) if (r.id === id) rows.delete(k);
    },
    async listForConnection(connectionId) {
      guard('listForConnection');
      return [...rows.values()].filter((r) => r.connectionId === connectionId).map(clone);
    },
    async intersectForConnection(connectionId, scopes) {
      guard('intersectForConnection');
      const bound = new Set(scopes.map((s) => s.replace(GOOGLE_PREFIX, '')));
      const changed: LinkPermission[] = [];
      for (const r of rows.values()) {
        if (r.connectionId !== connectionId) continue;
        const current = [...new Set(r.allowedScopes.map((s) => s.replace(GOOGLE_PREFIX, '')))].sort();
        const next = current.filter((s) => bound.has(s));
        if (!scopeSetsEqual(current, next)) {
          r.allowedScopes = next;
          r.updatedAt = new Date().toISOString();
          changed.push(clone(r));
        }
      }
      return changed;
    },
  };
  return { port, rows };
}

function seedPermission(
  rows: Map<string, LinkPermission>,
  overrides: Partial<LinkPermission> = {},
): LinkPermission {
  const createdAt = new Date(PAST);
  const p: LinkPermission = {
    id: 'perm_seed',
    agentId: AGENT,
    connectionId: CONN,
    allowedScopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
    requiresApproval: false,
    delegatable: false,
    maxDelegationDepth: 0,
    createdAt,
    updatedAt: createdAt.toISOString(),
    createdBy: `link:${CLIENT}`,
    ...overrides,
  };
  rows.set(`${p.agentId}::${p.connectionId}`, p);
  return p;
}

function check(overrides: Partial<LinkAccessCheckInput> = {}): LinkAccessCheckInput {
  return {
    operation: 'delegate',
    connection_id: CONN,
    agent_id: AGENT,
    provider: 'google',
    requested_scopes: ['calendar.readonly'],
    now: NOW,
    ...overrides,
  };
}

function setup(init: {
  connection?: Connection | null;
  grant?: ClientGrant | null;
  client?: LinkClient | null;
  port?: FakePortOptions;
  seed?: Partial<LinkPermission> | null;
} = {}) {
  const { store, state } = makeStore(init);
  const { port, rows } = makePort(init.port);
  if (init.seed !== null) seedPermission(rows, init.seed ?? {});
  const hooks = createLinkHooks({ store, permissions: port });
  return { hooks, store, state, port, rows };
}

// ── checkLinkAccess: the decision table, row by row ──────────────────────────

describe('createLinkHooks().checkLinkAccess decision table', () => {
  it('allows when connection, grant and permission all cover the request', async () => {
    const { hooks } = setup();
    const result = await hooks.checkLinkAccess(check());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.effective_scopes).toEqual(['calendar.readonly']);
    expect(result.connection.id).toBe(CONN);
    expect(result.grant.id).toBe(GRANT);
    expect(result.permission.agentId).toBe(AGENT);
  });

  describe('row 1: a blank requested scope -> permission_required (malformed, never "everything")', () => {
    it.each([[['']], [['   ']], [['/']], [['calendar.readonly', ' ']], [['\t\n']]])('%j', async (requested_scopes) => {
      const { hooks, state } = setup();
      const result = await hooks.checkLinkAccess(check({ requested_scopes }));
      expect(result).toEqual({ ok: false, code: 'permission_required', status: 403 });
      expect(state.calls).toEqual([]);
    });

    it('wins over every later row', async () => {
      const { hooks } = setup({ connection: null, grant: null, client: null, seed: null });
      const result = await hooks.checkLinkAccess(check({ connection_id: 'conn_unknown1', requested_scopes: [''] }));
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
    });

    it('an agent with a permission still cannot use a blank entry to mean "everything"', async () => {
      const { hooks } = setup();
      const blank = await hooks.checkLinkAccess(check({ requested_scopes: [' '] }));
      const all = await hooks.checkLinkAccess(check({ requested_scopes: [] }));
      expect(blank.ok).toBe(false);
      expect(all.ok).toBe(true);
    });
  });

  describe('row 2: unknown connection or provider mismatch -> permission_required', () => {
    it('unknown connection id', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ connection_id: 'conn_unknown1' }));
      expect(result).toEqual({ ok: false, code: 'permission_required', status: 403 });
    });

    it('malformed connection id is denied without touching the store', async () => {
      const { hooks, state } = setup();
      const result = await hooks.checkLinkAccess(check({ connection_id: 'github' }));
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
      expect(state.calls).toEqual([]);
    });

    it('provider mismatch', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ provider: 'github' }));
      expect(result).toMatchObject({ ok: false, code: 'permission_required', status: 403 });
    });

    it('provider omitted is not a mismatch', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ provider: undefined }));
      expect(result.ok).toBe(true);
    });

    it('row 2 wins over every later row', async () => {
      const { hooks } = setup({ grant: null, seed: null });
      const result = await hooks.checkLinkAccess(check({ provider: 'slack', agent_id: null }));
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
    });
  });

  describe("row 3: the connection's client unknown or not active -> grant_revoked", () => {
    it('client disabled by an operator', async () => {
      const { hooks } = setup({ client: makeClient({ status: 'disabled' }) });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toEqual({ ok: false, code: 'grant_revoked', status: 403 });
    });

    it('client unknown', async () => {
      const { hooks } = setup({ client: null });
      expect(await hooks.checkLinkAccess(check())).toMatchObject({ ok: false, code: 'grant_revoked' });
    });

    it('client record for a different id', async () => {
      const { hooks, state } = setup();
      state.clients.set(CLIENT, makeClient({ client_id: 'someone-else' }));
      expect(await hooks.checkLinkAccess(check())).toMatchObject({ ok: false, code: 'grant_revoked' });
    });

    it('looks the client up by the connection, not by anything the call names', async () => {
      const { hooks, state } = setup();
      const getClient = vi.spyOn(state.clients, 'get');
      await hooks.checkLinkAccess(check());
      expect(getClient).toHaveBeenCalledWith(CLIENT);
    });

    it('comes after row 2 (unknown connection) and before row 4 (connection status)', async () => {
      const unknown = setup({ client: null });
      expect(await unknown.hooks.checkLinkAccess(check({ connection_id: 'conn_unknown1' })))
        .toMatchObject({ code: 'permission_required' });
      const pending = setup({ client: makeClient({ status: 'disabled' }), connection: makeConnection({ status: 'pending' }) });
      expect(await pending.hooks.checkLinkAccess(check())).toMatchObject({ code: 'grant_revoked' });
    });

    it('a disabled client also denies an agent that holds a Permission (use)', async () => {
      const { hooks } = setup({ client: makeClient({ status: 'disabled' }) });
      const result = await hooks.checkLinkAccess(check({ operation: 'use', grant_id: GRANT }));
      expect(result).toMatchObject({ ok: false, code: 'grant_revoked' });
    });
  });

  describe('row 4: connection status not active', () => {
    it.each([
      ['pending', 'consent_required'],
      ['needs_reauth', 'reauth_required'],
      ['frozen', 'grant_reuse_detected'],
      ['revoked', 'grant_revoked'],
    ] as const)('%s -> %s', async (status, code) => {
      const { hooks } = setup({ connection: makeConnection({ status }) });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toEqual({ ok: false, code, status: LINK_MACHINE_ERROR_STATUS[code] });
    });

    it('status_reason wins when set', async () => {
      const { hooks } = setup({ connection: makeConnection({ status: 'needs_reauth', status_reason: 'grant_expired' }) });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'grant_expired' });
    });

    it('row 4 wins over a missing grant', async () => {
      const { hooks } = setup({ connection: makeConnection({ status: 'revoked' }), grant: null });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'grant_revoked' });
    });
  });

  describe('row 5: grant missing -> grant_revoked', () => {
    it('no grant for the connection', async () => {
      const { hooks } = setup({ grant: null });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toEqual({ ok: false, code: 'grant_revoked', status: 403 });
    });
  });

  describe('row 6: grant status not active, or expired', () => {
    it.each([
      ['pending', 'consent_required'],
      ['needs_reauth', 'reauth_required'],
      ['revoked', 'grant_revoked'],
      ['expired', 'grant_expired'],
    ] as const)('grant %s -> %s', async (status, code) => {
      const { hooks } = setup({ grant: makeGrant({ status }) });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code });
    });

    it('expires_at in the past -> grant_expired', async () => {
      const { hooks } = setup({ grant: makeGrant({ expires_at: PAST }) });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'grant_expired' });
    });

    it('expires_at equal to now -> grant_expired', async () => {
      const { hooks } = setup({ grant: makeGrant({ expires_at: NOW }) });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'grant_expired' });
    });

    it('expires_at in the future is fine', async () => {
      const { hooks } = setup({ grant: makeGrant({ expires_at: FUTURE }) });
      expect((await hooks.checkLinkAccess(check())).ok).toBe(true);
    });
  });

  describe('row 7: use with a different grant_id -> grant_revoked', () => {
    it('different grant id', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ operation: 'use', grant_id: 'grt_other1' }));
      expect(result).toMatchObject({ ok: false, code: 'grant_revoked' });
    });

    it('missing grant id on use', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ operation: 'use' }));
      expect(result).toMatchObject({ ok: false, code: 'grant_revoked' });
    });

    it('matching grant id with a stale grant_version still passes', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ operation: 'use', grant_id: GRANT, grant_version: 1 }));
      expect(result.ok).toBe(true);
    });

    it('delegate ignores grant_id', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ operation: 'delegate', grant_id: 'grt_other1' }));
      expect(result.ok).toBe(true);
    });
  });

  describe('row 8: no agent, no Permission, or expired Permission -> permission_required', () => {
    it('agent_id null', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ agent_id: null }));
      expect(result).toMatchObject({ ok: false, code: 'permission_required', missing_scopes: ['calendar.readonly'] });
    });

    it('deny by default: grant active but no Permission row for this agent', async () => {
      const { hooks } = setup({ seed: null });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
    });

    it('a Permission for another agent does not help', async () => {
      const { hooks } = setup({ seed: { agentId: 'agt_other' } });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
    });

    it('a Permission on another connection does not help', async () => {
      const { hooks } = setup({ seed: { connectionId: 'google' } });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
    });

    it('an expired Permission is treated as absent', async () => {
      const { hooks } = setup({ seed: { expiresAt: new Date(PAST) } });
      const result = await hooks.checkLinkAccess(check());
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
    });

    it('a Permission expiring in the future is fine', async () => {
      const { hooks } = setup({ seed: { expiresAt: new Date(FUTURE) } });
      expect((await hooks.checkLinkAccess(check())).ok).toBe(true);
    });

    it('row 8 wins over a scope outside the grant', async () => {
      const { hooks } = setup({ seed: null });
      const result = await hooks.checkLinkAccess(check({ requested_scopes: ['drive'] }));
      expect(result).toMatchObject({ ok: false, code: 'permission_required' });
    });
  });

  describe('row 9: requested scope outside grant.scopes -> insufficient_scope', () => {
    it('reports the missing scopes', async () => {
      const { hooks } = setup();
      const result = await hooks.checkLinkAccess(check({ requested_scopes: ['calendar.readonly', 'drive', 'gmail.readonly'] }));
      expect(result).toEqual({
        ok: false,
        code: 'insufficient_scope',
        status: 403,
        missing_scopes: ['drive', 'gmail.readonly'],
      });
    });

    it('wins over a scope outside the permission', async () => {
      const { hooks } = setup({ seed: { allowedScopes: ['calendar.readonly'] } });
      const result = await hooks.checkLinkAccess(check({ requested_scopes: ['gmail.send', 'drive'] }));
      expect(result).toMatchObject({ ok: false, code: 'insufficient_scope', missing_scopes: ['drive'] });
    });
  });

  describe('row 10: requested scope outside the permission -> permission_required', () => {
    it('reports the missing scopes', async () => {
      const { hooks } = setup({ seed: { allowedScopes: ['calendar.readonly'] } });
      const result = await hooks.checkLinkAccess(check({ requested_scopes: ['calendar.readonly', 'gmail.send'] }));
      expect(result).toEqual({
        ok: false,
        code: 'permission_required',
        status: 403,
        missing_scopes: ['gmail.send'],
      });
    });

    it('a stale Permission wider than the grant never widens the grant', async () => {
      const { hooks } = setup({
        grant: makeGrant({ scopes: ['calendar.readonly'] }),
        seed: { allowedScopes: ['calendar.readonly', 'gmail.send'] },
      });
      const denied = await hooks.checkLinkAccess(check({ requested_scopes: ['gmail.send'] }));
      expect(denied).toMatchObject({ ok: false, code: 'insufficient_scope', missing_scopes: ['gmail.send'] });
      const all = await hooks.checkLinkAccess(check({ requested_scopes: [] }));
      expect(all.ok && all.effective_scopes).toEqual(['calendar.readonly']);
    });
  });
});

// ── checkLinkAccess: effective scopes ────────────────────────────────────────

describe('createLinkHooks().checkLinkAccess effective_scopes', () => {
  it('empty request means everything: grant ∩ permission', async () => {
    const { hooks } = setup({ seed: { allowedScopes: ['calendar.readonly', 'gmail.send'] } });
    const result = await hooks.checkLinkAccess(check({ requested_scopes: [] }));
    expect(result.ok && result.effective_scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('is canonical: Google long and short names compare equal and come back short, sorted, deduplicated', async () => {
    const { hooks } = setup({
      grant: makeGrant({ scopes: ['calendar.readonly', `${GOOGLE_PREFIX}gmail.send`] }),
      seed: { allowedScopes: [`${GOOGLE_PREFIX}calendar.readonly`, 'gmail.send'] },
    });
    const result = await hooks.checkLinkAccess(check({
      requested_scopes: [`${GOOGLE_PREFIX}gmail.send/`, ' calendar.readonly ', 'HTTPS://WWW.GOOGLEAPIS.COM/AUTH/CALENDAR.READONLY', 'gmail.send'],
    }));
    expect(result.ok && result.effective_scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('a long-form request outside the grant reports the canonical short name', async () => {
    const { hooks } = setup();
    const result = await hooks.checkLinkAccess(check({ requested_scopes: [`${GOOGLE_PREFIX}drive.readonly`] }));
    expect(result).toMatchObject({ ok: false, code: 'insufficient_scope', missing_scopes: ['drive.readonly'] });
  });

  it('non-Google scopes keep their case', async () => {
    const { hooks } = setup({
      connection: makeConnection({ provider: 'github' }),
      grant: makeGrant({ scopes: ['read:user', 'repo'] }),
      seed: { allowedScopes: ['repo'] },
    });
    const ok = await hooks.checkLinkAccess(check({ provider: 'github', requested_scopes: ['repo'] }));
    expect(ok.ok && ok.effective_scopes).toEqual(['repo']);
    const upper = await hooks.checkLinkAccess(check({ provider: 'github', requested_scopes: ['REPO'] }));
    expect(upper).toMatchObject({ ok: false, code: 'insufficient_scope' });
  });

  it('an empty request that resolves to no scopes is denied, never "everything"', async () => {
    const { hooks } = setup({ seed: { allowedScopes: [] } });
    const result = await hooks.checkLinkAccess(check({ requested_scopes: [] }));
    expect(result).toEqual({ ok: false, code: 'permission_required', status: 403 });
  });
});

// ── checkLinkAccess: fail closed ─────────────────────────────────────────────

describe('createLinkHooks().checkLinkAccess fails closed', () => {
  it.each(['getConnection', 'getClient', 'getGrantForConnection'])('store.%s throws -> denial', async (method) => {
    const { hooks, state } = setup();
    state.throwOn = method;
    const result = await hooks.checkLinkAccess(check());
    expect(result).toEqual({ ok: false, code: LINK_CHECK_ERROR_CODE, status: 403 });
  });

  it('permission port get throws -> denial', async () => {
    const { store } = makeStore();
    const { port } = makePort({ throwOn: 'get' });
    const hooks = createLinkHooks({ store, permissions: port });
    const result = await hooks.checkLinkAccess(check());
    expect(result.ok).toBe(false);
    expect(result).toMatchObject({ code: 'permission_required' });
  });

  it('a store that returns a rejected non-Error value -> denial', async () => {
    const { port } = makePort();
    const store = {
      getConnection: async () => makeConnection(),
      getClient: () => Promise.reject('boom'),
      getGrantForConnection: () => Promise.reject('boom'),
    } as unknown as LinkStore;
    const result = await createLinkHooks({ store, permissions: port }).checkLinkAccess(check());
    expect(result.ok).toBe(false);
  });

  it('malformed input -> denial, not a throw', async () => {
    const { hooks } = setup();
    for (const bad of [
      check({ requested_scopes: 'calendar.readonly' as unknown as string[] }),
      check({ requested_scopes: [42 as unknown as string] }),
      check({ now: 'not a date' }),
      check({ operation: 'refresh' as unknown as 'use' }),
      null as unknown as LinkAccessCheckInput,
    ]) {
      const result = await hooks.checkLinkAccess(bad);
      expect(result.ok).toBe(false);
    }
  });

  it('reports caught errors to onCheckError and still denies when the reporter throws', async () => {
    const { store, state } = makeStore();
    state.throwOn = 'getConnection';
    const { port } = makePort();
    const onCheckError = vi.fn(() => {
      throw new Error('logger broken');
    });
    const hooks = createLinkHooks({ store, permissions: port }, { onCheckError });
    const result = await hooks.checkLinkAccess(check());
    expect(result.ok).toBe(false);
    expect(onCheckError).toHaveBeenCalledOnce();
    expect((onCheckError.mock.calls[0] as unknown[])[0]).toBeInstanceOf(Error);
  });

  it('an unknown stored status fails closed', async () => {
    const { hooks } = setup({ grant: makeGrant({ status: 'weird' as unknown as 'active' }) });
    const result = await hooks.checkLinkAccess(check());
    expect(result).toMatchObject({ ok: false, code: 'grant_revoked' });
  });

  it('an unreadable grant expiry fails closed', async () => {
    const { hooks } = setup({ grant: makeGrant({ expires_at: 'soon' }) });
    expect(await hooks.checkLinkAccess(check())).toMatchObject({ ok: false, code: 'grant_expired' });
  });
});

// ── onActivate ───────────────────────────────────────────────────────────────

describe('createLinkHooks().onActivate', () => {
  const activate = (agent_id: string | null, grant = makeGrant()) => ({
    intent: 'connect' as const,
    connection: makeConnection(),
    grant,
    agent_id,
    tid: 'ltx_abc' as const,
    actor: `link:${CLIENT}`,
  });

  it('seeds the agent Permission with grant.scopes and the Link defaults', async () => {
    const { hooks, port } = setup({ seed: null });
    await hooks.onActivate(activate(AGENT));
    const permission = await port.get(AGENT, CONN);
    expect(permission).toMatchObject({
      agentId: AGENT,
      connectionId: CONN,
      allowedScopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
      ...LINK_PERMISSION_DEFAULTS,
      createdBy: `link:${CLIENT}`,
    });
  });

  it('stores scopes in canonical form', async () => {
    const { hooks, port } = setup({ seed: null });
    await hooks.onActivate(activate(AGENT, makeGrant({ scopes: [`${GOOGLE_PREFIX}gmail.send`, 'calendar.readonly'] })));
    expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('is a no-op without agent_id: the grant carries no agent and nobody gets access', async () => {
    const { hooks, port, rows } = setup({ seed: null });
    await hooks.onActivate(activate(null));
    expect(rows.size).toBe(0);
    expect(await port.listForConnection(CONN)).toEqual([]);
    const result = await hooks.checkLinkAccess(check({ requested_scopes: [] }));
    expect(result).toMatchObject({ ok: false, code: 'permission_required' });
  });

  it('is idempotent: repeated activation updates the one row', async () => {
    const { hooks, rows } = setup({ seed: null });
    await hooks.onActivate(activate(AGENT));
    await hooks.onActivate(activate(AGENT));
    await hooks.onActivate(activate(AGENT, makeGrant({ scopes: ['calendar.readonly'] })));
    expect(rows.size).toBe(1);
    expect([...rows.values()][0].allowedScopes).toEqual(['calendar.readonly']);
  });

  it('upserts over an existing row and resets it to the Link defaults', async () => {
    const { hooks, rows } = setup({ seed: { delegatable: true, maxDelegationDepth: 3, allowedScopes: ['calendar.readonly'] } });
    await hooks.onActivate(activate(AGENT));
    expect(rows.size).toBe(1);
    expect([...rows.values()][0]).toMatchObject({
      id: 'perm_seed',
      allowedScopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
      delegatable: false,
      maxDelegationDepth: 0,
    });
  });

  it('does not create duplicates when activations race', async () => {
    const { store } = makeStore();
    const { port, rows } = makePort({ yieldBetween: true });
    const hooks = createLinkHooks({ store, permissions: port });
    await Promise.all([hooks.onActivate(activate(AGENT)), hooks.onActivate(activate(AGENT)), hooks.onActivate(activate(AGENT))]);
    expect(rows.size).toBe(1);
  });

  it('throws when the grant belongs to another connection', async () => {
    const { hooks } = setup({ seed: null });
    await expect(hooks.onActivate(activate(AGENT, makeGrant({ connection_id: 'conn_other1' })))).rejects.toThrow();
  });

  it('propagates port errors (the server answers server_error)', async () => {
    const { store } = makeStore();
    const { port } = makePort({ throwOn: 'create' });
    const hooks = createLinkHooks({ store, permissions: port });
    await expect(hooks.onActivate(activate(AGENT))).rejects.toThrow();
  });
});

// ── onGrantUpdated ───────────────────────────────────────────────────────────

describe('createLinkHooks().onGrantUpdated', () => {
  it('intersects every Permission on the connection with grant.scopes', async () => {
    const { hooks, rows, port } = setup({ seed: null });
    seedPermission(rows, { id: 'perm_a', agentId: 'agt_a', allowedScopes: ['calendar.events', 'calendar.readonly', 'gmail.send'] });
    seedPermission(rows, { id: 'perm_b', agentId: 'agt_b', allowedScopes: ['gmail.send'] });
    seedPermission(rows, { id: 'perm_c', agentId: 'agt_c', connectionId: 'conn_other1', allowedScopes: ['gmail.send'] });
    const spy = vi.spyOn(port, 'intersectForConnection');

    const grant = makeGrant({ scopes: ['calendar.readonly'], version: 4 });
    await hooks.onGrantUpdated({ grant, previous_scopes: ['calendar.events', 'calendar.readonly', 'gmail.send'], reason: 'narrow' });

    expect(spy).toHaveBeenCalledWith(CONN, ['calendar.readonly']);
    expect((await port.get('agt_a', CONN))?.allowedScopes).toEqual(['calendar.readonly']);
    expect((await port.get('agt_b', CONN))?.allowedScopes).toEqual([]);
    expect((await port.get('agt_c', 'conn_other1'))?.allowedScopes).toEqual(['gmail.send']);
    for (const p of await port.listForConnection(CONN)) {
      expect(isScopeSubset(p.allowedScopes, grant.scopes)).toBe(true);
    }
  });

  it('never widens when the grant grows', async () => {
    const { hooks, port } = setup({ seed: { allowedScopes: ['calendar.readonly'] } });
    await hooks.onGrantUpdated({
      grant: makeGrant({ scopes: ['calendar.readonly', 'drive.file', 'gmail.send'] }),
      previous_scopes: ['calendar.readonly'],
      reason: 'activate',
    });
    expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual(['calendar.readonly']);
  });

  describe('previous_scopes bound (a missed earlier call cannot be undone by a widening)', () => {
    const CAL = 'calendar.readonly';
    const SEND = 'gmail.send';

    it('review example: a narrowing whose intersect was missed, then a widening, leaves agent A at the narrowed scopes', async () => {
      // Grant [calendar, gmail.send]; agent A holds both.
      const { hooks, port, state } = setup({ grant: makeGrant({ scopes: [CAL, SEND] }), seed: { allowedScopes: [CAL, SEND] } });

      // A narrowing commits grant [calendar]; its onGrantUpdated call is missed.
      state.grants.set(CONN, makeGrant({ scopes: [CAL], version: 4 }));

      // A later update for another agent widens the grant back.
      const widened = makeGrant({ scopes: [CAL, SEND], version: 5 });
      state.grants.set(CONN, widened);
      await hooks.onGrantUpdated({ grant: widened, previous_scopes: [CAL], reason: 'activate' });
      await hooks.onActivate({
        intent: 'update',
        connection: makeConnection(),
        grant: widened,
        agent_id: 'agt_b',
        tid: 'ltx_abc',
        actor: `link:${CLIENT}`,
      });

      expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual([CAL]);
      expect((await port.get('agt_b', CONN))?.allowedScopes).toEqual([CAL, SEND]);
      expect(await hooks.checkLinkAccess(check({ requested_scopes: [SEND] })))
        .toMatchObject({ ok: false, code: 'permission_required', missing_scopes: [SEND] });
      expect((await hooks.checkLinkAccess(check({ agent_id: 'agt_b', requested_scopes: [SEND] }))).ok).toBe(true);
    });

    it('a Permission within the previous scopes is untouched by a widening', async () => {
      const { hooks, port } = setup({ seed: { allowedScopes: [CAL] } });
      const before = await port.get(AGENT, CONN);
      const spy = vi.spyOn(port, 'intersectForConnection');
      await hooks.onGrantUpdated({ grant: makeGrant({ scopes: [CAL, SEND] }), previous_scopes: [CAL], reason: 'activate' });
      expect(spy).toHaveBeenCalledOnce();
      expect(await spy.mock.results[0].value).toEqual([]);
      expect(await port.get(AGENT, CONN)).toEqual(before);
    });

    it('a narrowing still narrows', async () => {
      const { hooks, port } = setup({ seed: { allowedScopes: [CAL, SEND] } });
      await hooks.onGrantUpdated({ grant: makeGrant({ scopes: [CAL] }), previous_scopes: [CAL, SEND], reason: 'narrow' });
      expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual([CAL]);
    });

    it('previous_scopes equal to grant.scopes (a repair or heal) is the plain grant intersect', async () => {
      const { hooks, port } = setup({ seed: { allowedScopes: ['calendar.events', CAL, SEND] } });
      const spy = vi.spyOn(port, 'intersectForConnection');
      const grant = makeGrant({ scopes: [SEND, CAL] });
      await hooks.onGrantUpdated({ grant, previous_scopes: grant.scopes, reason: 'activate' });
      expect(spy).toHaveBeenCalledOnce();
      expect(spy).toHaveBeenCalledWith(CONN, [CAL, SEND]);
      expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual([CAL, SEND]);
    });

    it('uses one store operation with the canonical intersection of grant and previous scopes', async () => {
      const { hooks, port } = setup({ seed: null });
      const spy = vi.spyOn(port, 'intersectForConnection');
      await hooks.onGrantUpdated({
        grant: makeGrant({ scopes: [`${GOOGLE_PREFIX}gmail.send`, CAL, 'drive.file'] }),
        previous_scopes: [SEND, `${GOOGLE_PREFIX}calendar.readonly/`, 'calendar.events'],
        reason: 'activate',
      });
      expect(spy).toHaveBeenCalledOnce();
      expect(spy).toHaveBeenCalledWith(CONN, [CAL, SEND]);
    });

    it('long-form and short-form Google names in previous_scopes match canonically', async () => {
      const { hooks, port } = setup({ seed: { allowedScopes: [CAL, SEND] } });
      await hooks.onGrantUpdated({
        grant: makeGrant({ scopes: [CAL, SEND, 'drive.file'] }),
        previous_scopes: [`${GOOGLE_PREFIX}calendar.readonly`, `${GOOGLE_PREFIX}gmail.send`],
        reason: 'activate',
      });
      expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual([CAL, SEND]);
    });

    it('a long-form previous_scopes still clips what it does not name', async () => {
      const { hooks, port } = setup({ seed: { allowedScopes: [CAL, SEND] } });
      await hooks.onGrantUpdated({
        grant: makeGrant({ scopes: [CAL, SEND] }),
        previous_scopes: [`${GOOGLE_PREFIX.toUpperCase()}CALENDAR.READONLY`],
        reason: 'activate',
      });
      expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual([CAL]);
    });

    it('an empty previous_scopes empties every Permission on the connection', async () => {
      const { hooks, port, rows } = setup({ seed: { allowedScopes: [CAL, SEND] } });
      seedPermission(rows, { id: 'perm_b', agentId: 'agt_b', allowedScopes: [CAL] });
      await hooks.onGrantUpdated({ grant: makeGrant({ scopes: [CAL, SEND] }), previous_scopes: [], reason: 'activate' });
      const all = await port.listForConnection(CONN);
      expect(all).toHaveLength(2);
      for (const p of all) expect(p.allowedScopes).toEqual([]);
    });

    it('a malformed previous_scopes throws and writes nothing', async () => {
      const { hooks, port } = setup({ seed: { allowedScopes: [CAL, SEND] } });
      const spy = vi.spyOn(port, 'intersectForConnection');
      for (const bad of [undefined, 'calendar.readonly', [CAL, 3]]) {
        await expect(hooks.onGrantUpdated({
          grant: makeGrant({ scopes: [CAL] }),
          previous_scopes: bad as unknown as string[],
          reason: 'narrow',
        })).rejects.toThrow(TypeError);
      }
      expect(spy).not.toHaveBeenCalled();
      expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual([CAL, SEND]);
    });

    it('never widens, whatever previous_scopes says', async () => {
      const { hooks, port } = setup({ seed: { allowedScopes: [CAL] } });
      await hooks.onGrantUpdated({
        grant: makeGrant({ scopes: [CAL, SEND, 'drive.file'] }),
        previous_scopes: [CAL, SEND, 'drive.file'],
        reason: 'activate',
      });
      expect((await port.get(AGENT, CONN))?.allowedScopes).toEqual([CAL]);
    });
  });
});

// ── setAgentPermission ───────────────────────────────────────────────────────

describe('createLinkHooks().setAgentPermission', () => {
  const set = (overrides: Partial<{ client_id: string; connection_id: ConnectionId; agent_id: string; scopes: string[]; actor: string }> = {}) => ({
    client_id: CLIENT,
    connection_id: CONN,
    agent_id: 'agt_2',
    scopes: ['calendar.readonly'],
    actor: `link:${CLIENT}`,
    ...overrides,
  });

  it('upserts exactly the given scopes with the Link defaults', async () => {
    const { hooks, port } = setup({ seed: null });
    const result = await hooks.setAgentPermission(set({ scopes: ['gmail.send', `${GOOGLE_PREFIX}calendar.readonly`] }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.permission).toMatchObject({
      agentId: 'agt_2',
      connectionId: CONN,
      allowedScopes: ['calendar.readonly', 'gmail.send'],
      ...LINK_PERMISSION_DEFAULTS,
    });
    expect(await port.get('agt_2', CONN)).toMatchObject({ allowedScopes: ['calendar.readonly', 'gmail.send'] });

    const narrowed = await hooks.setAgentPermission(set({ scopes: ['gmail.send'] }));
    expect(narrowed.ok && narrowed.permission.allowedScopes).toEqual(['gmail.send']);
    expect((await port.listForConnection(CONN)).length).toBe(1);
  });

  it('rejects scopes outside grant.scopes with invalid_scope', async () => {
    const { hooks, rows } = setup({ seed: null });
    const result = await hooks.setAgentPermission(set({ scopes: ['calendar.readonly', 'drive'] }));
    expect(result).toEqual({ ok: false, error: 'invalid_scope', status: 400 });
    expect(rows.size).toBe(0);
  });

  it('rejects malformed scopes with invalid_scope', async () => {
    const { hooks } = setup({ seed: null });
    const result = await hooks.setAgentPermission(set({ scopes: [7 as unknown as string] }));
    expect(result).toMatchObject({ ok: false, error: 'invalid_scope' });
  });

  it.each([[['']], [['  ']], [['/']], [['calendar.readonly', '']]])('rejects a blank entry %j with invalid_scope and writes nothing', async (scopes) => {
    const { hooks, rows, state } = setup({ seed: null });
    const result = await hooks.setAgentPermission(set({ scopes }));
    expect(result).toEqual({ ok: false, error: 'invalid_scope', status: 400 });
    expect(rows.size).toBe(0);
    expect(state.calls).toEqual([]);
  });

  it('refuses a connection owned by another client with the opaque-failure status', async () => {
    const { hooks, rows } = setup({ seed: null });
    const result = await hooks.setAgentPermission(set({ client_id: 'evil-app' }));
    expect(result).toEqual({ ok: false, error: 'permission_required', status: 401 });
    expect(rows.size).toBe(0);
  });

  it('refuses an unknown connection the same way as a foreign one', async () => {
    const { hooks } = setup({ seed: null });
    const unknown = await hooks.setAgentPermission(set({ connection_id: 'conn_nothere1' }));
    const foreign = await hooks.setAgentPermission(set({ client_id: 'evil-app' }));
    expect(unknown).toEqual(foreign);
  });

  it.each([
    ['pending', 'consent_required'],
    ['needs_reauth', 'reauth_required'],
    ['revoked', 'grant_revoked'],
    ['expired', 'grant_expired'],
  ] as const)('refuses when the grant is %s', async (status, error) => {
    const { hooks, rows } = setup({ seed: null, grant: makeGrant({ status }) });
    const result = await hooks.setAgentPermission(set());
    expect(result).toEqual({ ok: false, error, status: 403 });
    expect(rows.size).toBe(0);
  });

  it('refuses when the grant has expired by time', async () => {
    const { hooks } = setup({ seed: null, grant: makeGrant({ expires_at: '2000-01-01T00:00:00.000Z' }) });
    expect(await hooks.setAgentPermission(set())).toMatchObject({ ok: false, error: 'grant_expired' });
  });

  it('refuses when the grant is missing', async () => {
    const { hooks } = setup({ seed: null, grant: null });
    expect(await hooks.setAgentPermission(set())).toMatchObject({ ok: false, error: 'grant_revoked' });
  });

  it('refuses when the connection is not active', async () => {
    const { hooks } = setup({ seed: null, connection: makeConnection({ status: 'frozen' }) });
    expect(await hooks.setAgentPermission(set())).toMatchObject({ ok: false, error: 'grant_reuse_detected' });
  });

  it('throws on an empty agent id (the server validates the body first)', async () => {
    const { hooks } = setup({ seed: null });
    await expect(hooks.setAgentPermission(set({ agent_id: '' }))).rejects.toThrow(TypeError);
  });

  it('re-applies the grant bound if the grant narrowed during the write', async () => {
    const { store, state } = makeStore();
    const { port } = makePort();
    const realCreate = port.create.bind(port);
    port.create = async (input) => {
      // The grant narrows between the subset check and the write.
      state.grants.set(CONN, makeGrant({ scopes: ['calendar.readonly'], version: 4 }));
      return realCreate(input);
    };
    const hooks = createLinkHooks({ store, permissions: port });
    const result = await hooks.setAgentPermission(set({ scopes: ['calendar.readonly', 'gmail.send'] }));
    expect(result.ok && result.permission.allowedScopes).toEqual(['calendar.readonly']);
    expect((await port.get('agt_2', CONN))?.allowedScopes).toEqual(['calendar.readonly']);
  });

  it('clears an expiry that already passed, keeps one still in force', async () => {
    const { hooks, port, rows } = setup({ seed: { agentId: 'agt_2', expiresAt: new Date('2000-01-01T00:00:00.000Z') } });
    await hooks.setAgentPermission(set());
    expect((await port.get('agt_2', CONN))?.expiresAt).toBeUndefined();

    rows.clear();
    const future = new Date(Date.now() + 86_400_000);
    seedPermission(rows, { agentId: 'agt_2', expiresAt: future });
    await hooks.setAgentPermission(set());
    expect((await port.get('agt_2', CONN))?.expiresAt).toEqual(future);
  });

  it('only reads from the store', async () => {
    const { hooks, state } = setup({ seed: null });
    await hooks.setAgentPermission(set());
    expect(new Set(state.calls)).toEqual(new Set(['getClientConnection', 'getGrantForConnection']));
  });
});

describe('createLinkHooks() factory', () => {
  it('requires both dependencies', () => {
    const { store } = makeStore();
    expect(() => createLinkHooks({ store, permissions: undefined as unknown as LinkPermissionPort })).toThrow(TypeError);
  });
});
