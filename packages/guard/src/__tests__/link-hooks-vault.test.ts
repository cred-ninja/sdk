/**
 * End to end: createLinkHooks over the real @credninja/vault permission
 * store (SQLite, temp file) through CredVault.getLinkPermissionPort(), with
 * a small in-memory LinkStore fake for connections and grants.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { CredVault } from '@credninja/vault';
import { isScopeSubset } from '@credninja/protocol';
import type { ClientGrant, Connection, LinkHooks, LinkPermissionPort, LinkStore } from '@credninja/protocol';
import { createLinkHooks } from '../link/hooks.js';

const CONN = 'conn_e2e1';
const CLIENT = 'acme-app';
const NOW = () => new Date().toISOString();
const G = 'https://www.googleapis.com/auth/';

function connection(): Connection {
  return {
    id: CONN,
    org_id: 'org_default',
    client_id: CLIENT,
    provider: 'google',
    audience: 'https://www.googleapis.com',
    subject: 'user-123',
    subject_type: 'user',
    provider_account_id: 'sub-1',
    provider_scopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
    status: 'active',
    custody: 'self',
    version: 1,
    created_at: NOW(),
    updated_at: NOW(),
  };
}

function grant(scopes: string[], version = 1): ClientGrant {
  return {
    id: 'grt_e2e1',
    org_id: 'org_default',
    client_id: CLIENT,
    audience: 'https://www.googleapis.com',
    subject: 'user-123',
    subject_type: 'user',
    scopes,
    org_policy: { usage: 'allow' },
    authorization_details_types: [],
    connection_id: CONN,
    status: 'active',
    version,
    granted_at: NOW(),
    updated_at: NOW(),
  };
}

describe('Link hooks over the real vault permission store', () => {
  let dir: string;
  let vault: CredVault;
  let port: LinkPermissionPort;
  let hooks: LinkHooks;
  let current: { connection: Connection; grant: ClientGrant };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'cred-link-hooks-'));
    vault = new CredVault({ passphrase: 'test-passphrase', storage: 'sqlite', path: join(dir, 'vault.db') });
    port = vault.getLinkPermissionPort();
    current = { connection: connection(), grant: grant(['calendar.events', 'calendar.readonly', 'gmail.send']) };
    const store = {
      getClient: async (id: string) => (id === CLIENT ? { client_id: CLIENT, status: 'active' } : null),
      getConnection: async (id: string) => (id === CONN ? current.connection : null),
      getClientConnection: async ({ client_id, connection_id }: { client_id: string; connection_id: string }) =>
        connection_id === CONN && client_id === current.connection.client_id ? current.connection : null,
      getGrantForConnection: async (id: string) => (id === CONN ? current.grant : null),
    } as unknown as LinkStore;
    hooks = createLinkHooks({ store, permissions: port });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function expectPermissionsWithinGrant(): Promise<void> {
    for (const p of await port.listForConnection(CONN)) {
      expect(isScopeSubset(p.allowedScopes, current.grant.scopes)).toBe(true);
    }
  }

  const access = (agent_id: string | null, requested_scopes: string[]) =>
    hooks.checkLinkAccess({ operation: 'delegate', connection_id: CONN, agent_id, provider: 'google', requested_scopes, now: NOW() });

  it('runs the full lifecycle with the port contract holding end to end', async () => {
    // Deny by default: an active grant alone is unusable.
    expect(await access('agt_1', [])).toMatchObject({ ok: false, code: 'permission_required' });

    // Activation seeds the agent (racing activations still leave one row).
    const activation = {
      intent: 'connect' as const,
      connection: current.connection,
      grant: current.grant,
      agent_id: 'agt_1',
      tid: 'ltx_e2e1' as const,
      actor: `link:${CLIENT}`,
    };
    await Promise.all([hooks.onActivate(activation), hooks.onActivate(activation), hooks.onActivate(activation)]);
    const seeded = await port.listForConnection(CONN);
    expect(seeded).toHaveLength(1);
    expect(seeded[0]).toMatchObject({
      agentId: 'agt_1',
      allowedScopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
      delegatable: false,
      maxDelegationDepth: 0,
      requiresApproval: false,
      createdBy: `link:${CLIENT}`,
    });
    await expectPermissionsWithinGrant();

    // Long Google names resolve to the canonical short ones.
    const ok = await access('agt_1', [`${G}calendar.readonly`]);
    expect(ok.ok && ok.effective_scopes).toEqual(['calendar.readonly']);

    // A second agent within the grant; a superset is refused; a foreign client is refused.
    expect((await hooks.setAgentPermission({ client_id: CLIENT, connection_id: CONN, agent_id: 'agt_2', scopes: ['gmail.send'], actor: 'x' })).ok).toBe(true);
    expect(await hooks.setAgentPermission({ client_id: CLIENT, connection_id: CONN, agent_id: 'agt_3', scopes: ['drive'], actor: 'x' }))
      .toMatchObject({ ok: false, error: 'invalid_scope' });
    expect(await hooks.setAgentPermission({ client_id: 'other', connection_id: CONN, agent_id: 'agt_3', scopes: ['gmail.send'], actor: 'x' }))
      .toMatchObject({ ok: false, status: 401 });
    expect(await port.get('agt_3', CONN)).toBeNull();
    expect(await access('agt_2', ['calendar.readonly'])).toMatchObject({ ok: false, code: 'permission_required', missing_scopes: ['calendar.readonly'] });

    // A legacy (provider-slug) permission for the same agent is untouched by Link narrowing.
    await vault.createPermission({
      agentId: 'agt_1', connectionId: 'google', allowedScopes: ['gmail.send'],
      requiresApproval: false, delegatable: true, maxDelegationDepth: 1, createdBy: 'admin',
    });

    // The grant narrows: every permission on the connection follows.
    const previous = current.grant.scopes;
    current.grant = grant(['calendar.readonly'], 2);
    await hooks.onGrantUpdated({ grant: current.grant, previous_scopes: previous, reason: 'narrow' });
    await expectPermissionsWithinGrant();
    expect((await port.get('agt_1', CONN))?.allowedScopes).toEqual(['calendar.readonly']);
    expect((await port.get('agt_2', CONN))?.allowedScopes).toEqual([]);
    expect((await vault.getPermission('agt_1', 'google'))?.allowedScopes).toEqual(['gmail.send']);
    expect(await access('agt_1', ['gmail.send'])).toMatchObject({ ok: false, code: 'insufficient_scope' });
    expect(await access('agt_2', [])).toMatchObject({ ok: false, code: 'permission_required' });

    // An expired Permission is absent.
    const p1 = await port.get('agt_1', CONN);
    await port.update(p1!.id, { expiresAt: new Date(Date.now() - 1000) });
    expect(await access('agt_1', ['calendar.readonly'])).toMatchObject({ ok: false, code: 'permission_required' });

    // Re-setting the permission clears the lapsed expiry and stays within the grant.
    const reset = await hooks.setAgentPermission({ client_id: CLIENT, connection_id: CONN, agent_id: 'agt_1', scopes: ['calendar.readonly'], actor: 'x' });
    expect(reset.ok).toBe(true);
    expect((await access('agt_1', ['calendar.readonly'])).ok).toBe(true);
    expect(await port.listForConnection(CONN)).toHaveLength(2);
    await expectPermissionsWithinGrant();
  });

  it('onActivate racing itself on the real vault port ends with exactly one row, within the grant', async () => {
    // The real vault does not throw on a duplicate create: it upserts on
    // (agent_id, connection_id) and replaces the row id. Prove the race
    // still converges on one usable row whose id matches what get() returns.
    const activation = {
      intent: 'connect' as const,
      connection: current.connection,
      grant: current.grant,
      agent_id: 'agt_race',
      tid: 'ltx_race1' as const,
      actor: `link:${CLIENT}`,
    };
    await Promise.all(Array.from({ length: 12 }, () => hooks.onActivate(activation)));

    const rows = await port.listForConnection(CONN);
    expect(rows).toHaveLength(1);
    expect(rows[0].agentId).toBe('agt_race');
    expect(rows[0].allowedScopes).toEqual(current.grant.scopes);
    expect((await port.get('agt_race', CONN))?.id).toBe(rows[0].id);
    expect((await vault.listPermissions('agt_race')).map((p) => p.id)).toEqual([rows[0].id]);
    await expectPermissionsWithinGrant();
    const result = await access('agt_race', []);
    expect(result.ok && result.permission.id).toBe(rows[0].id);
  });

  it('onActivate racing a grant narrowing on the real vault port ends within the narrowed grant', async () => {
    const wide = current.grant;
    const activation = {
      intent: 'connect' as const,
      connection: current.connection,
      grant: wide,
      agent_id: 'agt_race',
      tid: 'ltx_race2' as const,
      actor: `link:${CLIENT}`,
    };
    const narrowed = grant(['calendar.readonly'], 2);
    await Promise.all([
      hooks.onActivate(activation),
      hooks.onActivate(activation),
      (async () => {
        current.grant = narrowed;
        await hooks.onGrantUpdated({ grant: narrowed, previous_scopes: wide.scopes, reason: 'narrow' });
      })(),
      hooks.onActivate(activation),
    ]);

    const rows = await port.listForConnection(CONN);
    expect(rows).toHaveLength(1);
    expect(rows[0].allowedScopes).toEqual(['calendar.readonly']);
    await expectPermissionsWithinGrant();
    expect(await access('agt_race', ['gmail.send'])).toMatchObject({ ok: false, code: 'insufficient_scope' });
  });

  it('a missed narrowing intersect is not undone by a later widening (previous_scopes bound)', async () => {
    const CAL = 'calendar.readonly';
    const SEND = 'gmail.send';
    current.grant = grant([CAL, SEND], 1);
    const activate = (agent_id: string, g: ClientGrant, tid: `ltx_${string}`) => hooks.onActivate({
      intent: 'update', connection: current.connection, grant: g, agent_id, tid, actor: `link:${CLIENT}`,
    });
    await activate('agt_a', current.grant, 'ltx_v1');
    expect((await port.get('agt_a', CONN))?.allowedScopes).toEqual([CAL, SEND]);

    // A narrowing commits grant [calendar]; its onGrantUpdated call is missed.
    current.grant = grant([CAL], 2);

    // A later update for another agent widens the grant back.
    const widened = grant([CAL, SEND], 3);
    current.grant = widened;
    await hooks.onGrantUpdated({ grant: widened, previous_scopes: [`${G}calendar.readonly`], reason: 'activate' });
    await activate('agt_b', widened, 'ltx_v3');

    expect((await port.get('agt_a', CONN))?.allowedScopes).toEqual([CAL]);
    expect((await port.get('agt_b', CONN))?.allowedScopes).toEqual([CAL, SEND]);
    expect(await access('agt_a', [SEND])).toMatchObject({ ok: false, code: 'permission_required' });
    expect((await access('agt_b', [SEND])).ok).toBe(true);
    await expectPermissionsWithinGrant();

    // A repair that re-applies the current grant changes nothing further.
    await hooks.onGrantUpdated({ grant: widened, previous_scopes: widened.scopes, reason: 'activate' });
    expect((await port.get('agt_a', CONN))?.allowedScopes).toEqual([CAL]);
    expect((await port.get('agt_b', CONN))?.allowedScopes).toEqual([CAL, SEND]);
  });

  it('a file-backed vault refuses to hand out a Link permission port', () => {
    const fileVault = new CredVault({ passphrase: 'p', storage: 'file', path: join(dir, 'vault.json') });
    expect(() => fileVault.getLinkPermissionPort()).toThrow(/not supported/);
  });
});
