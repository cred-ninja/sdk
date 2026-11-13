/**
 * Local mode is in-process trusted vault access, not an HTTP actor verifier, but
 * the row that authorizes a handoff must still be the right row: the Permission
 * of the agent handing off, not only of the agent receiving. Uses a real
 * encrypted sqlite vault and genuinely signed receipts, so nothing here can pass
 * by mocking the authorization it is testing.
 */
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Cred, generateAgentIdentity, type AgentIdentity } from '../index';
import { CredVault } from '@credninja/vault';

const PASSPHRASE = 'test-passphrase-grantor-local';
const SCOPES = ['repo', 'read:user'];
const dirs: string[] = [];

function dir(): string {
  const made = mkdtempSync(join(tmpdir(), 'cred-grantor-sdk-'));
  dirs.push(made);
  return made;
}

afterAll(() => {
  for (const made of dirs) rmSync(made, { recursive: true, force: true });
});

type Gate = { delegatable: boolean; maxDelegationDepth: number };
/** A Permission row fixture: the gate plus, optionally, narrower scopes or an expiry. */
type Row = Gate & { allowedScopes?: string[]; expiresAt?: Date };
type RoleName = 'origin' | 'parent' | 'child';

/** A real vault with a synthetic stored token, one agent record and optional Permission per role. */
async function setup(rows: Partial<Record<RoleName | 'parentByDid' | 'ghost', Row>>, stored: string[] = SCOPES) {
  const where = dir();
  const options = { passphrase: PASSPHRASE, path: join(where, 'vault.sqlite'), storage: 'sqlite' as const };
  const vault = new CredVault(options);
  await vault.init();
  await vault.store({
    provider: 'github',
    userId: 'alice',
    accessToken: 'synthetic-provider-token',
    scopes: stored,
    expiresAt: new Date(Date.now() + 3_600_000),
  });
  const agents = {} as Record<RoleName | 'ghost', AgentIdentity>;
  for (const role of ['origin', 'parent', 'child', 'ghost'] as const) {
    const agent = await generateAgentIdentity();
    agents[role] = agent;
    // `ghost` is deliberately left unregistered: no agent record and no
    // Permission row, the legacy shape this change must not narrow.
    if (role === 'ghost') continue;
    const now = new Date().toISOString();
    await vault.registerAgent({
      id: `agt_${role}`,
      did: agent.did,
      name: role,
      fingerprint: `fp_${role}`,
      scopeCeiling: [],
      status: 'active',
      createdBy: 'test',
      createdAt: now,
      updatedAt: now,
    });
  }
  const grant = async (agentId: string, row: Row) => vault.createPermission({
    agentId,
    connectionId: 'github',
    requiresApproval: false,
    createdBy: 'test',
    ...row,
    allowedScopes: row.allowedScopes ?? SCOPES,
  });
  for (const role of ['origin', 'parent', 'child'] as const) {
    const gate = rows[role];
    if (gate) await grant(`agt_${role}`, gate);
  }
  if (rows.parentByDid) await grant(agents.parent.did, rows.parentByDid);
  const cred = new Cred({ mode: 'local', vault: options, providers: {}, requireAudit: true });
  return { cred, vault, agents };
}

const PERMISSIVE: Gate = { delegatable: true, maxDelegationDepth: 5 };

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Cred.subDelegate() local mode: the grantor's own Permission", () => {
  it('refuses a grantor whose Permission is not delegatable, before any credential read', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: false, maxDelegationDepth: 5 }, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    const get = vi.spyOn(CredVault.prototype, 'get');
    await expect(s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    })).rejects.toMatchObject({ code: 'delegation_not_allowed' });
    expect(get).not.toHaveBeenCalled();
  });

  it('refuses a grantor at its depth cap of 0', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: true, maxDelegationDepth: 0 }, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    const get = vi.spyOn(CredVault.prototype, 'get');
    await expect(s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    })).rejects.toMatchObject({ code: 'depth_exceeded' });
    expect(get).not.toHaveBeenCalled();
  });

  it("refuses one hop past a genuine depth-1 grantor's cap, and no receipt is signed", async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: true, maxDelegationDepth: 1 }, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.origin.did, scopes: SCOPES });
    const first = await s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES,
    });
    expect(first.chainDepth).toBe(1);
    const get = vi.spyOn(CredVault.prototype, 'get');
    await expect(s.cred.subDelegate({
      parentReceipt: first.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    })).rejects.toMatchObject({ code: 'depth_exceeded' });
    expect(get).not.toHaveBeenCalled();
  });

  it("allows the hop that lands exactly on the grantor's cap", async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: true, maxDelegationDepth: 1 }, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    const child = await s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    });
    expect(child.chainDepth).toBe(1);
    expect(child.scopes).toEqual(SCOPES);
    expect(child.accessToken).toBe('synthetic-provider-token');
    expect(child.receipt).toBeTypeOf('string');
  });

  it('takes the tighter of a grantor\'s record-id row and its DID row', async () => {
    // The record-id row would allow the hop; the DID row caps depth at 0.
    // Neither row may widen the other, so the hop is refused.
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, parentByDid: { delegatable: true, maxDelegationDepth: 0 }, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    await expect(s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    })).rejects.toMatchObject({ code: 'depth_exceeded' });
  });

  it("keeps the recipient's own delegatable and depth gates", async () => {
    const undelegatable = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: { delegatable: false, maxDelegationDepth: 5 } });
    const rootA = await undelegatable.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: undelegatable.agents.parent.did, scopes: SCOPES });
    await expect(undelegatable.cred.subDelegate({
      parentReceipt: rootA.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: undelegatable.agents.child.did, scopes: SCOPES,
    })).rejects.toMatchObject({ code: 'delegation_not_allowed' });

    const shallow = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: { delegatable: true, maxDelegationDepth: 0 } });
    const rootB = await shallow.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: shallow.agents.parent.did, scopes: SCOPES });
    await expect(shallow.cred.subDelegate({
      parentReceipt: rootB.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: shallow.agents.child.did, scopes: SCOPES,
    })).rejects.toMatchObject({ code: 'depth_exceeded' });
  });

  it('attenuates scopes and refuses escalation with a permissive grantor', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    const child = await s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: ['repo'],
    });
    expect(child.scopes).toEqual(['repo']);
    await expect(s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: [...SCOPES, 'delete_repo'],
    })).rejects.toMatchObject({ code: 'scope_escalation_denied' });
  });

  it('leaves a grantor the vault holds no Permission row for working as before', async () => {
    const s = await setup({ child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.ghost.did, scopes: SCOPES });
    const child = await s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    });
    expect(child.chainDepth).toBe(1);
    expect(child.receipt).toBeTypeOf('string');
  });
});

const RETAINED = SCOPES[0]!;
const DROPPED = SCOPES[1]!;

/** Run a handoff and report whether it let a credential out; a refusal must not. */
async function attempt<T>(run: () => Promise<T>): Promise<{ credentialReleased: true; result: T } | { credentialReleased: false; error: { code?: string; message?: string } }> {
  try {
    return { credentialReleased: true, result: await run() };
  } catch (error) {
    return { credentialReleased: false, error: error as { code?: string; message?: string } };
  }
}

/** The parent Permission row this vault stores for a role, id and all. */
async function rowFor(vault: CredVault, role: RoleName) {
  const row = await vault.getPermission(`agt_${role}`, 'github');
  if (!row) throw new Error(`no Permission for agt_${role}`);
  return row;
}

describe("Cred.subDelegate() local mode: the grantor's present scopes and validity", () => {
  it('refuses a handoff the grantor\'s narrowed row no longer covers, releasing no credential', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    const row = await rowFor(s.vault, 'parent');
    await s.vault.updatePermission(row.id, { allowedScopes: [RETAINED] });

    const get = vi.spyOn(CredVault.prototype, 'get');
    // Inheriting the receipt's scopes asks for the dropped one too.
    const inherited = await attempt(() => s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    }));
    expect(inherited.credentialReleased, JSON.stringify(inherited)).toBe(false);
    expect(inherited.credentialReleased === false && inherited.error.code).toBe('invalid_scope');
    expect(get).not.toHaveBeenCalled();

    // Asking for the dropped scope alone is the same refusal.
    const explicit = await attempt(() => s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: [DROPPED],
    }));
    expect(explicit.credentialReleased, JSON.stringify(explicit)).toBe(false);
    expect(explicit.credentialReleased === false && explicit.error.code).toBe('invalid_scope');
    expect(get).not.toHaveBeenCalled();
  });

  it('keeps the retained scope working after that narrowing', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    const row = await rowFor(s.vault, 'parent');
    await s.vault.updatePermission(row.id, { allowedScopes: [RETAINED] });

    const child = await s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: [RETAINED],
    });
    expect(child.scopes).toEqual([RETAINED]);
    expect(child.chainDepth).toBe(1);
    expect(child.accessToken).toBe('synthetic-provider-token');
    expect(child.receipt).toBeTypeOf('string');
  });

  it('takes the tighter scopes of the grantor\'s record-id row and its DID row', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, parentByDid: { ...PERMISSIVE, allowedScopes: [RETAINED] }, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });

    const get = vi.spyOn(CredVault.prototype, 'get');
    const refused = await attempt(() => s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: [DROPPED],
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('invalid_scope');
    expect(get).not.toHaveBeenCalled();

    const allowed = await s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: [RETAINED],
    });
    expect(allowed.scopes).toEqual([RETAINED]);
  });

  it('refuses a handoff once the grantor\'s Permission has expired, releasing no credential', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });
    const row = await rowFor(s.vault, 'parent');
    await s.vault.updatePermission(row.id, { expiresAt: new Date(Date.now() - 60_000) });

    const get = vi.spyOn(CredVault.prototype, 'get');
    const refused = await attempt(() => s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('permission_expired');
    expect(get).not.toHaveBeenCalled();
  });

  it('refuses a handoff when only the grantor\'s DID row is expired', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, parentByDid: { ...PERMISSIVE, expiresAt: new Date(Date.now() - 60_000) }, child: PERMISSIVE });
    const root = await s.cred.delegate({ service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.parent.did, scopes: SCOPES });

    const get = vi.spyOn(CredVault.prototype, 'get');
    const refused = await attempt(() => s.cred.subDelegate({
      parentReceipt: root.receipt!, service: 'github', userId: 'alice', appClientId: 'local', agentDid: s.agents.child.did, scopes: SCOPES,
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('permission_expired');
    expect(get).not.toHaveBeenCalled();
  });
});

/**
 * A derived read scope is Cred's name for access the raw token already carries.
 * `github.read` over a token holding `repo` reaches private repositories, so a
 * grantor that may only use `public_repo` cannot hand it on — whichever row it
 * is named by, and however old the receipt it holds. The comparison is made
 * over the stored connection's scopes, because that is what the read would
 * actually reach.
 */
describe("Cred.subDelegate() local mode: derived reads over the stored connection", () => {
  const base = (agentDid: string) => ({ service: 'github', userId: 'alice', appClientId: 'local', agentDid });

  it('refuses a github.read hop from a stale receipt once the grantor is narrowed to public_repo over a repo token', async () => {
    const s = await setup({ parent: { ...PERMISSIVE, allowedScopes: ['repo'] }, child: { ...PERMISSIVE, allowedScopes: ['github.read'] } }, ['repo']);
    const root = await s.cred.delegate({ ...base(s.agents.parent.did), scopes: ['github.read'] });
    // The receipt names the derived read while the token still backed it.
    expect(root.scopes).toEqual(['github.read']);
    const row = await rowFor(s.vault, 'parent');
    await s.vault.updatePermission(row.id, { allowedScopes: ['public_repo'] });

    const get = vi.spyOn(CredVault.prototype, 'get');
    const refused = await attempt(() => s.cred.subDelegate({
      ...base(s.agents.child.did), parentReceipt: root.receipt!, scopes: ['github.read'],
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('invalid_scope');
    // Refused before the credential read, so nothing was released or refreshed,
    // and the refusal names the scope rather than the token.
    expect(get).not.toHaveBeenCalled();
    expect(refused.credentialReleased === false && refused.error.message).not.toContain('synthetic-provider-token');
  });

  it('refuses it when the grantor is narrowed only on its DID row, merged tightest-first', async () => {
    const s = await setup({
      parent: { ...PERMISSIVE, allowedScopes: ['repo', 'public_repo'] },
      parentByDid: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
    }, ['repo']);
    const root = await s.cred.delegate({ ...base(s.agents.parent.did), scopes: ['github.read'] });
    expect(root.scopes).toEqual(['github.read']);

    const get = vi.spyOn(CredVault.prototype, 'get');
    const refused = await attempt(() => s.cred.subDelegate({
      ...base(s.agents.child.did), parentReceipt: root.receipt!, scopes: ['github.read'],
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('invalid_scope');
    expect(get).not.toHaveBeenCalled();

    // The DID row is what narrowed the grantor: widened back to the token's own
    // scope, the same hop is allowed, so the refusal above came from that row.
    const didRow = await s.vault.getPermission(s.agents.parent.did, 'github');
    expect(didRow).not.toBeNull();
    await s.vault.updatePermission(didRow!.id, { allowedScopes: ['repo'] });
    const allowed = await s.cred.subDelegate({
      ...base(s.agents.child.did), parentReceipt: root.receipt!, scopes: ['github.read'],
    });
    expect(allowed.scopes).toEqual(['github.read']);
  });

  it('keeps the public_repo grant deriving github.read over a token that only holds public_repo', async () => {
    const s = await setup({ parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] }, child: { ...PERMISSIVE, allowedScopes: ['github.read'] } }, ['public_repo']);
    const root = await s.cred.delegate({ ...base(s.agents.parent.did), scopes: ['github.read'] });
    expect(root.scopes).toEqual(['github.read']);

    const child = await s.cred.subDelegate({
      ...base(s.agents.child.did), parentReceipt: root.receipt!, scopes: ['github.read'],
    });
    expect(child.scopes).toEqual(['github.read']);
    expect(child.accessToken).toBe('synthetic-provider-token');
    expect(child.chainDepth).toBe(1);
    expect(child.receipt).toBeTypeOf('string');
  });
});

/**
 * The reviewer's wildcard fixture: a parent receipt granting a wildcard, a
 * grantor row allowing one concrete scope under it, and a request for that
 * concrete scope against a recipient whose Permission also allows a second
 * stored scope. What the child's delegation is selected for is read from the
 * vault's own audit record of that selection, not only from the returned
 * receipt, so a broad selection cannot hide behind a narrow receipt.
 */
describe('Cred.subDelegate() local mode: a wildcard parent receipt', () => {
  const CRM = ['crm.read', 'crm.write'];

  async function setupWildcard() {
    const where = dir();
    const options = { passphrase: PASSPHRASE, path: join(where, 'vault.sqlite'), storage: 'sqlite' as const };
    const vault = new CredVault(options);
    await vault.init();
    const store = (scopes: string[]) => vault.store({
      provider: 'crm', userId: 'alice', accessToken: 'synthetic-crm-token', scopes, expiresAt: new Date(Date.now() + 3_600_000),
    });
    // The receipt is minted over a wildcard the connection names, then the
    // connection is reconnected to the concrete scopes an operator really holds.
    await store(['crm.*', ...CRM]);
    const grantor = await generateAgentIdentity();
    const child = await generateAgentIdentity();
    for (const [role, agent] of [['wild_grantor', grantor], ['wild_child', child]] as const) {
      const now = new Date().toISOString();
      await vault.registerAgent({
        id: role, did: agent.did, name: role, fingerprint: `fp_${role}`, scopeCeiling: [], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now,
      });
    }
    const grantorRow = await vault.createPermission({
      agentId: 'wild_grantor', connectionId: 'crm', allowedScopes: ['crm.*'], requiresApproval: false, delegatable: true, maxDelegationDepth: 5, createdBy: 'test',
    });
    await vault.createPermission({
      agentId: 'wild_child', connectionId: 'crm', allowedScopes: CRM, requiresApproval: false, delegatable: true, maxDelegationDepth: 5, createdBy: 'test',
    });
    const cred = new Cred({ mode: 'local', vault: options, providers: {}, requireAudit: true });
    const root = await cred.delegate({ service: 'crm', userId: 'alice', appClientId: 'local', agentDid: grantor.did, scopes: ['crm.*'] });
    expect(root.scopes).toEqual(['crm.*']);
    await store(CRM);
    await vault.updatePermission(grantorRow.id, { allowedScopes: ['crm.read'] });
    return { cred, vault, child, root };
  }

  /** Every successful delegation record in the vault, with the scopes it granted. */
  function delegationRecords(s: Awaited<ReturnType<typeof setupWildcard>>) {
    return s.vault.queryAuditEvents({ action: 'delegate' })
      .filter((e) => e.outcome === 'success' && Array.isArray(e.scopesGranted))
      .map((e) => ({ id: e.id, scopes: e.scopesGranted! }));
  }

  it('hands the child only the validated concrete scope, never the wider stored one', async () => {
    const s = await setupWildcard();
    const before = new Set(delegationRecords(s).map((e) => e.id));

    const child = await s.cred.subDelegate({
      service: 'crm', userId: 'alice', appClientId: 'local', agentDid: s.child.did, parentReceipt: s.root.receipt!, scopes: ['crm.read'],
    });

    // What was validated and minted.
    expect(child.scopes).toEqual(['crm.read']);
    const claims = JSON.parse(Buffer.from(child.receipt!.split('.')[1]!, 'base64url').toString('utf8')) as { scopes: string[] };
    expect(claims.scopes).toEqual(['crm.read']);

    // What the vault recorded as selected for the child's delegation: the same
    // scope, chosen by name — not the empty list that means "unspecified" and
    // picks `crm.write` out of the connection.
    const recorded = delegationRecords(s).filter((e) => !before.has(e.id));
    expect(recorded.length).toBeGreaterThan(0);
    for (const event of recorded) expect(event.scopes).toEqual(['crm.read']);
  });
});

/**
 * Notion's token carries no scopes: its capabilities are set on the
 * integration, so a stored Notion connection with an empty scope list is the
 * whole connection. A row naming only `read_content` therefore reaches no
 * `notion.read` — neither as a fresh delegation of its own nor across a hop
 * from a receipt minted while its row was wider — while a row naming `content`
 * still does. A refusal must release no credential.
 */
describe('Cred local mode: a Notion connection with no stored scopes', () => {
  const NOTION_TOKEN = 'synthetic-notion-token';

  async function setupNotion(grantorScopes: string[], childScopes: string[] = ['notion.read']) {
    const where = dir();
    const options = { passphrase: PASSPHRASE, path: join(where, 'vault.sqlite'), storage: 'sqlite' as const };
    const vault = new CredVault(options);
    await vault.init();
    // The ordinary Notion shape: the token carries no scopes at all.
    await vault.store({
      provider: 'notion', userId: 'bob', accessToken: NOTION_TOKEN, scopes: [], expiresAt: new Date(Date.now() + 3_600_000),
    });
    const grantor = await generateAgentIdentity();
    const child = await generateAgentIdentity();
    const now = new Date().toISOString();
    for (const [id, agent] of [['agt_notion_grantor', grantor], ['agt_notion_child', child]] as const) {
      await vault.registerAgent({
        id, did: agent.did, name: id, fingerprint: `fp_${id}`, scopeCeiling: [], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now,
      });
    }
    const grantorRow = await vault.createPermission({
      agentId: 'agt_notion_grantor', connectionId: 'notion', allowedScopes: grantorScopes, requiresApproval: false, delegatable: true, maxDelegationDepth: 5, createdBy: 'test',
    });
    await vault.createPermission({
      agentId: 'agt_notion_child', connectionId: 'notion', allowedScopes: childScopes, requiresApproval: false, delegatable: true, maxDelegationDepth: 5, createdBy: 'test',
    });
    const cred = new Cred({ mode: 'local', vault: options, providers: {}, requireAudit: true });
    return { cred, vault, grantor, child, grantorRow, base: { service: 'notion', userId: 'bob', appClientId: 'local' } };
  }

  /** Successful delegation records: the ones a refusal must not add to. */
  const successes = (vault: CredVault) => vault.queryAuditEvents({ action: 'delegate' })
    .filter((event) => event.outcome === 'success');

  it('still derives notion.read for a row naming content over the whole connection', async () => {
    const s = await setupNotion(['content']);
    const root = await s.cred.delegate({ ...s.base, agentDid: s.grantor.did, scopes: ['notion.read'] });
    expect(root.scopes).toEqual(['notion.read']);
    expect(root.accessToken).toBe(NOTION_TOKEN);
  });

  it('refuses a fresh notion.read to a row narrowed to read_content, releasing no credential', async () => {
    const s = await setupNotion(['read_content']);
    const before = successes(s.vault).length;
    const refused = await attempt(() => s.cred.delegate({ ...s.base, agentDid: s.grantor.did, scopes: ['notion.read'] }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('invalid_scope');
    expect(JSON.stringify(refused)).not.toContain(NOTION_TOKEN);
    expect(successes(s.vault).length).toBe(before);
  });

  it('refuses a stale-receipt hop for notion.read once the grantor is narrowed to read_content', async () => {
    const s = await setupNotion(['content']);
    const root = await s.cred.delegate({ ...s.base, agentDid: s.grantor.did, scopes: ['notion.read'] });
    expect(root.scopes).toEqual(['notion.read']);
    await s.vault.updatePermission(s.grantorRow.id, { allowedScopes: ['read_content'] });

    const before = successes(s.vault).length;
    const refused = await attempt(() => s.cred.subDelegate({
      ...s.base, parentReceipt: root.receipt!, agentDid: s.child.did, scopes: ['notion.read'],
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('invalid_scope');
    expect(JSON.stringify(refused)).not.toContain(NOTION_TOKEN);
    expect(successes(s.vault).length).toBe(before);
  });
});

/**
 * The receiving agent's own scope ceiling is a hard cap on what a hop may
 * select, so the response, the signed receipt and the hop's audit record must
 * all name exactly the selection that was made. A receipt that claimed more
 * would anchor a later hop to a scope its holder never received.
 */
describe("Cred.subDelegate() local mode: the receiving agent's ceiling bounds the receipt", () => {
  const CRM = ['crm.read', 'crm.write'];

  async function setupCapped(ceiling: string[]) {
    const where = dir();
    const options = { passphrase: PASSPHRASE, path: join(where, 'vault.sqlite'), storage: 'sqlite' as const };
    const vault = new CredVault(options);
    await vault.init();
    await vault.store({
      provider: 'crm', userId: 'alice', accessToken: 'synthetic-crm-token', scopes: CRM, expiresAt: new Date(Date.now() + 3_600_000),
    });
    const grantor = await generateAgentIdentity();
    const child = await generateAgentIdentity();
    const grandchild = await generateAgentIdentity();
    const now = new Date().toISOString();
    for (const [id, agent, cap] of [
      ['cap_grantor', grantor, []],
      ['cap_child', child, ceiling],
      ['cap_grandchild', grandchild, []],
    ] as const) {
      await vault.registerAgent({
        id, did: agent.did, name: id, fingerprint: `fp_${id}`, scopeCeiling: [...cap], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now,
      });
    }
    for (const id of ['cap_grantor', 'cap_child', 'cap_grandchild']) {
      await vault.createPermission({
        agentId: id, connectionId: 'crm', allowedScopes: CRM, requiresApproval: false, delegatable: true, maxDelegationDepth: 5, createdBy: 'test',
      });
    }
    const cred = new Cred({ mode: 'local', vault: options, providers: {}, requireAudit: true });
    const base = { service: 'crm', userId: 'alice', appClientId: 'local' };
    const root = await cred.delegate({ ...base, agentDid: grantor.did, scopes: CRM });
    expect(root.scopes).toEqual(CRM);
    return { cred, vault, child, grandchild, root, base };
  }

  it('names only the selection in the response, the receipt and the audit record', async () => {
    const s = await setupCapped(['crm.read']);
    const before = new Set(s.vault.queryAuditEvents({ action: 'delegate' }).filter((e) => e.outcome === 'success').map((e) => e.id));

    const child = await s.cred.subDelegate({ ...s.base, parentReceipt: s.root.receipt!, agentDid: s.child.did, scopes: CRM });

    expect(child.scopes).toEqual(['crm.read']);
    const claims = JSON.parse(Buffer.from(child.receipt!.split('.')[1]!, 'base64url').toString('utf8')) as { scopes: string[] };
    expect(claims.scopes).toEqual(['crm.read']);
    const recorded = s.vault.queryAuditEvents({ action: 'delegate' })
      .filter((event) => event.outcome === 'success' && !before.has(event.id));
    expect(recorded.length).toBeGreaterThan(0);
    for (const event of recorded) expect(event.scopesGranted).toEqual(['crm.read']);

    // The receipt cannot anchor a hop to a scope this one did not select.
    // Either refusal is a refusal: the helper reports an empty grant before it
    // reports an escalation, and both leave the credential unreleased.
    const grand = await attempt(() => s.cred.subDelegate({
      ...s.base, parentReceipt: child.receipt!, agentDid: s.grandchild.did, scopes: ['crm.write'],
    }));
    expect(grand.credentialReleased, JSON.stringify(grand)).toBe(false);
    expect(['no_scopes_granted', 'scope_escalation_denied'])
      .toContain(grand.credentialReleased === false ? grand.error.code : 'released');
  });

  it('keeps a ceiling that equals the validated grant: the receipt names that grant', async () => {
    const s = await setupCapped(CRM);
    const child = await s.cred.subDelegate({ ...s.base, parentReceipt: s.root.receipt!, agentDid: s.child.did, scopes: CRM });
    expect(child.scopes).toEqual(CRM);
    const claims = JSON.parse(Buffer.from(child.receipt!.split('.')[1]!, 'base64url').toString('utf8')) as { scopes: string[] };
    expect(claims.scopes).toEqual(CRM);
    expect(child.accessToken).toBe('synthetic-crm-token');
    expect(child.chainDepth).toBe(1);
  });

  it('still refuses a selection the ceiling leaves empty', async () => {
    const s = await setupCapped(['crm.read']);
    const before = s.vault.queryAuditEvents({ action: 'delegate' }).filter((e) => e.outcome === 'success').length;
    const refused = await attempt(() => s.cred.subDelegate({
      ...s.base, parentReceipt: s.root.receipt!, agentDid: s.child.did, scopes: ['crm.write'],
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('scope_ceiling_exceeded');
    expect(s.vault.queryAuditEvents({ action: 'delegate' }).filter((e) => e.outcome === 'success').length).toBe(before);
  });
});

/**
 * The receiving Permission bounds a hop as well as the grantor's, and local mode
 * reads it exactly: a `public_repo` recipient row does not cover `github.read`,
 * so a `repo` token behind the parent receipt never reaches such a recipient.
 */
describe('Cred.subDelegate() local mode: the receiving Permission bounds a hop', () => {
  const base = (agentDid: string) => ({ service: 'github', userId: 'alice', appClientId: 'local', agentDid });

  it('refuses github.read to a recipient row naming only public_repo over a repo token', async () => {
    const s = await setup({ parent: { ...PERMISSIVE, allowedScopes: ['repo'] }, child: { ...PERMISSIVE, allowedScopes: ['public_repo'] } }, ['repo']);
    const root = await s.cred.delegate({ ...base(s.agents.parent.did), scopes: ['github.read'] });
    expect(root.scopes).toEqual(['github.read']);

    const succeeded = () => s.vault.queryAuditEvents({ action: 'delegate' }).filter((e) => e.outcome === 'success').length;
    const before = succeeded();
    const get = vi.spyOn(CredVault.prototype, 'get');
    const refused = await attempt(() => s.cred.subDelegate({
      ...base(s.agents.child.did), parentReceipt: root.receipt!, scopes: ['github.read'],
    }));
    expect(refused.credentialReleased, JSON.stringify(refused)).toBe(false);
    expect(refused.credentialReleased === false && refused.error.code).toBe('no_scopes_granted');
    expect(get).not.toHaveBeenCalled();
    expect(succeeded()).toBe(before);
  });

  it('issues it once the recipient row names the read itself', async () => {
    // Local mode reads the receiving Permission exactly, so the read is issued
    // when the row names it. That is the documented way to allow a derived read
    // deliberately, and it shows the refusal above came from that row and not
    // from the connection or the service.
    const s = await setup({ parent: { ...PERMISSIVE, allowedScopes: ['repo'] }, child: { ...PERMISSIVE, allowedScopes: ['github.read'] } }, ['repo']);
    const root = await s.cred.delegate({ ...base(s.agents.parent.did), scopes: ['github.read'] });
    expect(root.scopes).toEqual(['github.read']);

    const child = await s.cred.subDelegate({ ...base(s.agents.child.did), parentReceipt: root.receipt!, scopes: ['github.read'] });
    expect(child.scopes).toEqual(['github.read']);
    expect(child.accessToken).toBe('synthetic-provider-token');
  });
});

