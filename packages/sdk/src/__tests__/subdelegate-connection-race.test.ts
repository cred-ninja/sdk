/**
 * Local mode must decide and issue against one stored row.
 *
 * `subDelegate()` read the connection once for the grantor's Permission and
 * derived-read check, then let `delegateLocal()` pick the credential through a
 * second read. A connection replaced from narrow to wide in that window was
 * decided on the narrow row and issued from the wide one — and local mode hands
 * back the raw token, so the caller receives a credential wider than the
 * receipt and the audit record say was checked.
 *
 * The barrier here sits on the vault's own `getStored`, so the replacement lands
 * inside a real hop, with real receipts and a real encrypted vault. Nothing
 * about the authorization is mocked.
 */
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Cred, generateAgentIdentity, type AgentIdentity } from '../index';
import { CredVault } from '@credninja/vault';

const PASSPHRASE = 'test-passphrase-connection-race';
const ORIGINAL = 'synthetic-narrow-provider-token';
const REPLACEMENT = 'synthetic-wide-replacement-token';
const dirs: string[] = [];

function dir(): string {
  const made = mkdtempSync(join(tmpdir(), 'cred-connection-race-sdk-'));
  dirs.push(made);
  return made;
}

afterAll(() => {
  for (const made of dirs) rmSync(made, { recursive: true, force: true });
});

beforeEach(() => {
  vi.restoreAllMocks();
});

type Gate = { delegatable: boolean; maxDelegationDepth: number; allowedScopes?: string[] };
const PERMISSIVE: Gate = { delegatable: true, maxDelegationDepth: 5 };

type Fixture = {
  cred: Cred;
  vault: CredVault;
  parent: AgentIdentity;
  child: AgentIdentity;
  parentRow: string;
  root: { receipt?: string; scopes: string[] };
  base: { service: string; userId: string; appClientId: string };
};

async function setup(opts: {
  service: 'github' | 'notion';
  storedScopes: string[];
  parent: Gate;
  child: Gate;
}): Promise<Fixture> {
  const where = dir();
  const options = { passphrase: PASSPHRASE, path: join(where, 'vault.sqlite'), storage: 'sqlite' as const };
  const vault = new CredVault(options);
  await vault.init();
  await vault.store({
    provider: opts.service,
    userId: 'alice',
    accessToken: ORIGINAL,
    scopes: opts.storedScopes,
    expiresAt: new Date(Date.now() + 3_600_000),
  });
  const parent = await generateAgentIdentity();
  const child = await generateAgentIdentity();
  const now = new Date().toISOString();
  for (const [id, agent] of [['agt_parent', parent], ['agt_child', child]] as const) {
    await vault.registerAgent({
      id, did: agent.did, name: id, fingerprint: `fp_${id}`, scopeCeiling: [], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now,
    });
  }
  const parentRow = await vault.createPermission({
    agentId: 'agt_parent',
    connectionId: opts.service,
    requiresApproval: false,
    createdBy: 'test',
    ...opts.parent,
    allowedScopes: opts.parent.allowedScopes ?? opts.storedScopes,
  });
  await vault.createPermission({
    agentId: 'agt_child',
    connectionId: opts.service,
    requiresApproval: false,
    createdBy: 'test',
    ...opts.child,
    allowedScopes: opts.child.allowedScopes ?? opts.storedScopes,
  });
  const cred = new Cred({ mode: 'local', vault: options, providers: {}, requireAudit: true });
  const base = { service: opts.service, userId: 'alice', appClientId: 'local' };
  const root = await cred.delegate({ ...base, agentDid: parent.did, scopes: opts.child.allowedScopes ?? opts.storedScopes });
  return { cred, vault, parent, child, parentRow: parentRow.id, root, base };
}

/** Hold the hop open from inside its own `getStored`, until the test releases it. */
function pauseAfterStoredRead() {
  const original = CredVault.prototype.getStored;
  let signal!: () => void;
  let resume!: () => void;
  const reached = new Promise<void>((resolve) => { signal = resolve; });
  const held = new Promise<void>((resolve) => { resume = resolve; });
  let once = true;
  const spy = vi.spyOn(CredVault.prototype, 'getStored').mockImplementation(async function (
    this: CredVault,
    ...args: Parameters<CredVault['getStored']>
  ) {
    const entry = await original.apply(this, args);
    if (once) {
      once = false;
      signal();
      await held;
    }
    return entry;
  } as unknown as CredVault['getStored']);
  return { reached, resume: () => resume(), spy };
}

async function reachedOrTimeout(reached: Promise<void>) {
  return Promise.race([
    reached.then(() => 'reached' as const),
    new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 5000)),
  ]);
}

/** Run a handoff and report whether it let a credential out; a refusal must not. */
async function attempt<T>(run: () => Promise<T>) {
  try {
    return { credentialReleased: true as const, result: await run() };
  } catch (error) {
    return { credentialReleased: false as const, error: error as { code?: string; message?: string } };
  }
}

function claimsOf(receipt: string): { scopes: string[] } {
  return JSON.parse(Buffer.from(receipt.split('.')[1]!, 'base64url').toString('utf8'));
}

/**
 * The shapes the parent probe reproduced: narrow at the decision, widened by
 * another operation before the credential is chosen.
 */
const SHAPES = [
  {
    name: 'github grantor Permission',
    service: 'github' as const,
    storedScopes: ['public_repo'],
    parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
    child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
    replacementScopes: ['repo'],
    requested: ['github.read'],
  },
  {
    name: 'Notion grantor Permission',
    service: 'notion' as const,
    storedScopes: ['read_content'],
    parent: { ...PERMISSIVE, allowedScopes: ['content'] },
    child: { ...PERMISSIVE, allowedScopes: ['notion.read'] },
    replacementScopes: [] as string[],
    requested: ['notion.read'],
  },
];

describe('Cred.subDelegate() local mode: a connection replaced mid-hop', () => {
  for (const shape of SHAPES) {
    it(`issues against the row it decided on: ${shape.name}`, async () => {
      const world = await setup(shape);
      expect(world.root.scopes).toEqual(shape.requested);
      const pause = pauseAfterStoredRead();
      const inFlight = attempt(() => world.cred.subDelegate({
        ...world.base, parentReceipt: world.root.receipt!, agentDid: world.child.did, scopes: shape.requested,
      }));
      expect(await reachedOrTimeout(pause.reached), 'the hop reached its stored read').toBe('reached');
      await world.vault.store({
        provider: shape.service, userId: 'alice', accessToken: REPLACEMENT, scopes: shape.replacementScopes, expiresAt: new Date(Date.now() + 3_600_000),
      });
      pause.resume();

      const outcome = await inFlight;
      expect(outcome.credentialReleased, JSON.stringify(outcome)).toBe(true);
      if (!outcome.credentialReleased) return;
      // The one credential read this hop made was the one it decided on.
      expect(pause.spy).toHaveBeenCalledTimes(1);
      expect(outcome.result.accessToken).toBe(ORIGINAL);
      expect(outcome.result.accessToken).not.toBe(REPLACEMENT);
      expect(outcome.result.scopes).toEqual(shape.requested);
      expect(claimsOf(outcome.result.receipt!).scopes).toEqual(shape.requested);
      expect(JSON.stringify(outcome.result)).not.toContain(REPLACEMENT);
    });

    it(`keeps the unchanged connection control: ${shape.name}`, async () => {
      const world = await setup(shape);
      const pause = pauseAfterStoredRead();
      const inFlight = world.cred.subDelegate({
        ...world.base, parentReceipt: world.root.receipt!, agentDid: world.child.did, scopes: shape.requested,
      });
      expect(await reachedOrTimeout(pause.reached), 'the hop reached its stored read').toBe('reached');
      pause.resume();
      const child = await inFlight;
      expect(child.accessToken).toBe(ORIGINAL);
      expect(child.scopes).toEqual(shape.requested);
      expect(claimsOf(child.receipt!).scopes).toEqual(shape.requested);
    });
  }

  it('fails closed when the pinned row has expired and the re-read is wider', async () => {
    // An expired row cannot itself be the credential — `get()` is what may
    // refresh it — so that one re-read is allowed and its result is compared
    // against the decision. A wider one is refused, never issued.
    const world = await setup(SHAPES[0]!);
    await world.vault.store({
      provider: 'github', userId: 'alice', accessToken: ORIGINAL, scopes: ['public_repo'], expiresAt: new Date(Date.now() - 60_000),
    });
    const pause = pauseAfterStoredRead();
    const inFlight = attempt(() => world.cred.subDelegate({
      ...world.base, parentReceipt: world.root.receipt!, agentDid: world.child.did, scopes: ['github.read'],
    }));
    expect(await reachedOrTimeout(pause.reached), 'the hop reached its stored read').toBe('reached');
    await world.vault.store({
      provider: 'github', userId: 'alice', accessToken: REPLACEMENT, scopes: ['repo'], expiresAt: new Date(Date.now() + 3_600_000),
    });
    pause.resume();

    const outcome = await inFlight;
    expect(outcome.credentialReleased, JSON.stringify(outcome)).toBe(false);
    if (outcome.credentialReleased) return;
    expect(outcome.error.code).toBe('invalid_scope');
    expect(outcome.error.message ?? '').not.toContain(ORIGINAL);
    expect(outcome.error.message ?? '').not.toContain(REPLACEMENT);
  });
});

describe('Cred.delegate() local mode: the grant comes from the entry it read', () => {
  it('does not re-read the connection after the read that backed its scopes', async () => {
    const world = await setup({
      service: 'github',
      storedScopes: ['public_repo'],
      parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
    });
    const original = CredVault.prototype.get;
    let signal!: () => void;
    let resume!: () => void;
    const reached = new Promise<void>((resolve) => { signal = resolve; });
    const held = new Promise<void>((resolve) => { resume = resolve; });
    let once = true;
    const spy = vi.spyOn(CredVault.prototype, 'get').mockImplementation(async function (
      this: CredVault,
      ...args: Parameters<CredVault['get']>
    ) {
      const entry = await original.apply(this, args);
      if (once) {
        once = false;
        signal();
        await held;
      }
      return entry;
    } as unknown as CredVault['get']);

    const inFlight = (async () => await world.cred.delegate({
      ...world.base, agentDid: world.child.did, scopes: ['github.read'],
    }))();
    expect(await reachedOrTimeout(reached), 'the route reached its credential read').toBe('reached');
    await world.vault.store({
      provider: 'github', userId: 'alice', accessToken: REPLACEMENT, scopes: ['repo'], expiresAt: new Date(Date.now() + 3_600_000),
    });
    resume();

    const issued = await inFlight;
    expect(spy).toHaveBeenCalledTimes(1);
    expect(issued.accessToken).toBe(ORIGINAL);
    expect(issued.scopes).toEqual(['github.read']);
    expect(claimsOf(issued.receipt!).scopes).toEqual(['github.read']);
    expect(JSON.stringify(issued)).not.toContain(REPLACEMENT);
  });
});
