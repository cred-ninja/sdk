import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, scryptSync, sign } from 'node:crypto';
import { CredVault } from '@credninja/vault';
import { Cred } from '../index.js';

const directories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

async function local() {
  const directory = mkdtempSync(join(tmpdir(), 'cred-opaque-'));
  directories.push(directory);
  const options = { passphrase: 'test-opaque', path: join(directory, 'vault.sqlite'), storage: 'sqlite' as const };
  const vault = new CredVault(options);
  await vault.init();
  await vault.store({ provider: 'github', userId: 'user-test', accessToken: 'test-token', scopes: ['repo'] });
  await vault.createPermission({ agentId: 'did:key:child', connectionId: 'github', allowedScopes: ['repo'], requiresApproval: false, delegatable: true, maxDelegationDepth: 5, createdBy: 'test' });
  return new Cred({ mode: 'local', vault: options, providers: {} });
}

function receipt(constraints: unknown[], duplicateMember = false) {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const text = JSON.stringify({ sub: 'did:key:parent', service: 'github', userId: 'user-test', appClientId: 'local', delegationId: 'del_parent', scopes: ['repo'], chainDepth: 0, iat: Math.floor(Date.now() / 1000), constraints });
  const payload = Buffer.from(duplicateMember ? text.replace('"nested":1', '"nested":1,"nested":2') : text).toString('base64url');
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), scryptSync('test-opaque', 'cred:local-receipt:v1', 32)]), format: 'der', type: 'pkcs8' });
  return `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString('base64url')}`;
}

const constraints = [{ key: 'destination', future: { a: [1, 2], b: true } }];

const knownConstraints = [
  { key: 'max_calls', max_lifetime: 0 }, { key: 'max_calls', max_subtree: 0 },
  { key: 'destination', prefix: 'https://blocked.invalid/' }, { key: 'x', max: 1 },
  { key: 'x', min: 1 }, { key: 'x', one_of: ['allowed'] },
  { key: 'x', not_one_of: ['blocked'] }, { key: 'x', rank: 0 },
];

describe('local opaque constraint enforcement', () => {
  it.each(knownConstraints)('refuses unsupported local constraint %j before loading credentials', async (constraint) => {
    const cred = await local();
    const get = vi.spyOn(CredVault.prototype, 'get');
    const list = vi.spyOn(CredVault.prototype, 'list');
    await expect(cred.delegate({ service: 'github', userId: 'user-test', constraints: [constraint] })).rejects.toMatchObject({ code: 'unsupported_constraint' });
    await expect(cred.authorizeLocalUse({ service: 'github', userId: 'user-test', constraints: [constraint] })).rejects.toMatchObject({ code: 'unsupported_constraint' });
    expect(get).not.toHaveBeenCalled();
    expect(list).not.toHaveBeenCalled();
  });

  it.each(knownConstraints)('refuses inherited local constraint %j when the child omits it', async (constraint) => {
    const cred = await local();
    const get = vi.spyOn(CredVault.prototype, 'get');
    await expect(cred.subDelegate({ parentReceipt: receipt([constraint]), service: 'github', userId: 'user-test', agentDid: 'did:key:child' })).rejects.toMatchObject({ code: 'unsupported_constraint' });
    expect(get).not.toHaveBeenCalled();
  });

  it('keeps an empty local constraint list unrestricted', async () => {
    const result = await (await local()).delegate({ service: 'github', userId: 'user-test', constraints: [] });
    expect(result.accessToken).toBe('test-token');
  });
  it('refuses raw issuance before vault lookup or token refresh', async () => {
    const get = vi.spyOn(CredVault.prototype, 'get');
    await expect((await local()).delegate({ service: 'github', userId: 'user-test', constraints })).rejects.toMatchObject({ code: 'unknown_constraint' });
    expect(get).not.toHaveBeenCalled();
  });

  it('refuses inherited opaque constraints before raw subdelegation', async () => {
    const get = vi.spyOn(CredVault.prototype, 'get');
    await expect((await local()).subDelegate({ parentReceipt: receipt(constraints), service: 'github', userId: 'user-test', agentDid: 'did:key:child' })).rejects.toMatchObject({ code: 'unknown_constraint' });
    expect(get).not.toHaveBeenCalled();
  });

  it('refuses local exercise before loading credentials', async () => {
    const list = vi.spyOn(CredVault.prototype, 'list');
    await expect((await local()).authorizeLocalUse({ service: 'github', userId: 'user-test', constraints })).rejects.toMatchObject({ code: 'unknown_constraint' });
    expect(list).not.toHaveBeenCalled();
  });

  it('does not downgrade malformed known constraints into opaque ones', async () => {
    await expect((await local()).delegate({ service: 'github', userId: 'user-test', constraints: [{ key: 'x', max: 'bad' }] })).rejects.toMatchObject({ code: 'invalid_constraints' });
  });

  it('rejects duplicate JSON members nested in a signed opaque parent', async () => {
    const parentReceipt = receipt([{ key: 'x', future: { nested: 1 } }], true);
    await expect((await local()).subDelegate({ parentReceipt, service: 'github', userId: 'user-test', agentDid: 'did:key:child' })).rejects.toMatchObject({ code: 'invalid_parent' });
  });
});

describe('cloud constraint transport', () => {
  it('never strips constraints from TOFU raw delegation', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: 'unknown_constraint' }), { status: 403 }));
    const cred = new Cred({ agentToken: 'cred_at_test', baseUrl: 'https://cred.example.com' });
    await expect(cred.tofuDelegate({ service: 'github', userId: 'user-test', fingerprint: 'test', privateKeyBytes: new Uint8Array(32).fill(1), constraints })).rejects.toMatchObject({ code: 'unknown_constraint' });
    expect(JSON.parse(String(fetch.mock.calls[0]![1]!.body)).constraints).toEqual(constraints);
  });
  it.each(['delegate', 'delegateHandle', 'subDelegate', 'subDelegateHandle'] as const)('never strips constraints in %s', async (method) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: 'unknown_constraint' }), { status: 403 }));
    const cred = new Cred({ agentToken: 'cred_at_test', baseUrl: 'https://cred.example.com' });
    await expect(cred[method]({ service: 'github', userId: 'user-test', appClientId: 'local', agentDid: 'did:key:child', parentReceipt: 'receipt', constraints })).rejects.toMatchObject({ code: 'unknown_constraint' });
    expect(JSON.parse(String(fetch.mock.calls[0]![1]!.body)).constraints).toEqual(constraints);
  });
});
