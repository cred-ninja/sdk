import { afterEach, expect, it, vi } from 'vitest';
import request from 'supertest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SqliteCumulativeLedger } from '@credninja/vault';
import { createActorToken, generateAgentIdentity } from '@credninja/sdk';
import { createServer } from '../server.js';

const directories: string[] = [];
const token = 'cred_at_constraint_fixture';
afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

async function setup() {
  const directory = mkdtempSync(join(tmpdir(), 'cred-constraint-boundaries-'));
  directories.push(directory);
  const { app, vault } = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'constraint-fixture-only',
    vaultStorage: 'sqlite', vaultPath: join(directory, 'vault.sqlite'),
    tofuStorage: 'sqlite', tofuPath: join(directory, 'tofu.sqlite'),
    adminToken: 'cred_admin_constraint_fixture', agentToken: token, requireDpop: false,
    providers: [{ slug: 'github', clientId: 'fixture', clientSecret: 'fixture', defaultScopes: ['repo'] }],
    redirectBaseUri: 'http://localhost:3456',
  });
  await vault.init();
  await vault.store({ provider: 'github', userId: 'owner', accessToken: 'fixture-token', scopes: ['repo'] });
  return { app, vault };
}

const rootBody = { service: 'github', user_id: 'owner', agent_did: 'did:key:root', token_format: 'handle' };

it.each(['/api/v1/delegate', '/api/v1/subdelegate'])('rejects unsafe raw constraint JSON on %s before issuing a receipt', async (route) => {
  const { app, vault } = await setup();
  let body: Record<string, unknown> = rootBody;
  const identity = await generateAgentIdentity();
  if (route.endsWith('/subdelegate')) {
    await vault.createPermission({ agentId: 'did:key:child', connectionId: 'github', allowedScopes: ['repo'], requiresApproval: false, delegatable: true, maxDelegationDepth: 3, createdBy: 'fixture' });
    const root = await request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${token}`).send({ ...rootBody, agent_did: identity.did });
    expect(root.status).toBe(200);
    body = { ...rootBody, parent_receipt: root.body.receipt, agent_did: 'did:key:child' };
  }
  const send = (members: string) => {
    const payload = route.endsWith('/subdelegate')
      ? { ...body, actor_token: createActorToken(identity, 'http://localhost:3456/api/v1/subdelegate') } : body;
    return request(app).post(route).set('Authorization', `Bearer ${token}`).type('json')
      .send(JSON.stringify(payload).slice(0, -1) + ',' + members + '}');
  };
  // Both paths really issue without the malformed constraints (including actor proof).
  expect((await send('"constraints":[]')).status).toBe(200);
  for (const members of [
    '"constraints":[{"key":"destination","future":{"ceiling":1,"ceiling":2}}]',
    '"constraints":[{"key":"x","future":{"nested":[{"ceiling":1,"\\u0063eiling":2}]}}]',
    '"constraints":[{"key":"x","future":1,"future":2}]',
    '"constraints":[{"key":"x","future":1}],"constraints":[]',
    '"constraints":[{"key":"x","future":{"ceiling":9007199254740993}}]',
    '"constraints":[{"key":"x","max":9007199254740993}]',
    '"constraints":[{"key":"x","future":1,"other_future":2}]',
    '"constraints":[{"key":"x","max":1,"future":2}]',
  ]) {
    const result = await send(members);
    expect(result.status, members).toBe(400);
    expect(result.body.error).toBe('invalid_constraints');
    expect(result.body.receipt).toBeUndefined();
    expect(result.body.delegation_id).toBeUndefined();
  }
  // Unconstrained legacy JSON retains its existing last-member-wins behavior.
  expect((await send('"legacy_note":1,"legacy_note":2')).status).toBe(200);
});

it('exposes unknown-constraint exercise denial only in the owning user audit feed without debit or dispatch', async () => {
  const { app } = await setup();
  const issued = await request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${token}`).send({
    ...rootBody, constraints: [{ key: 'x', future: { nested: true } }, { key: 'max_calls', max_lifetime: 1 }],
  });
  expect(issued.status).toBe(200);
  const debit = vi.spyOn(SqliteCumulativeLedger.prototype, 'debit');
  const upstream = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));
  const denied = await request(app).post('/api/v1/use').set('Authorization', `Bearer ${token}`).send({
    delegation_id: issued.body.delegation_id, url: 'https://api.github.com/user', method: 'GET',
  });
  expect(denied.status).toBe(403);
  expect(denied.body.error).toBe('unknown_constraint');
  expect(debit).not.toHaveBeenCalled();
  expect(upstream).not.toHaveBeenCalled();
  const audit = (user: string, service = 'github') => request(app).get('/api/v1/audit')
    .set('Authorization', `Bearer ${token}`).query({ user_id: user, service });
  const owner = await audit('owner');
  expect(owner.status).toBe(200);
  const denials = owner.body.entries.filter((entry: { action: string }) => entry.action === 'deny');
  expect(denials).toHaveLength(1);
  expect(denials[0]).toMatchObject({
    service: 'github', userId: 'owner', metadata: {
      errorMessage: 'unknown_constraint', outcome: 'denied',
      webBotAuth: { delegationId: issued.body.delegation_id },
    },
  });
  expect((await audit('other')).body.entries).toEqual([]);
  expect((await audit('owner', 'google')).body.entries).toEqual([]);
});
