import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { generateAgentIdentity } from '@credninja/sdk';

const require = createRequire(import.meta.url);
const vaultEsm = await import('@credninja/vault');
const vaultCjs = require('@credninja/vault');
const aiEsm = await import('@credninja/ai');
const aiCjs = require('@credninja/ai');

// Every named value must remain available to ESM consumers of the common
// implementation, including values re-exported from other packages.
for (const [esm, cjs] of [[vaultEsm, vaultCjs], [aiEsm, aiCjs]]) {
  for (const name of Object.keys(cjs)) assert.equal(esm[name], cjs[name], name);
}

for (const [maker, consumer] of [[vaultEsm, vaultCjs], [vaultCjs, vaultEsm]]) {
  const vault = new maker.CredVault({ passphrase: 'mixed-module-fixture', storage: 'file', path: 'unused-fixture.json' });
  const store = {}; // Constructor-only check: no storage calls are made.
  assert.doesNotThrow(() => new consumer.VaultLinkSecretStore({ vault, store }));
  for (const forged of [Object.create(maker.CredVault.prototype), new Proxy(vault, {})]) {
    assert.throws(() => new consumer.VaultLinkSecretStore({ vault: forged, store }), /genuine CredVault/);
  }
}

const agentIdentity = await generateAgentIdentity();
const otherIdentity = await generateAgentIdentity();
const options = { agentToken: 'cred_at_fixture', baseUrl: 'https://cred.example.com', userId: 'fixture', appClientId: 'fixture', agentIdentity };
const originalFetch = globalThis.fetch;
let calls = 0;
let delegationNumber = 0;
globalThis.fetch = async (url, init) => {
  calls++;
  if (String(url).endsWith('/api/v1/delegate')) {
    delegationNumber++;
    return Response.json({ access_token: 'fixture.delegation.token', token_type: 'DPoP', cnf: { jkt: 'fixture' }, expires_in: 900, service: 'github', scopes: ['repo'], delegation_id: `mixed-${delegationNumber}` });
  }
  assert.equal(String(url), 'https://cred.example.com/api/v1/use');
  assert.equal(init.headers.Authorization, 'DPoP fixture.delegation.token');
  assert.ok(init.headers.DPoP);
  return Response.json({ ok: true, status: 200, body: { fixture: true } });
};
try {
  for (const [producer, consumer] of [[aiEsm, aiCjs], [aiCjs, aiEsm]]) {
    const delegated = await producer.credDelegateTool(options).execute({ service: 'github', scopes: ['repo'] });
    assert.ok(!('token' in delegated) && !('accessToken' in delegated));
    const input = { delegationId: delegated.delegationId, url: 'https://api.github.com/user', method: 'GET' };
    const used = await consumer.credUseTool(options).execute(input);
    assert.deepEqual(used.body, { fixture: true });
    const before = calls;
    for (const changed of [{ agentIdentity: otherIdentity }, { baseUrl: 'https://other.example.com' }]) {
      await assert.rejects(consumer.credUseTool({ ...options, ...changed }).execute(input), /another agent or server/);
    }
    assert.equal(calls, before, 'incorrectly bound use must not reach the network');
  }
} finally {
  globalThis.fetch = originalFetch;
}
console.log('mixed ESM/CommonJS vault identity and AI delegation smoke ok');
