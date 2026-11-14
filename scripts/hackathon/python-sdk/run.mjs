#!/usr/bin/env node
// The Python SDK (packages/sdk-python) as a WIMSE workload against a real
// Cred server: delegation and a brokered read with WIT + HTTP signature
// (draft-ietf-wimse-http-signature-08) and a bound Txn-Token, plus two
// refusals. Needs `npm run build` and a Python with packages/sdk-python
// installed (set PYTHON; default python3).
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { witIssuer, txnService } = await import('../lib/issuers.mjs');
const { startMockProvider } = await import('../lib/mock-provider.mjs');
const { startCred } = await import('../lib/cred.mjs');

const TD = 'domain-b.example';
const state = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-python-sdk-'));
const files = path.join(state, 'workloads');
fs.mkdirSync(files, { mode: 0o700 });
const provider = await startMockProvider();
const issuer = witIssuer(TD, state);
const tts = txnService(TD, state);
const planner = issuer.workload('/ns/agents/sa/planner');
const stranger = issuer.workload('/ns/agents/sa/stranger');

const cred = await startCred({
  trustDomains: { [TD]: { witBundle: issuer.bundlePath, keyUse: 'wit-svid' } },
  txnTokens: {
    [TD]: {
      aud: TD, jwks: tts.jwksPath, keyUse: 'sig',
      userSubject: { claim: 'sub', pattern: '^user:([a-z0-9._-]{1,64})$' },
      scopeMap: { google: { 'calendar.read': ['calendar.readonly'], 'calendar.write': ['calendar.events'] } },
    },
  },
  user: 'alice',
  connectionScopes: ['calendar.readonly', 'calendar.events'],
  agents: [
    { name: 'planner', workload: planner.subject, allowedScopes: ['calendar.readonly'] },
    { name: 'stranger', workload: stranger.subject },
  ],
}, { stateDir: path.join(state, 'cred') });

let code = 1;
try {
  for (const [name, w] of Object.entries({ planner, stranger })) {
    fs.writeFileSync(path.join(files, `${name}.wit`), w.wit, { mode: 0o600 });
    fs.writeFileSync(path.join(files, `${name}.key.pem`), w.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  }
  const id = cred.agents.planner.identity;
  fs.writeFileSync(path.join(files, 'planner.agent.json'),
    JSON.stringify({ did: id.did, private_key_hex: Buffer.from(id.privateKey).toString('hex') }), { mode: 0o600 });
  const mint = () => tts.mint({ txn: crypto.randomUUID() });
  fs.writeFileSync(path.join(files, 'txns.json'), JSON.stringify({
    planner: [mint(), mint(), mint(), mint()], stranger: [mint(), mint()],
  }));
  const before = provider.received.length;
  // Async: Cred runs in this process and must keep serving while Python runs.
  const py = await new Promise((resolve) => {
    const child = spawn(process.env.PYTHON ?? 'python3', ['-I', path.join(here, 'client.py'), cred.baseUrl, files], {
      stdio: ['ignore', 'inherit', 'inherit'],
    });
    child.on('close', (status) => resolve({ status }));
  });
  const calls = provider.received.length - before;
  console.log(`Provider calls: ${calls} (expected 1: only the allowed read)`);
  code = py.status === 0 && calls === 1 ? 0 : 1;
  console.log(code === 0 ? 'Python SDK interop: PASS' : 'Python SDK interop: FAIL');
} finally {
  await cred.close?.();
  await provider.close?.();
  fs.rmSync(state, { recursive: true, force: true });
}
process.exit(code);
