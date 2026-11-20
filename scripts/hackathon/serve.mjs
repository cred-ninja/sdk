#!/usr/bin/env node
// Run Cred for a hackathon participant: your trust domain, your WIT trust
// bundle file, your audience URL and your workload-to-agent mapping, from one
// JSON file (see docs/HACKATHON.md and scripts/hackathon/hackathon.example.json).
//
//   node scripts/hackathon/serve.mjs --config my-domain.json [--state ./cred-state]
//
// Cred listens until you stop it (Ctrl-C). A mock provider standing in for
// the Google Calendar API runs in the same process, so a delegated call
// works end to end without real provider credentials.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? dflt : process.argv[i + 1];
};
const configPath = arg('--config');
if (!configPath) {
  console.error('usage: node scripts/hackathon/serve.mjs --config <file.json> [--state <dir>]');
  process.exit(2);
}
if (!fs.existsSync(path.join(root, 'packages/server/dist/index.js'))) {
  const b = spawnSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });
  if (b.status !== 0) process.exit(b.status ?? 1);
}
const { startCred } = await import('./lib/cred.mjs');
const { startMockProvider } = await import('./lib/mock-provider.mjs');

const configDir = path.dirname(path.resolve(configPath));
const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
// Paths in the config are relative to the config file.
for (const t of Object.values(cfg.trustDomains ?? {})) t.witBundle = path.resolve(configDir, t.witBundle);
for (const t of Object.values(cfg.txnTokens ?? {})) t.jwks = path.resolve(configDir, t.jwks);

const stateDir = path.resolve(arg('--state', path.join(configDir, 'cred-state')));
const provider = await startMockProvider();
const cred = await startCred(cfg, { stateDir, quiet: false });
const tokens = path.join(stateDir, 'tokens.json');
fs.writeFileSync(tokens, JSON.stringify({ adminToken: cred.adminToken, agentToken: cred.agentToken }, null, 2), { mode: 0o600 });

console.log(`\nCred is listening on ${cred.baseUrl}`);
console.log(`Trusted WIMSE trust domains: ${Object.keys(cfg.trustDomains ?? {}).join(', ')}`);
console.log(`Txn-Tokens: ${Object.keys(cfg.txnTokens ?? {}).length ? Object.keys(cfg.txnTokens).join(', ') : 'not configured (header ignored)'}`);
console.log('Workload -> agent mappings:');
for (const a of Object.values(cred.agents)) console.log(`  ${a.workload}  ->  ${a.name} (${a.did})`);
if (Object.values(cred.agents).some((a) => a.identity)) console.log(`Generated agent keys (for DPoP on /delegate and /use): ${path.join(stateDir, 'agents')}/<name>.json (mode 0600)`);
console.log(`\nAudience (wimse-aud / WPT aud) for an agent route: ${cred.baseUrl}/api/v1/connections`);
console.log(`Try:  GET ${cred.baseUrl}/api/v1/connections?user_id=${cred.user}  with Workload-Identity-Token + Signature-Input/Signature (or Authorization: WPT)`);
console.log(`Admin and agent tokens for this local server: ${tokens} (mode 0600)`);
console.log(`Audit trail:  curl -s -H "Authorization: Bearer $(node -p 'require("${tokens}").adminToken')" ${cred.baseUrl}/admin/audit\n`);

const stop = async () => {
  await cred.close();
  await provider.close();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
