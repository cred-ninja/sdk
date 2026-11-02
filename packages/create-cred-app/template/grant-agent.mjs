#!/usr/bin/env node
// Grant this app's agent a Permission: what it may do on one connected service.
// An agent with no Permission is issued nothing. Granting again replaces the
// limits, and restores an agent whose access was revoked.
//
//   npm run grant -- github github.read
//   npm run grant -- google calendar.readonly gmail.readonly
//   npm run grant -- --agent did:key:z6Mk... slack channels:read
import { existsSync, readFileSync } from 'node:fs';

function readEnvFile(file) {
  if (!existsSync(file)) return {};
  return Object.fromEntries(readFileSync(file, 'utf8').split('\n')
    .filter((line) => /^[A-Z_][A-Z0-9_]*=/.test(line))
    .map((line) => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1).trim()]));
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

const args = process.argv.slice(2);
const agentFlag = args.indexOf('--agent');
const agentOverride = agentFlag >= 0 ? args.splice(agentFlag, 2)[1] : undefined;
const [service, ...scopes] = args;
if (!service || scopes.length === 0) {
  fail('Usage: npm run grant -- [--agent <did:key>] <service> <scope> [scope...]');
}

const env = { ...readEnvFile('.env'), ...process.env };
const agentId = agentOverride ?? readEnvFile('agent.env').CRED_AGENT_DID;
if (!agentId) fail('No agent named: pass --agent, or keep agent.env beside this script.');
if (!env.ADMIN_TOKEN) fail('No ADMIN_TOKEN in .env.');

const host = !env.HOST || env.HOST === '0.0.0.0' ? '127.0.0.1' : env.HOST;
const base = `http://${host}:${env.PORT ?? '3456'}`;
let res;
try {
  res = await fetch(`${base}/admin/permissions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId, connectionId: service, allowedScopes: scopes }),
  });
} catch {
  fail(`Could not reach the server at ${base}. Start it with npm start.`);
}
if (!res.ok) fail(`The server refused the grant (${res.status}): ${await res.text()}`);
console.log(`Granted ${agentId} on ${service}: ${scopes.join(', ')}`);
