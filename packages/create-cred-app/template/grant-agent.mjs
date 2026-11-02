#!/usr/bin/env node
// Grant this app's agent a Permission: what it may do on one connected service.
// An agent with no Permission is issued nothing. Granting again replaces the
// limits, and restores an agent whose access was revoked.
//
//   npm run grant -- github github.read
//   npm run grant -- google calendar.readonly gmail.readonly
//   npm run grant -- --agent did:key:z6Mk... slack channels:read
//
// The admin token goes only to this app's own server: over loopback, or over
// https when the server is remote. It and the address come from the .env beside
// this script, never from the environment, so a stray variable cannot send the
// token somewhere else.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

function readEnvFile(name) {
  const file = join(here, name);
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

const env = readEnvFile('.env');
const agentId = agentOverride ?? readEnvFile('agent.env').CRED_AGENT_DID;
if (!agentId) fail('No agent named: pass --agent, or keep agent.env beside this script.');
if (!env.ADMIN_TOKEN) fail('No ADMIN_TOKEN in the .env beside this script.');

/** The server's address, or null if the admin token cannot safely go there. */
function serverBase() {
  const isLoopback = (host) => host === 'localhost' || host === '::1' || /^127(\.\d{1,3}){3}$/.test(host);
  const host = env.HOST ?? '127.0.0.1';
  // A server listening on every interface is reachable here on loopback.
  if (host === '0.0.0.0' || host === '::') return `http://127.0.0.1:${env.PORT ?? '3456'}`;
  if (isLoopback(host)) return `http://${host === '::1' ? '[::1]' : host}:${env.PORT ?? '3456'}`;
  // Remote: only the public https address the server is configured with.
  try {
    const url = new URL(env.REDIRECT_BASE_URI ?? '');
    return url.protocol === 'https:' ? url.origin : null;
  } catch {
    return null;
  }
}

const base = serverBase();
if (!base) fail(`Refusing to send the admin token to ${env.HOST} over http. Use a loopback HOST, or set REDIRECT_BASE_URI to the server's https address in .env.`);

let res;
try {
  res = await fetch(`${base}/admin/permissions`, {
    method: 'POST',
    // A redirect would carry the token to a host nobody checked.
    redirect: 'error',
    headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId, connectionId: service, allowedScopes: scopes }),
  });
} catch {
  fail(`Could not reach the server at ${base}, or it redirected. Start it with npm start.`);
}
if (!res.ok) fail(`The server refused the grant (${res.status}): ${await res.text()}`);
console.log(`Granted ${agentId} on ${service}, for every user of this server: ${scopes.join(', ')}`);
