/**
 * Cloud mode as a WIMSE workload: env parsing, startup checks, and that the
 * client signs every request with the WIT currently in the file.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Cred, generateAgentIdentity } from '@credninja/sdk';
import { loadConfig } from '../config';
import { buildMcpServer } from '../server';
import { loadWimseWorkload } from '../wimse';
import { agentTokenHashForCloudMode, agentTokenHashForWimseMode } from '../guard-wiring';
import { describeAuthentication } from '../authentication';
import { handleCapabilities } from '../tools/capabilities';
import { handleWhoami } from '../tools/whoami';

const ENV_KEYS = [
  'CRED_MODE', 'CRED_AGENT_TOKEN', 'CRED_APP_CLIENT_ID', 'CRED_BASE_URL', 'CRED_AGENT_DID',
  'CRED_AGENT_PRIVATE_KEY_HEX', 'CRED_WIMSE_WIT_FILE', 'CRED_WIMSE_KEY_FILE', 'CRED_WIMSE_ALG',
  'CRED_TXN_TOKEN_FILE', 'CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX', 'CRED_WEB_BOT_AUTH_SIGNATURE_AGENT',
];

function wit(sub: string): string {
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ typ: 'wit+jwt', alg: 'ES256' })}.${enc({ sub, exp: 9999999999 })}.c2ln`;
}

let dir: string;
let saved: Record<string, string | undefined>;
let witFile: string;
let keyFile: string;

beforeEach(async () => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  dir = mkdtempSync(join(tmpdir(), 'cred-mcp-wimse-'));
  witFile = join(dir, 'wit.jwt');
  keyFile = join(dir, 'key.pem');
  writeFileSync(witFile, `${wit('wimse://b.example/agent')}\n`);
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const agent = await generateAgentIdentity();
  Object.assign(process.env, {
    CRED_APP_CLIENT_ID: 'app',
    CRED_BASE_URL: 'https://cred.example.com',
    CRED_AGENT_DID: agent.did,
    CRED_AGENT_PRIVATE_KEY_HEX: Buffer.from(agent.privateKey).toString('hex'),
    CRED_WIMSE_WIT_FILE: witFile,
    CRED_WIMSE_KEY_FILE: keyFile,
    CRED_WIMSE_ALG: 'ES256',
  });
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe('loadConfig with CRED_WIMSE_*', () => {
  it('parses a workload config with no agent token', () => {
    const config = loadConfig([]);
    expect(config.mode).toBe('cloud');
    expect(config.mode === 'cloud' && config.wimse).toEqual({ witFile, keyFile, alg: 'ES256' });
    expect(config.mode === 'cloud' && config.agentToken).toBeFalsy();
  });

  it('still requires CRED_AGENT_TOKEN when WIMSE is not configured', () => {
    for (const k of ['CRED_WIMSE_WIT_FILE', 'CRED_WIMSE_KEY_FILE', 'CRED_WIMSE_ALG']) delete process.env[k];
    expect(() => loadConfig([])).toThrow('CRED_AGENT_TOKEN environment variable is required');
  });

  it('refuses WIMSE together with an agent token or Web Bot Auth', () => {
    process.env.CRED_AGENT_TOKEN = 'cred_at_x';
    expect(() => loadConfig([])).toThrow(/not both/);
    delete process.env.CRED_AGENT_TOKEN;
    process.env.CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX = 'a'.repeat(64);
    process.env.CRED_WEB_BOT_AUTH_SIGNATURE_AGENT = 'https://agent.example.com';
    expect(() => loadConfig([])).toThrow(/Web Bot Auth/);
  });

  it('refuses CRED_WIMSE_* in local mode', () => {
    process.env.CRED_MODE = 'local';
    expect(() => loadConfig([])).toThrow(/cloud mode only/);
  });

  it('refuses a partial config, an unknown alg, or a missing agent key', () => {
    delete process.env.CRED_WIMSE_KEY_FILE;
    expect(() => loadConfig([])).toThrow(/must be provided together/);
    process.env.CRED_WIMSE_KEY_FILE = keyFile;
    process.env.CRED_WIMSE_ALG = 'RS256';
    expect(() => loadConfig([])).toThrow(/ES256 or EdDSA/);
    process.env.CRED_WIMSE_ALG = 'ES256';
    delete process.env.CRED_AGENT_PRIVATE_KEY_HEX;
    expect(() => loadConfig([])).toThrow(/DPoP proof of the agent key/);
  });

  it('builds a server, and refuses at startup an unreadable key, a key for another alg, or a bad WIT', () => {
    expect(() => buildMcpServer(loadConfig([]))).not.toThrow();
    process.env.CRED_WIMSE_KEY_FILE = join(dir, 'missing.pem');
    expect(() => buildMcpServer(loadConfig([]))).toThrow(/readable PKCS#8/);
    process.env.CRED_WIMSE_KEY_FILE = keyFile;
    process.env.CRED_WIMSE_ALG = 'EdDSA';
    expect(() => buildMcpServer(loadConfig([]))).toThrow(/does not hold a key for EdDSA/);
    process.env.CRED_WIMSE_ALG = 'ES256';
    writeFileSync(witFile, '');
    expect(() => buildMcpServer(loadConfig([]))).toThrow(/readable, non-empty/);
    writeFileSync(witFile, 'not-a-jwt');
    expect(() => buildMcpServer(loadConfig([]))).toThrow(/compact JWT/);
  });

  it('keys rate limits on the WIT sub in its own namespace', () => {
    expect(agentTokenHashForWimseMode('x')).not.toBe(agentTokenHashForCloudMode('x'));
    expect(loadWimseWorkload({ witFile, keyFile, alg: 'ES256' }).subject).toBe('wimse://b.example/agent');
  });
});

describe('the WIMSE workload signs each request with the current files', () => {
  it('sends a covered WIT and Txn-Token, re-read after rotation, and never leaks the path on a read failure', async () => {
    const seen: http.IncomingHttpHeaders[] = [];
    const server = http.createServer((req, res) => {
      seen.push(req.headers);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ providers: [] }));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as { port: number };
    const txnFile = join(dir, 'txn.jwt');
    writeFileSync(txnFile, 'txn-one');
    try {
      const workload = loadWimseWorkload({ witFile, keyFile, alg: 'ES256', txnTokenFile: txnFile });
      const cred = new Cred({ baseUrl: `http://127.0.0.1:${port}`, signRequest: workload.signRequest });
      await cred.listProviders();
      writeFileSync(witFile, `${wit('wimse://b.example/agent')}.rotated`.replace(/\.c2ln\.rotated$/, '.bmV3'));
      writeFileSync(txnFile, 'txn-two');
      await cred.listProviders();
      expect(seen).toHaveLength(2);
      expect(seen[0]['workload-identity-token']).toBe(wit('wimse://b.example/agent'));
      expect(seen[1]['workload-identity-token']).toBe(wit('wimse://b.example/agent').replace(/\.c2ln$/, '.bmV3'));
      expect([seen[0]['txn-token'], seen[1]['txn-token']]).toEqual(['txn-one', 'txn-two']);
      expect(seen[1]['signature-input']).toMatch(/"txn-token".*tag="wimse-workload-to-workload"/);
      expect(seen[1].authorization).toBeUndefined();

      writeFileSync(witFile, wit('wimse://b.example/someone-else'));
      const changed = await cred.listProviders().then(() => undefined, (e: Error) => e);
      expect(changed?.message).toBe('wimse WIT subject changed; restart required');

      rmSync(witFile);
      const err = await cred.listProviders().then(() => undefined, (e: Error) => e);
      expect(err?.message).toBe('wimse WIT unavailable');
      expect(err?.message).not.toContain(dir);
      expect(seen).toHaveLength(2);
    } finally {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    }
  });
});

describe('cred_capabilities and cred_whoami report how this instance authenticates', () => {
  it('reports wimse-workload with the Txn-Token flag, and never a path, key or token', async () => {
    process.env.CRED_TXN_TOKEN_FILE = join(dir, 'txn.jwt');
    const authentication = describeAuthentication(loadConfig([]));
    expect(authentication).toEqual({ mode: 'wimse-workload', txnToken: true, webBotAuth: false });
    const caps = await handleCapabilities({}, { cred: { listProviders: async () => [] } as any, authentication });
    const who = await handleWhoami({}, { authentication });
    for (const result of [caps, who]) {
      const text = String(result.content[0]?.text);
      expect(JSON.parse(text).authentication).toEqual(authentication);
      expect(text).not.toContain(dir);
      expect(text).not.toContain(process.env.CRED_AGENT_PRIVATE_KEY_HEX as string);
    }
  });

  it('reports agent-token (with Web Bot Auth when set) and local modes', () => {
    for (const k of ['CRED_WIMSE_WIT_FILE', 'CRED_WIMSE_KEY_FILE', 'CRED_WIMSE_ALG']) delete process.env[k];
    process.env.CRED_AGENT_TOKEN = 'cred_at_x';
    expect(describeAuthentication(loadConfig([]))).toEqual({ mode: 'agent-token', txnToken: false, webBotAuth: false });
    process.env.CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX = 'a'.repeat(64);
    process.env.CRED_WEB_BOT_AUTH_SIGNATURE_AGENT = 'https://agent.example.com';
    expect(describeAuthentication(loadConfig([])).webBotAuth).toBe(true);
    expect(describeAuthentication({ mode: 'local' } as any)).toEqual({ mode: 'local', txnToken: false, webBotAuth: false });
    expect(describeAuthentication({ mode: 'local', webBotAuth: { privateKeyHex: 'a', signatureAgent: 'https://a', ttlSeconds: 30 } } as any).webBotAuth).toBe(true);
  });
});
