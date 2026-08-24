/**
 * Proxy configuration.
 *
 * Runtime/deployment settings come from environment variables (matching the
 * Cred server/mcp convention). The scope map is a separate reviewable file,
 * not env config - see config/scope-map.json.
 */

import { fileURLToPath } from 'node:url';
import { resolve, isAbsolute } from 'node:path';
import { CRED_PUBLIC_KEY_HEX } from '@credninja/sdk';

/** Directory containing this example (parent of src/). */
export const EXAMPLE_ROOT = fileURLToPath(new URL('..', import.meta.url));

export type SseExpiryBehavior = 'terminate' | 'ride';

export interface ProxyConfig {
  listenHost: string;
  listenPort: number;
  /** Upstream x64dbg plugin HTTP base, e.g. http://127.0.0.1:9094 */
  upstreamUrl: string;
  /** Service slug receipts must carry in their `service` claim. */
  service: string;
  /** Ed25519 public key (hex) of the delegation issuer that signs receipts. */
  issuerPublicKeyHex: string;
  /**
   * Optional subject allowlist: if set, the receipt `sub` (agent DID) must match.
   * This is an extra constraint on top of the mandatory proof-of-possession check
   * (which already proves the caller holds the subject's key); it is not a bearer
   * escape hatch. Unset = accept any validly signed receipt whose holder proves
   * possession of its subject key.
   */
  expectedAgentDid?: string;
  /** Max age (s) for legacy receipts without an `exp` claim. */
  receiptMaxAgeSeconds?: number;
  /** Absolute path to the scope map JSON. */
  scopeMapPath: string;
  /** Optional file to append audit lines to (audit always also goes to stdout). */
  auditLogPath?: string;
  /** What to do with an SSE stream when the token that opened it expires. */
  sseOnExpiry: SseExpiryBehavior;
  /** Filter tools/list responses down to tools the credential can actually call. */
  filterToolsList: boolean;
  /** Mirror audit lines to stdout (in addition to the optional audit file). */
  auditStdout: boolean;
  /** Freshness window (seconds) for a proof-of-possession `iat`. Also the replay-cache TTL. */
  popWindowSeconds: number;
}

function envInt(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (Number.isNaN(n)) throw new Error(`Invalid ${name}: "${raw}" is not an integer`);
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ProxyConfig {
  const upstreamUrl = (env.X64DBG_UPSTREAM_URL ?? 'http://127.0.0.1:9094').replace(/\/$/, '');
  try {
    void new URL(upstreamUrl); // validate; throws on a malformed URL
  } catch {
    throw new Error(`Invalid X64DBG_UPSTREAM_URL: "${upstreamUrl}"`);
  }

  const scopeMapRaw = env.X64DBG_SCOPE_MAP ?? 'config/scope-map.json';
  const scopeMapPath = isAbsolute(scopeMapRaw) ? scopeMapRaw : resolve(EXAMPLE_ROOT, scopeMapRaw);

  const sseOnExpiryRaw = (env.X64DBG_SSE_ON_EXPIRY ?? 'terminate').toLowerCase();
  if (sseOnExpiryRaw !== 'terminate' && sseOnExpiryRaw !== 'ride') {
    throw new Error(`Invalid X64DBG_SSE_ON_EXPIRY: "${sseOnExpiryRaw}" (use "terminate" or "ride")`);
  }

  return {
    listenHost: env.X64DBG_LISTEN_HOST ?? '127.0.0.1',
    listenPort: envInt(env, 'X64DBG_LISTEN_PORT', 9114),
    upstreamUrl,
    service: env.X64DBG_SERVICE ?? 'x64dbg',
    issuerPublicKeyHex: env.X64DBG_ISSUER_PUBLIC_KEY_HEX ?? CRED_PUBLIC_KEY_HEX,
    expectedAgentDid: env.X64DBG_EXPECTED_AGENT_DID || undefined,
    receiptMaxAgeSeconds:
      env.X64DBG_RECEIPT_MAX_AGE_SECONDS !== undefined
        ? envInt(env, 'X64DBG_RECEIPT_MAX_AGE_SECONDS', 3600)
        : undefined,
    scopeMapPath,
    auditLogPath: env.X64DBG_AUDIT_LOG || undefined,
    sseOnExpiry: sseOnExpiryRaw,
    filterToolsList: (env.X64DBG_FILTER_TOOLS_LIST ?? 'true').toLowerCase() !== 'false',
    auditStdout: (env.X64DBG_AUDIT_STDOUT ?? 'true').toLowerCase() !== 'false',
    popWindowSeconds: envInt(env, 'X64DBG_POP_WINDOW_SECONDS', 30),
  };
}
