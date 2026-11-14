/**
 * WIMSE workload signing for cloud mode: the MCP server reaches Cred as a
 * workload with a WIT plus an HTTP Message Signature
 * (draft-ietf-wimse-http-signature-08) instead of an agent token.
 *
 * The WIT and the optional Txn-Token are read from files on every request, so
 * a rotated file takes effect without a restart. The private key is loaded
 * once at startup. Read failures never echo the file path, because errors from
 * a tool call can reach the model.
 */
import { createPrivateKey, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { CredError, createWimseHttpSigner, type SdkSignableRequest } from '@credninja/sdk';
import type { CredMcpWimseConfig } from './config.js';

function readTokenFile(path: string, what: string): string {
  let value: string;
  try {
    value = readFileSync(path, 'utf8').trim();
  } catch {
    throw new CredError(`wimse ${what} unavailable`, 'invalid_config', 0);
  }
  if (!value) throw new CredError(`wimse ${what} unavailable`, 'invalid_config', 0);
  return value;
}

/** The WIT's `sub` claim, read without verification. Used only to key local rate-limit counters. */
export function witSubject(wit: string): string {
  const parts = wit.split('.');
  if (parts.length !== 3) throw new Error('CRED_WIMSE_WIT_FILE does not hold a compact JWT');
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw new Error('CRED_WIMSE_WIT_FILE does not hold a compact JWT');
  }
  const sub = (claims as { sub?: unknown } | null)?.sub;
  if (typeof sub !== 'string' || !sub) throw new Error('The WIT in CRED_WIMSE_WIT_FILE has no sub claim');
  return sub;
}

function loadKey(path: string, alg: CredMcpWimseConfig['alg']): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(readFileSync(path, 'utf8'));
  } catch {
    throw new Error('CRED_WIMSE_KEY_FILE must be a readable PKCS#8 PEM private key');
  }
  const fits = alg === 'ES256'
    ? key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
    : key.asymmetricKeyType === 'ed25519';
  if (!fits) throw new Error(`CRED_WIMSE_KEY_FILE does not hold a key for ${alg}`);
  return key;
}

export interface WimseWorkload {
  signRequest: (request: SdkSignableRequest) => Record<string, string>;
  /** The WIT's sub at startup. A WIT with a different sub needs a restart. */
  subject: string;
}

/** Loads the key and checks the WIT at startup; throws on any misconfiguration. */
export function loadWimseWorkload(config: CredMcpWimseConfig): WimseWorkload {
  const privateKey = loadKey(config.keyFile, config.alg);
  let subject: string;
  try {
    subject = witSubject(readTokenFile(config.witFile, 'WIT'));
  } catch (err) {
    if (err instanceof CredError) throw new Error('CRED_WIMSE_WIT_FILE must be a readable, non-empty file');
    throw err;
  }
  const signRequest = createWimseHttpSigner({
    wit: () => readTokenFile(config.witFile, 'WIT'),
    privateKey,
    alg: config.alg,
    ...(config.txnTokenFile ? { txnToken: () => readTokenFile(config.txnTokenFile as string, 'Txn-Token') } : {}),
  });
  return { signRequest, subject };
}
