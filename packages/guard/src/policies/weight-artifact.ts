/**
 * @credninja/guard — Weight Artifact Policy (experimental)
 *
 * For agents that program other models in weight space: constrains the
 * brokered calls through which an agent reads or writes model weights,
 * checkpoints and intermediate tensors at an artifact store (a model hub,
 * an object store with presigned URLs, an internal registry). The store's
 * credential stays in the vault and is exercised through `cred_use` like any
 * other delegation; this policy decides which calls the delegation may make.
 *
 * Per provider it pins the hosts, limits writes to declared path prefixes,
 * optionally pins the digests an agent may load or push, and caps the
 * declared artifact size. Digest and size are declared by the caller in
 * `GuardContext.metadata` (`artifactSha256`, `artifactBytes`); the policy
 * fails closed when a pin or cap is configured and the declaration is
 * missing. It cannot verify the bytes itself: pair it with a broker that
 * checks the response digest, or treat the declaration as the agent's
 * signed intent, recorded in the audit event.
 */

import type { CredPolicy, GuardContext, ParameterValue, PolicyDescriptor, PolicyResult } from '../types.js';
import { cloneParameters, isPlainObject, isPositiveInteger, isStringArray, requireOptionalBoolean, requireOptionalStringArray } from '../weightspace/params.js';

export interface WeightArtifactStoreConfig {
  /**
   * Hostnames the store answers on. An entry starting with `.` matches any
   * host under that suffix (`.r2.cloudflarestorage.com`); any other entry
   * must match the hostname exactly.
   */
  hosts: string[];
  /** Methods that read. Default `['GET', 'HEAD']`. */
  readMethods?: string[];
  /** Allow writes (PUT, POST, PATCH, DELETE). Default false. */
  allowWrite?: boolean;
  /** With `allowWrite`, path prefixes a write may target. Empty or absent: any path. */
  writePathPrefixes?: string[];
  /**
   * SHA-256 hex digests (lowercase) the agent may read or write. When set,
   * every call must declare `metadata.artifactSha256` and it must be listed.
   */
  pinnedDigests?: string[];
  /**
   * Largest artifact, in bytes. When set, every call must declare
   * `metadata.artifactBytes` and it must not exceed this.
   */
  maxBytes?: number;
}

export interface WeightArtifactPolicyConfig {
  /** Per-provider store rules. Providers not listed are skipped. */
  stores: Record<string, WeightArtifactStoreConfig>;
}

const WRITE_METHODS = new Set(['PUT', 'POST', 'PATCH', 'DELETE']);
const DIGEST_RE = /^[0-9a-f]{64}$/;

function hostMatches(hostname: string, entry: string): boolean {
  const host = hostname.toLowerCase();
  const rule = entry.toLowerCase();
  if (rule.startsWith('.')) return host.endsWith(rule) && host.length > rule.length;
  return host === rule;
}

export class WeightArtifactPolicy implements CredPolicy {
  readonly name = 'weight-artifact';
  private readonly config: WeightArtifactPolicyConfig;

  constructor(config: WeightArtifactPolicyConfig) {
    this.config = WeightArtifactPolicy.parseParameters(cloneParameters(config) as Record<string, ParameterValue>);
  }

  evaluate(ctx: GuardContext): PolicyResult {
    const { provider, targetUrl, targetMethod, metadata } = ctx;
    const store = this.config.stores[provider];
    if (!targetUrl) return { decision: 'SKIP', policy: this.name, reason: 'No targetUrl — not a cred_use request' };
    if (!store) return { decision: 'SKIP', policy: this.name, reason: `No artifact store rules for provider: ${provider}` };

    const deny = (reason: string, code: string): PolicyResult => ({ decision: 'DENY', policy: this.name, reason, code });

    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return deny('Target URL could not be parsed', 'artifact_url_invalid');
    }
    if (parsed.protocol !== 'https:') return deny('Target URL must use HTTPS', 'artifact_url_invalid');
    if (parsed.username || parsed.password) return deny('Target URL must not contain userinfo', 'artifact_url_invalid');
    if (!store.hosts.some((entry) => hostMatches(parsed.hostname, entry))) {
      return deny(`Host ${parsed.hostname} is not an allowed artifact store for ${provider}`, 'artifact_host_not_allowed');
    }

    const method = (targetMethod ?? 'GET').toUpperCase();
    const readMethods = new Set((store.readMethods ?? ['GET', 'HEAD']).map((m) => m.toUpperCase()));
    const isRead = readMethods.has(method);
    const isWrite = WRITE_METHODS.has(method);
    if (!isRead && !isWrite) return deny(`Method ${method} is neither a read nor a write for artifact stores`, 'artifact_method_not_allowed');
    if (isWrite) {
      if (!store.allowWrite) return deny(`Writes (${method}) are not allowed for ${provider} artifacts`, 'artifact_write_not_allowed');
      const prefixes = store.writePathPrefixes ?? [];
      if (prefixes.length > 0 && !prefixes.some((prefix) => parsed.pathname.startsWith(prefix))) {
        return deny(`Path ${parsed.pathname} is outside the writable prefixes for ${provider}`, 'artifact_path_not_writable');
      }
    }

    if (store.pinnedDigests && store.pinnedDigests.length > 0) {
      const declared = metadata?.artifactSha256;
      if (typeof declared !== 'string' || !DIGEST_RE.test(declared.toLowerCase())) {
        return deny('Call must declare metadata.artifactSha256 (64 hex) for a pinned artifact store', 'artifact_digest_required');
      }
      if (!store.pinnedDigests.includes(declared.toLowerCase())) {
        return deny(`Artifact digest ${declared.slice(0, 12)}… is not pinned for ${provider}`, 'artifact_digest_not_pinned');
      }
    }

    if (store.maxBytes !== undefined) {
      const declared = metadata?.artifactBytes;
      if (typeof declared !== 'number' || !Number.isFinite(declared) || declared < 0) {
        return deny('Call must declare metadata.artifactBytes for a size-capped artifact store', 'artifact_size_required');
      }
      if (declared > store.maxBytes) {
        return deny(`Artifact of ${declared} bytes exceeds the ${store.maxBytes} byte cap for ${provider}`, 'artifact_too_large');
      }
    }

    return {
      decision: 'ALLOW',
      policy: this.name,
      reason: `${isWrite ? 'Write' : 'Read'} of artifact at ${parsed.hostname} allowed for ${provider}`,
    };
  }

  describe(): PolicyDescriptor {
    return { kind: this.name, parameters: cloneParameters(this.config) as Record<string, ParameterValue> };
  }

  withParameters(parameters: Record<string, ParameterValue>): WeightArtifactPolicy {
    return new WeightArtifactPolicy(WeightArtifactPolicy.parseParameters(parameters));
  }

  static parseParameters(parameters: Record<string, ParameterValue>): WeightArtifactPolicyConfig {
    if (!isPlainObject(parameters) || !isPlainObject(parameters.stores)) throw new Error('weight-artifact.stores must be an object');
    const stores: Record<string, WeightArtifactStoreConfig> = {};
    for (const [provider, raw] of Object.entries(parameters.stores)) {
      const label = `weight-artifact.stores.${provider}`;
      if (!isPlainObject(raw)) throw new Error(`${label} must be an object`);
      if (!isStringArray(raw.hosts) || raw.hosts.length === 0) throw new Error(`${label}.hosts must be a non-empty array of hostnames`);
      for (const host of raw.hosts) {
        if (!/^\.?[a-z0-9-]+(\.[a-z0-9-]+)*$/i.test(host)) throw new Error(`${label}.hosts: "${host}" is not a hostname or .suffix`);
      }
      const store: WeightArtifactStoreConfig = { hosts: [...raw.hosts] };
      const readMethods = requireOptionalStringArray(raw.readMethods, `${label}.readMethods`);
      if (readMethods) {
        for (const method of readMethods) {
          if (WRITE_METHODS.has(method.toUpperCase())) throw new Error(`${label}.readMethods cannot list the write method ${method}`);
        }
        store.readMethods = readMethods;
      }
      const allowWrite = requireOptionalBoolean(raw.allowWrite, `${label}.allowWrite`);
      if (allowWrite !== undefined) store.allowWrite = allowWrite;
      const prefixes = requireOptionalStringArray(raw.writePathPrefixes, `${label}.writePathPrefixes`);
      if (prefixes) {
        for (const prefix of prefixes) {
          if (!prefix.startsWith('/')) throw new Error(`${label}.writePathPrefixes: "${prefix}" must start with /`);
        }
        store.writePathPrefixes = prefixes;
      }
      const digests = requireOptionalStringArray(raw.pinnedDigests, `${label}.pinnedDigests`);
      if (digests) {
        for (const digest of digests) {
          if (!DIGEST_RE.test(digest)) throw new Error(`${label}.pinnedDigests: "${digest}" is not a lowercase sha256 hex digest`);
        }
        store.pinnedDigests = digests;
      }
      if (raw.maxBytes !== undefined && raw.maxBytes !== null) {
        if (!isPositiveInteger(raw.maxBytes)) throw new Error(`${label}.maxBytes must be a positive integer`);
        store.maxBytes = raw.maxBytes;
      }
      stores[provider] = store;
    }
    return { stores };
  }
}

/** Factory function to create a weight artifact policy (experimental). */
export function weightArtifactPolicy(config: WeightArtifactPolicyConfig): WeightArtifactPolicy {
  return new WeightArtifactPolicy(config);
}
