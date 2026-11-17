/**
 * External identity sources: a caller proves an identity that Cred did not
 * issue (a WIMSE Workload Identity Token, a Tailscale node), Cred verifies it
 * itself, and explicit configuration maps it to an existing Cred agent. Every
 * later step (Permission, Guard, receipts, audit) runs on that agent's DID
 * exactly as it does for a did:key agent.
 */

export type ExternalIdentityKind = 'wimse' | 'tailscale';

/** The parts of an incoming request a source may read. */
export interface IdentityRequest {
  /** Upper-case HTTP method. */
  method: string;
  /**
   * The request's target URI as the broker publishes it: configured public
   * base URI plus path, without query or fragment. Never derived from Host.
   */
  targetUri: string;
  /** Lower-case header names, as Node delivers them. */
  headers: Readonly<Record<string, string | string[] | undefined>>;
  /**
   * Name/value pairs exactly as received (Node's `rawHeaders`), for checks
   * that the folded `headers` view hides, such as a repeated Authorization.
   */
  rawHeaders?: readonly string[];
  /** The connection's socket, so a source can tell which listener accepted it. */
  socket: unknown;
}

/** An identity a source has verified for this one request. */
export interface VerifiedExternalIdentity {
  kind: ExternalIdentityKind;
  /** `spiffe://td/path`-style Workload Identifier, or `tailscale:node:<StableID>`. */
  subject: string;
  /** The WIMSE trust domain (identifier authority), or the tailnet name. */
  trustDomain: string;
  /** Source-specific verified attributes, e.g. `{ tags: ['tag:agent'] }`. */
  attributes: Readonly<Record<string, string | readonly string[]>>;
  /**
   * The per-request proof the source verified. `'channel'` means the source
   * proved only the connection (Tailscale): the server then requires a DPoP
   * proof from the mapped agent's did:key on the same request.
   */
  proof: 'wpt' | 'http-sig' | 'channel';
  /** Seconds since the epoch after which this identity must not be used. */
  expiresAt: number;
}

/**
 * A request that carried a credential for this source, but the credential
 * failed. `detail` is for the server log and the audit `deny` event only; the
 * HTTP response never says which check failed.
 */
export class IdentityRefusal extends Error {
  readonly code: string;
  readonly detail: string;
  readonly kind: ExternalIdentityKind;

  constructor(kind: ExternalIdentityKind, code: string, detail: string) {
    super(`${kind}: ${code}`);
    this.name = 'IdentityRefusal';
    this.kind = kind;
    this.code = code;
    this.detail = detail;
  }
}

export interface ExternalIdentitySource {
  readonly kind: ExternalIdentityKind;
  /**
   * `null` when the request carries no credential for this source (so another
   * source, or the agent token, may authenticate it). Throws
   * `IdentityRefusal` when it carries one and verification fails.
   */
  authenticate(req: IdentityRequest): Promise<VerifiedExternalIdentity | null>;
}

/** One explicit mapping from a verified external subject to a Cred agent. */
export interface ExternalIdentityMapping {
  kind: ExternalIdentityKind;
  /** Exact subject string; no wildcards or prefixes. */
  subject: string;
  /** DID of an agent that already exists in the vault. */
  agentDid: string;
}

/** Exact-match lookup. `undefined` means unmapped, which callers refuse. */
export function mappedAgentDid(
  mappings: readonly ExternalIdentityMapping[],
  identity: Pick<VerifiedExternalIdentity, 'kind' | 'subject'>,
): string | undefined {
  const hits = mappings.filter((m) => m.kind === identity.kind && m.subject === identity.subject);
  // Two mappings for one subject are a configuration error, not a choice.
  return hits.length === 1 ? hits[0].agentDid : undefined;
}

/** Bounded per-process replay cache: a value is accepted once until it expires. */
export interface ReplayCache {
  /** Returns false if `key` was already recorded and has not expired; otherwise records it. */
  checkAndRecord(key: string, expiresAtSeconds: number, nowSeconds?: number): boolean;
}

export function createReplayCache(maxEntries = 100_000): ReplayCache {
  const seen = new Map<string, number>();
  return {
    checkAndRecord(key, expiresAtSeconds, nowSeconds = Math.floor(Date.now() / 1000)) {
      const prior = seen.get(key);
      if (prior !== undefined && prior >= nowSeconds) return false;
      if (seen.size >= maxEntries) {
        for (const [k, exp] of seen) if (exp < nowSeconds) seen.delete(k);
        // Still full of live entries: refuse rather than forget one, so a
        // flood cannot evict a value and then replay it.
        if (seen.size >= maxEntries) return false;
      }
      seen.set(key, expiresAtSeconds);
      return true;
    },
  };
}
