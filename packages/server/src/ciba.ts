/**
 * CIBA-derived agent consent (draft-sweeney-wimse-credential-delegation-02
 * Section 8.1; OpenID Connect CIBA Core 1.0, poll mode).
 *
 * The agent side is CIBA on every deployment: the agent asks at
 * `/bc-authorize`, receives an `auth_req_id`, and polls the token endpoint
 * with `grant_type=urn:openid:params:grant-type:ciba` until the request is
 * approved, denied or expires. Who approves comes from the Permission (the
 * subject, an admin, or both); how the subject is asked is pluggable: the
 * built-in signed-link page announced by webhook, or an external OpenID
 * Provider's own CIBA endpoint. Requests are held in this process.
 */
import crypto from 'crypto';
import type { PermissionApprover } from '@credninja/vault';

export const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';
/** How long an approval request waits for a decision. */
export const DEFAULT_CIBA_EXPIRES_SECONDS = 300;
/** The minimum seconds between token polls (CIBA Section 7.3 `interval`). */
export const DEFAULT_CIBA_INTERVAL_SECONDS = 5;
/** The most live requests held at once, so a flood of asks cannot grow memory without bound. */
export const DEFAULT_MAX_APPROVAL_REQUESTS = 10_000;
/** The most live requests one agent, or one subject, may hold: no one fills the shared pool. */
export const DEFAULT_MAX_APPROVAL_REQUESTS_PER_PARTY = 20;
/** How long a finished request is kept for the agent's last poll. */
const FINISHED_RETENTION_MS = 60_000;

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'redeemed';

export interface ApprovalRequest {
  authReqId: string;
  subject: string;
  agentDid: string;
  /** RFC 7638 thumbprint of the agent key the request is bound to. */
  jkt: string;
  service: string;
  appClientId: string;
  scopes: string[];
  /** Validated `authorization_details`, when the agent asked for them. */
  capabilities?: unknown[];
  constraints: unknown[];
  bindingMessage?: string;
  approver: PermissionApprover;
  createdAt: number;
  expiresAt: number;
  intervalSeconds: number;
  lastPolledAt: number | null;
  status: ApprovalStatus;
  /** Who has approved so far, by role. */
  approvals: { subject?: string; admin?: string };
  deniedBy?: string;
  /** When the request was denied or redeemed. */
  finishedAt?: number;
}

export type PollResult =
  | { ok: true; request: ApprovalRequest }
  | { ok: false; error: 'authorization_pending' | 'slow_down' | 'access_denied' | 'expired_token' | 'invalid_grant'; description: string };

/** Approvals held by this process, keyed by `auth_req_id`. */
export class ApprovalStore {
  private readonly requests = new Map<string, ApprovalRequest>();
  private readonly linkKey: Buffer;

  private readonly maxRequests: number;
  private readonly maxPerParty: number;

  constructor(linkKey: Buffer = crypto.randomBytes(32), opts: { maxRequests?: number; maxPerParty?: number } = {}) {
    this.linkKey = linkKey;
    this.maxRequests = opts.maxRequests ?? DEFAULT_MAX_APPROVAL_REQUESTS;
    this.maxPerParty = opts.maxPerParty ?? DEFAULT_MAX_APPROVAL_REQUESTS_PER_PARTY;
  }

  /**
   * Whether another request by this agent for this subject can be held
   * now. Only live requests (undecided, or approved and not yet redeemed)
   * count, overall and per agent and per subject.
   */
  hasCapacity(party: { agentDid: string; subject: string }, now = Date.now()): boolean {
    this.sweep(now);
    let live = 0;
    let byAgent = 0;
    let bySubject = 0;
    for (const request of this.requests.values()) {
      const status = this.get(request.authReqId, now)?.status;
      if (status !== 'pending' && status !== 'approved') continue;
      live += 1;
      if (request.agentDid === party.agentDid) byAgent += 1;
      if (request.subject === party.subject) bySubject += 1;
    }
    return live < this.maxRequests && byAgent < this.maxPerParty && bySubject < this.maxPerParty;
  }

  create(input: Omit<ApprovalRequest, 'authReqId' | 'createdAt' | 'expiresAt' | 'intervalSeconds' | 'lastPolledAt' | 'status' | 'approvals' | 'deniedBy' | 'finishedAt'>, opts: {
    expiresInSeconds?: number;
    intervalSeconds?: number;
    now?: number;
  } = {}): ApprovalRequest {
    const now = opts.now ?? Date.now();
    this.sweep(now);
    const request: ApprovalRequest = {
      ...input,
      authReqId: `ar_${crypto.randomBytes(24).toString('base64url')}`,
      createdAt: now,
      expiresAt: now + (opts.expiresInSeconds ?? DEFAULT_CIBA_EXPIRES_SECONDS) * 1000,
      intervalSeconds: opts.intervalSeconds ?? DEFAULT_CIBA_INTERVAL_SECONDS,
      lastPolledAt: null,
      status: 'pending',
      approvals: {},
    };
    this.requests.set(request.authReqId, request);
    return request;
  }

  get(authReqId: string, now = Date.now()): ApprovalRequest | null {
    const request = this.requests.get(authReqId);
    if (!request) return null;
    // An approval not redeemed within the request's lifetime lapses too
    // (CIBA Section 7.3 `expires_in` covers the whole request).
    if ((request.status === 'pending' || request.status === 'approved') && now >= request.expiresAt) request.status = 'expired';
    return request;
  }

  pending(now = Date.now()): ApprovalRequest[] {
    return [...this.requests.values()].filter((r) => this.get(r.authReqId, now)?.status === 'pending');
  }

  /**
   * Record one approver's decision. A denial by either role ends the
   * request; it is approved once every role its approver setting names
   * has approved.
   */
  decide(authReqId: string, role: 'subject' | 'admin', decision: 'approve' | 'deny', by: string, now = Date.now()): ApprovalRequest | null {
    const request = this.get(authReqId, now);
    if (!request || request.status !== 'pending') return null;
    if (role === 'admin' && request.approver === 'subject') return null;
    if (role === 'subject' && request.approver === 'admin') return null;
    if (decision === 'deny') {
      request.status = 'denied';
      request.deniedBy = by;
      request.finishedAt = now;
      return request;
    }
    request.approvals[role] = by;
    const needed: Array<'subject' | 'admin'> = request.approver === 'both' ? ['subject', 'admin'] : [request.approver];
    if (needed.every((r) => request.approvals[r] !== undefined)) request.status = 'approved';
    return request;
  }

  /**
   * End every undecided or unredeemed request matching the filter, as a
   * consent revocation does (Section 8.3): an approval given before the
   * security event is not redeemable after it. Returns the ids ended.
   */
  cancel(filter: { subject?: string; agentDid?: string }, by: string, now = Date.now()): string[] {
    const ended: string[] = [];
    for (const request of this.requests.values()) {
      const status = this.get(request.authReqId, now)?.status;
      if (status !== 'pending' && status !== 'approved') continue;
      if (filter.subject !== undefined && request.subject !== filter.subject) continue;
      if (filter.agentDid !== undefined && request.agentDid !== filter.agentDid) continue;
      request.status = 'denied';
      request.deniedBy = by;
      request.finishedAt = now;
      ended.push(request.authReqId);
    }
    return ended;
  }

  /**
   * One token poll by the agent holding `jkt`. Approved requests are
   * redeemed once; polling faster than the interval is slowed (CIBA
   * Section 11).
   */
  poll(authReqId: string, jkt: string, now = Date.now()): PollResult {
    const request = this.get(authReqId, now);
    if (!request || request.jkt !== jkt) return { ok: false, error: 'invalid_grant', description: 'Unknown auth_req_id, or not this agent\'s' };
    if (request.status === 'expired') return { ok: false, error: 'expired_token', description: 'The approval request expired' };
    if (request.status === 'denied') return { ok: false, error: 'access_denied', description: 'The approval request was denied' };
    if (request.status === 'redeemed') return { ok: false, error: 'invalid_grant', description: 'The approval was already redeemed' };
    if (request.status === 'pending') {
      const tooSoon = request.lastPolledAt !== null && now - request.lastPolledAt < request.intervalSeconds * 1000;
      request.lastPolledAt = now;
      if (tooSoon) {
        request.intervalSeconds += 5;
        return { ok: false, error: 'slow_down', description: `Poll at most every ${request.intervalSeconds} seconds` };
      }
      return { ok: false, error: 'authorization_pending', description: 'Waiting for approval' };
    }
    request.status = 'redeemed';
    request.finishedAt = now;
    return { ok: true, request };
  }

  /** The signature on a subject approval link for this request. */
  linkSignature(authReqId: string): string {
    return crypto.createHmac('sha256', this.linkKey).update(`cred:ciba-link:v1:${authReqId}`).digest('base64url');
  }

  verifyLink(authReqId: string, signature: unknown): boolean {
    if (typeof signature !== 'string') return false;
    const expected = Buffer.from(this.linkSignature(authReqId));
    const given = Buffer.from(signature);
    return given.length === expected.length && crypto.timingSafeEqual(given, expected);
  }

  private sweep(now: number): void {
    for (const [id, request] of this.requests) {
      const status = this.get(id, now)?.status;
      // A live request stays; a finished one is kept briefly for the
      // agent's last poll (its denial or expiry), then forgotten.
      if (status === 'pending' || status === 'approved') continue;
      if (now - Math.min(request.expiresAt, request.finishedAt ?? request.expiresAt) > FINISHED_RETENTION_MS) this.requests.delete(id);
    }
  }
}

/** How long one call to an external provider may take. */
const PROVIDER_TIMEOUT_MS = 10_000;

/** An external OpenID Provider's CIBA endpoints, used to ask the subject. */
export interface ExternalCibaProvider {
  backchannelAuthenticationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
}

/**
 * Ask the subject through an external OpenID Provider (CIBA poll mode, as
 * its client): start the request, then poll until it decides. Resolves to
 * the decision; the caller records it.
 */
export async function askExternalProvider(
  provider: ExternalCibaProvider,
  request: Pick<ApprovalRequest, 'subject' | 'bindingMessage' | 'expiresAt'>,
  opts: { fetchImpl?: typeof fetch; sleep?: (ms: number) => Promise<void> } = {},
): Promise<'approve' | 'deny' | 'expired'> {
  const doFetch = opts.fetchImpl ?? fetch;
  const sleep = opts.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const auth = `Basic ${Buffer.from(`${encodeURIComponent(provider.clientId)}:${encodeURIComponent(provider.clientSecret)}`).toString('base64')}`;
  const form = (fields: Record<string, string>) => new URLSearchParams(fields).toString();
  const started = await doFetch(provider.backchannelAuthenticationEndpoint, {
    method: 'POST',
    signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
    headers: { Authorization: auth, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      scope: 'openid',
      login_hint: request.subject,
      ...(request.bindingMessage ? { binding_message: request.bindingMessage } : {}),
    }),
  });
  if (!started.ok) return 'deny';
  const { auth_req_id: authReqId, interval } = await started.json() as { auth_req_id?: string; interval?: number };
  if (typeof authReqId !== 'string') return 'deny';
  let wait = Math.max(1, typeof interval === 'number' ? interval : DEFAULT_CIBA_INTERVAL_SECONDS);
  while (Date.now() < request.expiresAt) {
    await sleep(wait * 1000);
    const polled = await doFetch(provider.tokenEndpoint, {
      method: 'POST',
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      headers: { Authorization: auth, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({ grant_type: CIBA_GRANT_TYPE, auth_req_id: authReqId }),
    });
    if (polled.ok) return 'approve';
    const { error } = await polled.json().catch(() => ({})) as { error?: string };
    if (error === 'authorization_pending') continue;
    if (error === 'slow_down') { wait += 5; continue; }
    return error === 'expired_token' ? 'expired' : 'deny';
  }
  return 'expired';
}
