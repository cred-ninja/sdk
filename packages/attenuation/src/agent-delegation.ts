/**
 * The Delegation Chain format of draft-asor-wimse-agent-delegation-chain-02,
 * read and written unchanged.
 *
 * draft-sweeney-wimse-credential-delegation-02 "Chain-Verifiable Profile"
 * says a token meant to be verified by a party other than the issuing
 * Delegation Server uses that format as is: exactly one
 * `authorization_details` entry of type `agent_delegation` carrying `scopes`
 * and `constraints`, `sub` naming the Principal at every hop, `client_id`
 * naming the Acting Agent, `cnf`, `par_hash`, `del_depth` and `del_max_depth`,
 * and it is checked with the algorithm of Section 6 of that draft. This
 * module is that check (verifyAgentDelegationChain) and the matching
 * producer (mintAgentDelegationToken).
 *
 * Order of evaluation, denying on the first failure:
 *
 *   parse     every token: three base64url parts, strict JSON objects whose
 *             bytes are their RFC 8785 JCS form (duplicate members and
 *             integers past 2^53-1 rejected), then the parse-time claim and
 *             detail rules of Sections 3, 4, 4.2 and 4.4 (`malformed`).
 *             DT_0 is subject to them like every other token.
 *   step 1    signatures, under the verifier's own accepted-algorithm list
 *             and key resolver (`signature_invalid`).
 *   step 2    `par_hash` = base64url(SHA-256(JWS Signing Input of the
 *             parent)), compared in constant time (`par_hash_mismatch`).
 *   step 3    `del_depth` = position, leaf depth < DT_0's `del_max_depth`
 *             (`depth_invalid`); then the Principal in `sub` is identical in
 *             every token (`principal_altered`).
 *   step 4    subsumption rules 1, 2, 3 and 5 per hop (`not_narrower`).
 *   step 5    time: `nbf`, `exp`, and rule 4 (a child never expires after
 *             its parent) (`expired`).
 *   step 8    the audience half: DT_n's `aud` names this verifier
 *             (`audience_mismatch`), when the caller supplies its audience.
 *
 * Steps 6 (holder binding of the presenter) and 7 (status list) need a
 * request and a status source; they are the caller's. `cnf` is still
 * required and checked for shape. Cumulative constraints (`max_lifetime`,
 * `max_subtree`) are checked here only for narrowing; their running totals
 * are debited by the single writer that holds them (see the server's
 * cumulative ledger).
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalJson, CanonicalJsonError } from './jcs.js';
import { parseStrictJson, StrictJsonError } from './strict-json.js';
import { classifyScope, scopeCoveredBy } from './delegation-chain.js';
import {
  parseConstraints,
  constraintsSubsume,
  constraintTypeOf,
  DELEGATION_CONSTRAINT_TYPES,
  type DelegationConstraint,
} from './constraints.js';
import {
  base64urlDecode,
  checkJwsSignature,
  signCompactJws,
  type JwsKeyResolver,
  type JwsSigner,
} from './jws.js';

/** The only `authorization_details` type a token under this format carries. */
export const AGENT_DELEGATION_TYPE = 'agent_delegation';

/** Outcome names, as in Table 2 of draft-asor-wimse-agent-delegation-chain-02. */
export type AgentDelegationReason =
  | 'malformed'
  | 'duplicate_member'
  | 'non_finite'
  | 'non_canonical'
  | 'signature_invalid'
  | 'par_hash_mismatch'
  | 'depth_invalid'
  | 'principal_altered'
  | 'not_narrower'
  | 'expired'
  | 'audience_mismatch';

/**
 * A constraint of a type this implementation does not define: a closed
 * object carrying `key` and exactly one other member. It is not malformed;
 * it subsumes only a byte-identical (JCS) constraint, and any action under
 * it is denied (fail closed).
 */
export interface UnknownConstraint {
  key: string;
  type: string;
  value: unknown;
}

export interface AgentDelegationClaims {
  iss: string;
  /** The Principal. */
  sub: string;
  /** The Acting Agent. */
  client_id: string;
  aud: string | string[];
  iat: number;
  exp: number;
  nbf?: number;
  jti: string;
  cnf: Record<string, unknown>;
  del_depth: number;
  del_max_depth?: number;
  par_hash?: string;
  authorization_details: [{ type: typeof AGENT_DELEGATION_TYPE; scopes: string[]; constraints?: unknown[] }];
  [claim: string]: unknown;
}

export interface VerifiedAgentDelegationToken {
  header: Record<string, unknown>;
  claims: AgentDelegationClaims;
  scopes: string[];
  constraints: DelegationConstraint[];
  unknownConstraints: UnknownConstraint[];
  /** base64url SHA-256 over this token's JWS Signing Input: what a child's `par_hash` commits to. */
  commitment: string;
}

export type AgentDelegationChainResult =
  | {
    ok: true;
    depth: number;
    principal: string;
    /** `client_id` of DT_n. */
    actingAgent: string;
    tokens: VerifiedAgentDelegationToken[];
    leaf: VerifiedAgentDelegationToken;
  }
  | { ok: false; reason: AgentDelegationReason; hop: number; message: string };

export interface VerifyAgentDelegationChainOptions {
  /** The verifier's local list of accepted `alg` values. Required: the token never selects it. */
  acceptedAlgs: readonly string[];
  /** Resolves the verification key for each token. */
  resolveKey: JwsKeyResolver;
  /** Unix seconds. Defaults to the current time. */
  now?: number;
  /** Seconds of tolerance on `exp` and `nbf`. Defaults to 0. */
  clockSkewSeconds?: number;
  /** This verifier's own identifier. When given, DT_n's `aud` must name it (step 8). */
  audience?: string;
}

type Fail = { ok: false; reason: AgentDelegationReason; hop: number; message: string };

function fail(reason: AgentDelegationReason, hop: number, message: string): Fail {
  return { ok: false, reason, hop, message };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function isPositiveInteger(v: unknown): v is number {
  return Number.isSafeInteger(v) && (v as number) > 0;
}

/** RFC 7519 Section 4.1.3 as -02 Section 3 profiles it: a string or a non-empty array of strings. */
function isAudience(v: unknown): v is string | string[] {
  if (typeof v === 'string') return true;
  return Array.isArray(v) && v.length > 0 && v.every((a) => typeof a === 'string');
}

/** The confirmation members a `cnf` may bind the holder key with (RFC 9449, RFC 7800, RFC 8705). */
export const CNF_MEMBERS: readonly string[] = ['jkt', 'jwk', 'x5t#S256'];

function isCnf(v: unknown): v is Record<string, unknown> {
  return isObject(v) && CNF_MEMBERS.some((m) => Object.prototype.hasOwnProperty.call(v, m));
}

/** First number anywhere in `value` whose magnitude exceeds 2^53-1, or undefined. */
function unsafeNumber(value: unknown): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER ? value : undefined;
  if (Array.isArray(value)) {
    for (const v of value) { const u = unsafeNumber(v); if (u !== undefined) return u; }
  } else if (isObject(value)) {
    for (const v of Object.values(value)) { const u = unsafeNumber(v); if (u !== undefined) return u; }
  }
  return undefined;
}

const DETAIL_MEMBERS = new Set(['type', 'scopes', 'constraints']);
const KNOWN_TYPES = new Set<string>(DELEGATION_CONSTRAINT_TYPES);

export type ParsedAgentDelegationDetail =
  | { ok: true; scopes: string[]; constraints: DelegationConstraint[]; unknownConstraints: UnknownConstraint[] }
  | { ok: false; message: string };

/**
 * Sections 4, 4.1, 4.2 and 4.4 for one `authorization_details` claim:
 * exactly one detail, of type `agent_delegation`, closed to `type`,
 * `scopes` and `constraints`; every scope a literal, wildcard or opaque
 * scope; every constraint a closed object with one typed value, unique per
 * (key, type), a label `rank` carrying an `order` it is a member of.
 */
export function parseAgentDelegationDetail(details: unknown): ParsedAgentDelegationDetail {
  if (!Array.isArray(details) || details.length !== 1) {
    const n = Array.isArray(details) ? details.length : 'no';
    return { ok: false, message: `authorization_details must carry exactly one detail, of type '${AGENT_DELEGATION_TYPE}'; found ${n}` };
  }
  const d = details[0];
  if (!isObject(d) || d.type !== AGENT_DELEGATION_TYPE) {
    const got = isObject(d) ? JSON.stringify(d.type) : typeof d;
    return { ok: false, message: `authorization detail type ${got} is not '${AGENT_DELEGATION_TYPE}'; an unimplemented detail type is a rejection` };
  }
  const extra = Object.keys(d).filter((k) => !DETAIL_MEMBERS.has(k)).sort();
  if (extra.length > 0) {
    return { ok: false, message: `the ${AGENT_DELEGATION_TYPE} detail carries members this verifier cannot evaluate: ${extra.join(', ')}` };
  }
  const scopes = d.scopes;
  if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== 'string')) {
    return { ok: false, message: 'scopes must be an array of strings' };
  }
  for (const s of scopes as string[]) {
    if (classifyScope(s) === 'malformed') {
      return { ok: false, message: `invalid scope ${JSON.stringify(s)}: not a literal, wildcard or opaque scope` };
    }
  }
  const raw = d.constraints ?? [];
  if (!Array.isArray(raw)) return { ok: false, message: 'constraints must be an array' };

  const known: unknown[] = [];
  const unknownConstraints: UnknownConstraint[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < raw.length; i++) {
    const c: unknown = raw[i];
    if (!isObject(c)) return { ok: false, message: `constraints[${i}] is not an object` };
    const members = Object.keys(c).filter((k) => k !== 'key');
    const typed = members.filter((m) => KNOWN_TYPES.has(m));
    if (typed.length === 0 && members.length === 1) {
      const key = c.key;
      if (typeof key !== 'string' || key.trim() === '') return { ok: false, message: `constraints[${i}] has no key` };
      const type = members[0]!;
      const id = `${type}\u0000${key}`;
      if (seen.has(id)) return { ok: false, message: `constraints has duplicate (key, type) ('${key}', ${type})` };
      seen.add(id);
      unknownConstraints.push({ key, type, value: c[type] });
      continue;
    }
    known.push(c);
  }
  const parsed = parseConstraints(known);
  if (!parsed.ok) return { ok: false, message: parsed.message };
  for (const c of parsed.constraints) {
    const id = `${constraintTypeOf(c)}\u0000${c.key}`;
    if (seen.has(id)) return { ok: false, message: `constraints has duplicate (key, type) ('${c.key}', ${constraintTypeOf(c)})` };
    seen.add(id);
    if ('rank' in c && typeof c.rank === 'string' && !c.order) {
      return { ok: false, message: `constraint '${c.key}' rank label '${c.rank}' carries no order` };
    }
  }
  return { ok: true, scopes: scopes as string[], constraints: parsed.constraints, unknownConstraints };
}

/** Section 3 rules for one token's claims. Returns a message on the first violation. */
function checkClaims(p: Record<string, unknown>): string | null {
  for (const claim of ['iss', 'jti'] as const) {
    if (typeof p[claim] !== 'string' || p[claim] === '') return `${claim} must be a non-empty string`;
  }
  if (typeof p.sub !== 'string' || p.sub === '') return 'sub must be a non-empty string naming the Principal';
  if (typeof p.client_id !== 'string' || p.client_id === '') return 'missing required fields: client_id must name the Acting Agent';
  if (!isAudience(p.aud)) return 'aud must be a string or a non-empty array of strings';
  if (!isNumber(p.iat) || !isNumber(p.exp)) return 'iat and exp must be numbers';
  if (p.nbf !== undefined && !isNumber(p.nbf)) return 'nbf must be a number';
  if (!isCnf(p.cnf)) return `cnf must be an object carrying one of ${CNF_MEMBERS.join(', ')}`;
  if (!Number.isSafeInteger(p.del_depth) || (p.del_depth as number) < 0) return 'del_depth must be a non-negative integer';
  if (p.del_max_depth !== undefined && !isPositiveInteger(p.del_max_depth)) return 'del_max_depth must be a positive integer';
  if (p.par_hash !== undefined && typeof p.par_hash !== 'string') return 'par_hash must be a string';
  const unsafe = unsafeNumber(p);
  if (unsafe !== undefined) return `integer ${unsafe} exceeds 2^53-1`;
  return null;
}

interface DecodedToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Buffer;
  signature: Buffer;
}

function decodePart(text: string, which: string): { ok: true; value: Record<string, unknown>; bytes: Buffer } | { ok: false; reason: AgentDelegationReason; message: string } {
  const bytes = base64urlDecode(text);
  if (!bytes) return { ok: false, reason: 'malformed', message: `${which} is not base64url` };
  let value: unknown;
  try {
    value = parseStrictJson(bytes.toString('utf8'));
  } catch (err) {
    if (err instanceof StrictJsonError) {
      if (err.code === 'duplicate_member') return { ok: false, reason: 'duplicate_member', message: `${which}: ${err.message}` };
      if (err.code === 'unsafe_integer') return { ok: false, reason: 'malformed', message: `${which}: unsafe integer: ${err.message}` };
      return { ok: false, reason: 'malformed', message: `${which}: ${err.message}` };
    }
    return { ok: false, reason: 'malformed', message: `${which} is not JSON` };
  }
  if (!isObject(value)) return { ok: false, reason: 'malformed', message: `${which} is not a JSON object` };
  let canonical: string;
  try {
    canonical = canonicalJson(value);
  } catch (err) {
    const reason = err instanceof CanonicalJsonError && err.code === 'non_finite' ? 'non_finite' : 'malformed';
    return { ok: false, reason, message: `${which}: ${(err as Error).message}` };
  }
  if (!Buffer.from(canonical, 'utf8').equals(bytes)) {
    return { ok: false, reason: 'non_canonical', message: `${which} bytes are not their RFC 8785 JCS form` };
  }
  return { ok: true, value, bytes };
}

function decodeToken(token: unknown, i: number): { ok: true; token: DecodedToken } | Fail {
  if (typeof token !== 'string') return fail('malformed', i, `token[${i}] is not a string`);
  const parts = token.split('.');
  if (parts.length !== 3) return fail('malformed', i, `token[${i}] has ${parts.length} parts, expected 3`);
  const header = decodePart(parts[0]!, `token[${i}] header`);
  if (!header.ok) return fail(header.reason, i, header.message);
  const payload = decodePart(parts[1]!, `token[${i}] payload`);
  if (!payload.ok) return fail(payload.reason, i, payload.message);
  const signature = base64urlDecode(parts[2]!);
  if (!signature) return fail('malformed', i, `token[${i}] signature is not base64url`);
  return {
    ok: true,
    token: { header: header.value, payload: payload.value, signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), signature },
  };
}

/** base64url(SHA-256(JWS Signing Input)): the value a child's `par_hash` carries. */
export function agentDelegationCommitment(token: string): string {
  const [h, p] = token.split('.');
  return createHash('sha256').update(`${h}.${p}`, 'ascii').digest('base64url');
}

function unknownSubsumes(parent: readonly UnknownConstraint[], child: readonly UnknownConstraint[]): string | null {
  for (const p of parent) {
    const c = child.find((x) => x.key === p.key && x.type === p.type);
    if (!c) return `child omits parent constraint '${p.key}' (${p.type})`;
    if (canonicalJson(c.value) !== canonicalJson(p.value)) {
      return `constraint '${p.key}' has type ${p.type}, which this verifier does not implement; it subsumes only an identical constraint`;
    }
  }
  return null;
}

/**
 * Section 6 of draft-asor-wimse-agent-delegation-chain-02 over a root-first
 * chain `[DT_0, ..., DT_n]`, steps 1 to 5 and the audience half of step 8.
 */
export function verifyAgentDelegationChain(
  tokens: readonly unknown[],
  options: VerifyAgentDelegationChainOptions,
): AgentDelegationChainResult {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkewSeconds ?? 0;
  if (!Array.isArray(tokens) || tokens.length === 0) return fail('malformed', 0, 'empty token chain');
  if (!Array.isArray(options.acceptedAlgs)) throw new TypeError('acceptedAlgs must be an array of algorithm names');

  // Parse and the parse-time rules, every token, before any step.
  const decoded: DecodedToken[] = [];
  const verified: VerifiedAgentDelegationToken[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const d = decodeToken(tokens[i], i);
    if (!d.ok) return d;
    decoded.push(d.token);
  }
  for (let i = 0; i < decoded.length; i++) {
    const { header, payload, signingInput } = decoded[i]!;
    const claimError = checkClaims(payload);
    if (claimError) return fail('malformed', i, `token[${i}] ${claimError}`);
    const detail = parseAgentDelegationDetail(payload.authorization_details);
    if (!detail.ok) return fail('malformed', i, `token[${i}] ${detail.message}`);
    verified.push({
      header,
      claims: payload as AgentDelegationClaims,
      scopes: detail.scopes,
      constraints: detail.constraints,
      unknownConstraints: detail.unknownConstraints,
      commitment: createHash('sha256').update(signingInput).digest('base64url'),
    });
  }

  // Step 1: signatures.
  for (let i = 0; i < decoded.length; i++) {
    const { header, signingInput, signature } = decoded[i]!;
    const failure = checkJwsSignature(header, signingInput, signature, options.acceptedAlgs, options.resolveKey, i);
    if (failure === 'alg_not_accepted') {
      return fail('signature_invalid', i, `token[${i}] signature: alg ${JSON.stringify(header.alg)} is not on the accepted list`);
    }
    if (failure) return fail('signature_invalid', i, `token[${i}] signature did not verify (${failure})`);
  }

  // Step 2: parent commitment.
  if (verified[0]!.claims.par_hash !== undefined) return fail('malformed', 0, 'DT_0 must not carry par_hash');
  for (let i = 1; i < verified.length; i++) {
    const got = base64urlDecode(verified[i]!.claims.par_hash ?? '');
    const want = Buffer.from(verified[i - 1]!.commitment, 'base64url');
    if (!got || got.length !== want.length || !timingSafeEqual(got, want)) {
      return fail('par_hash_mismatch', i, `token[${i}] par_hash does not commit to the parent token presented`);
    }
  }

  // Step 3: depth, then principal invariance.
  const root = verified[0]!.claims;
  if (root.del_depth !== 0) return fail('depth_invalid', 0, 'DT_0 del_depth must be 0');
  if (!isPositiveInteger(root.del_max_depth)) return fail('depth_invalid', 0, 'DT_0 del_max_depth must be a positive integer');
  const n = verified.length - 1;
  if (n >= root.del_max_depth) return fail('depth_invalid', n, `leaf del_depth ${n} is not below del_max_depth ${root.del_max_depth}`);
  for (let i = 0; i < verified.length; i++) {
    if (verified[i]!.claims.del_depth !== i) return fail('depth_invalid', i, `token[${i}] del_depth is ${verified[i]!.claims.del_depth}, expected ${i}`);
  }
  for (let i = 1; i < verified.length; i++) {
    if (verified[i]!.claims.sub !== root.sub) {
      return fail('principal_altered', i, `token[${i}] sub (user) differs from DT_0's; the Principal must be identical in every token`);
    }
  }

  // Step 4: subsumption, rules 1, 2, 3 and 5.
  let depthBound = root.del_max_depth;
  for (let i = 1; i < verified.length; i++) {
    const parent = verified[i - 1]!;
    const child = verified[i]!;
    const widened = child.scopes.filter((s) => !scopeCoveredBy(parent.scopes, s));
    if (widened.length > 0) return fail('not_narrower', i, `token[${i}] holds scopes its parent does not cover: ${widened.join(', ')}`);
    const check = constraintsSubsume(parent.constraints, child.constraints);
    if (!check.ok) return fail('not_narrower', i, `token[${i}] constraint '${check.key}': ${check.message}`);
    const unknown = unknownSubsumes(parent.unknownConstraints, child.unknownConstraints);
    if (unknown) return fail('not_narrower', i, `token[${i}] ${unknown}`);
    const own = child.claims.del_max_depth;
    if (own !== undefined) {
      if (own > depthBound) return fail('not_narrower', i, `token[${i}] del_max_depth ${own} exceeds its parent's max depth ${depthBound}`);
      depthBound = own;
    }
  }

  // Step 5: time, including rule 4.
  for (let i = 0; i < verified.length; i++) {
    const c = verified[i]!.claims;
    if (c.nbf !== undefined && now + skew < c.nbf) return fail('expired', i, `token[${i}] is not valid before ${c.nbf}`);
    if (now > c.exp + skew) return fail('expired', i, `token[${i}] expired at ${c.exp}`);
    if (i > 0 && c.exp > verified[i - 1]!.claims.exp) {
      return fail('expired', i, `token[${i}] expires at ${c.exp}, after its parent at ${verified[i - 1]!.claims.exp}`);
    }
  }

  // Step 8, the audience half.
  const leaf = verified[n]!;
  if (options.audience !== undefined) {
    const aud = leaf.claims.aud;
    const names = aud === options.audience || (Array.isArray(aud) && aud.includes(options.audience));
    if (!names) return fail('audience_mismatch', n, `DT_n aud does not name this verifier (${options.audience})`);
  }

  return { ok: true, depth: n, principal: root.sub, actingAgent: leaf.claims.client_id, tokens: verified, leaf };
}

export interface MintAgentDelegationTokenInput {
  signer: JwsSigner;
  iss: string;
  /** The Principal. Must equal the parent's on a child. */
  sub: string;
  /** The Acting Agent this token is issued to. */
  clientId: string;
  aud: string | string[];
  /** Holder binding, e.g. `{ jkt: <RFC 7638 thumbprint of the agent's key> }`. */
  cnf: Record<string, unknown>;
  jti: string;
  iat: number;
  exp: number;
  scopes: string[];
  /** Wire constraint objects in the -02 shape. Omitted on a child: the parent's are inherited unchanged. */
  constraints?: unknown[];
  /** Root only: DT_0's del_max_depth. On a child, an optional tighter bound. */
  delMaxDepth?: number;
  /** The parent token, already verified by the caller. Absent for DT_0. */
  parent?: string;
}

export class AgentDelegationMintError extends Error {
  constructor(message: string, public readonly reason: 'malformed' | 'not_narrower' | 'expired' | 'principal_altered') {
    super(message);
    this.name = 'AgentDelegationMintError';
  }
}

/**
 * Mint one token in the -02 Delegation Chain format. On a child, the caller
 * hands in the verified parent token; the producer refuses to mint a token
 * that the verifier would reject against it (wider scopes or constraints, a
 * later expiry, a different Principal, a raised del_max_depth).
 */
export function mintAgentDelegationToken(input: MintAgentDelegationTokenInput): string {
  let parent: VerifiedAgentDelegationToken | undefined;
  if (input.parent !== undefined) {
    const d = decodeToken(input.parent, 0);
    if (!d.ok) throw new AgentDelegationMintError(`parent: ${d.message}`, 'malformed');
    const detail = parseAgentDelegationDetail(d.token.payload.authorization_details);
    if (!detail.ok) throw new AgentDelegationMintError(`parent: ${detail.message}`, 'malformed');
    parent = {
      header: d.token.header,
      claims: d.token.payload as AgentDelegationClaims,
      ...detail,
      commitment: agentDelegationCommitment(input.parent),
    };
  }
  const constraints = input.constraints ?? (parent?.claims.authorization_details[0].constraints ?? []);
  const claims: Record<string, unknown> = {
    iss: input.iss,
    sub: input.sub,
    client_id: input.clientId,
    aud: input.aud,
    cnf: input.cnf,
    jti: input.jti,
    iat: input.iat,
    exp: input.exp,
    del_depth: parent ? (parent.claims.del_depth + 1) : 0,
    authorization_details: [{ type: AGENT_DELEGATION_TYPE, scopes: input.scopes, constraints }],
    ...(input.delMaxDepth !== undefined ? { del_max_depth: input.delMaxDepth } : {}),
    ...(parent ? { par_hash: parent.commitment } : {}),
  };
  const claimError = checkClaims(claims);
  if (claimError) throw new AgentDelegationMintError(claimError, 'malformed');
  if (!parent && input.delMaxDepth === undefined) throw new AgentDelegationMintError('DT_0 needs del_max_depth', 'malformed');
  const detail = parseAgentDelegationDetail(claims.authorization_details);
  if (!detail.ok) throw new AgentDelegationMintError(detail.message, 'malformed');
  if (parent) {
    if (parent.claims.sub !== input.sub) throw new AgentDelegationMintError('a child must carry its parent\'s Principal', 'principal_altered');
    const widened = detail.scopes.filter((s) => !scopeCoveredBy(parent!.scopes, s));
    if (widened.length > 0) throw new AgentDelegationMintError(`scopes not covered by the parent: ${widened.join(', ')}`, 'not_narrower');
    const check = constraintsSubsume(parent.constraints, detail.constraints);
    if (!check.ok) throw new AgentDelegationMintError(check.message, 'not_narrower');
    const unknown = unknownSubsumes(parent.unknownConstraints, detail.unknownConstraints);
    if (unknown) throw new AgentDelegationMintError(unknown, 'not_narrower');
    if (input.exp > parent.claims.exp) throw new AgentDelegationMintError('a child cannot expire after its parent', 'expired');
    const bound = parent.claims.del_max_depth;
    if (input.delMaxDepth !== undefined && bound !== undefined && input.delMaxDepth > bound) {
      throw new AgentDelegationMintError('a child cannot raise del_max_depth', 'not_narrower');
    }
  }
  return signCompactJws(claims, input.signer, { typ: 'at+jwt', c14n: 'JCS' });
}


