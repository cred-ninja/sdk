/**
 * @credninja/server — Self-hosted credential delegation server
 *
 * A complete, runnable HTTP server that stores OAuth tokens in an encrypted
 * vault and serves delegated access tokens or brokered handles to authenticated agents.
 *
 * Designed to run on a separate host from the AI agent for true credential
 * isolation. In production, place behind a TLS reverse proxy (Caddy/nginx).
 *
 * Endpoints:
 *   GET  /.well-known/http-message-signatures-directory — Web Bot Auth key directory
 *   GET  /health                          — liveness check
 *   GET  /admin/login                     — admin login form
 *   POST /admin/login                     — admin session cookie
 *   GET  /providers                       — list configured providers (admin auth)
 *   GET  /connect/:provider               — start OAuth flow (browser, admin auth)
 *   GET  /connect/:provider/callback      — OAuth callback (browser)
 *   GET  /api/v1/providers                — list configured provider slugs (agent, Bearer auth)
 *   GET  /api/v1/connections              — list connections (agent, Bearer auth)
 *   POST /api/v1/use                      — brokered upstream API call (agent, Bearer auth)
 *   GET  /api/token/:provider             — compatibility token access route (agent, Bearer auth)
 *   POST /api/v1/delegate                 — delegate token or handle (agent, Bearer auth)
 *   POST /api/v1/subdelegate              — sub-delegate from a parent receipt; always brokered handle (agent, Bearer auth)
 *   DELETE /api/v1/connections/:provider  — revoke stored token (agent, Bearer auth)
 *   DELETE /api/token/:provider           — revoke stored token (agent, Bearer auth)
 */

import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import { CredVault, validateSubDelegation, DelegationChainError, scopeCoveredBy, parseConstraints, constraintsSubsume, unresolvableRankLabels, cumulativeConstraints, producerConstraintViolations, CUMULATIVE_CONSTRAINT_UNENFORCEABLE, parseStrictJson, StrictJsonError, isReservedLinkVaultUserId, ReservedVaultUserIdError, DelegationRevokedError } from '@credninja/vault';
import type { AgentRecord, Permission, UpdatePermissionInput, AuditEvent, AuditActor, DelegationConstraint, DelegationRevocationResult, RecordDelegationInput, CumulativeLedger, DelegationGrant, VaultEntry } from '@credninja/vault';
import { SqliteCumulativeLedger } from '@credninja/vault';
import {
  receiptActorClaims,
  readReceiptActor,
  didKeyConfirmation,
  signCompactJws,
  mintAgentDelegationToken,
  verifyAgentDelegationChain,
  AgentDelegationMintError,
  publicKeyFromDidKey,
  unknownConstraints,
  UNKNOWN_CONSTRAINT,
  exerciseConstraintViolation,
  mintDelegationToken,
  verifyDelegationToken,
  delegationTokenAth,
  receiptContentId,
  CRED_DELEGATION_TYPE,
} from '@credninja/attenuation';
import type { CredDelegationDetail } from '@credninja/attenuation';
import { createReceiptKeys, checkReceiptSignature, type ReceiptKeys } from './receipt-signing.js';
import { createDelegationGrantStore, createJtiReplayCache, verifyActorToken, DELEGATION_GRANT_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from './delegation-grants.js';
import { AgentVault, agentIdentityToDirectoryJwks, publicKeyToJwkWithKid } from '@credninja/tofu';
import { OAuthClient, createAdapter, toVaultRefreshAdapter } from '@credninja/oauth';
import type { BuiltinAdapterSlug } from '@credninja/oauth';
import type { ServerConfig, ProviderConfig, RequestAgentPrincipal } from './config.js';
import { assertLinkConfig, resolveLinkStorePath } from './config.js';
import { createLinkService } from './link/index.js';
import { brokerScopeEquivalent, isAllowedGoogleScopeEndpoint } from './google-scopes.js';
import type { LinkHandleBinding, LinkService } from './link/index.js';
import { contentTypeMismatch, createExpressMiddleware, evaluateOperation, isBrokerOnlyScope, methodOverrideChannel, providerScopesFor, withDerivedScopes, withDerivedScopesUnder, withStoredDerivedScopes, withoutRedundantDerivedScopes, type GuardContext, type GuardDecision } from '@credninja/guard';
import { computeTofuAuthorization, resolveTofuPrincipal, toTofuPrincipalId } from './tofu-bridge.js';
import { createWebBotAuthNonceStore } from './nonce-store.js';
import {
  CRED_PROTOCOL_SUPPORTED_VERSIONS,
  CRED_PROTOCOL_VERSION,
  CRED_PROTOCOL_VERSION_HEADER,
  CRED_PROTOCOL_VERSION_MINIMUM,
  CRED_PROTOCOL_VERSION_UNSUPPORTED_ERROR,
  hasDerivedReadScope,
  isCredProtocolVersionSupported,
  isConnectionId,
  isScopeSubset,
  linkAudienceFor,
  widestDerivedReadSources,
} from '@credninja/protocol';
import { verifyReceiptChain } from './receipt-chain.js';
import { auditOriginAndRoute, createRefusalAggregator } from './audit-route.js';
import { capabilitiesAllow, capabilitiesSubsumed, matchedPageParam, validateCapabilities } from './capabilities.js';
import { ITEM_KEYS, REQUEST_METERS, RESPONSE_METERS, countItems, destinationWithinPrefix, meterSide } from './metering.js';
import { ApprovalCapacityError, ApprovalStore, CIBA_GRANT_TYPE, askExternalProvider, type ApprovalRequest } from './ciba.js';
import { DPOP_ACCEPTED_ALGS, dpopBindingFor, dpopRequestHash, readDpopHeader, verifyDpopProof } from './dpop.js';
import { IdentityRefusal, mappedAgentDid, type ExternalIdentityKind, type IdentityRequest, type VerifiedExternalIdentity } from './identity/types.js';
import { WIMSE_PROBLEM_TYPES, WIMSE_SIGNATURE_TAG } from './identity/http-signature.js';
import { parseDictionary } from './identity/structured-fields.js';

// ── Types ────────────────────────────────────────────────────────────────────

interface PendingOAuth {
  provider: string;
  userId: string;
  scopes: string[];
  state: string;
  codeVerifier?: string;
  createdAt: number;
}

/**
 * A connect request minted by an authenticated call (an agent's
 * consent_url, or the admin page's POST /connect/:provider/start). The
 * browser only carries its random id, so GET /connect/:provider never takes
 * the user id or scopes from the query string under the admin cookie.
 */
interface PendingConnectRequest {
  provider: string;
  userId: string;
  scopes: string[];
  appClientId?: string;
  expiresAt: number;
}

interface BrokeredDelegation {
  accessToken: string;
  service: string;
  userId: string;
  scopes: string[];
  /**
   * The stored scopes of the connection row whose token this handle holds, as
   * that row read when the token was cached: the authority of the credential
   * the handle forwards, which a later replacement of the row cannot change.
   *
   * A live handle forwards the token it was issued, never a fresh read, so its
   * authorization decision is taken over these scopes and over the row only as
   * far as the row still covers them. A Link handle holds no provider token
   * (its token is loaded and checked at each exercise) and records none.
   *
   * Absent on a handle cached before this was recorded: what it forwards cannot
   * be established, so /api/v1/use refuses rather than assuming the current row.
   */
  credentialScopes?: string[];
  expiresAt: number;
  createdAt: number;
  /**
   * Constraint ceilings of the delegation this handle exercises (the same
   * list its receipt carries). /api/v1/use denies every action under a
   * cumulative constraint (max_lifetime, max_subtree), because no component
   * here holds the running total (draft-asor-wimse-agent-delegation-chain-02
   * section 6, step 8). Absent on handles minted without constraints.
   */
  constraints?: DelegationConstraint[];
  /**
   * Set for handles minted for a Cred Link connection. Such handles hold no
   * provider token (accessToken is ''): /api/v1/use re-runs the Link check
   * and loads the current token at call time.
   */
  link?: LinkHandleBinding;
  /** DID the handle was issued to, when the request named one. */
  agentDid?: string;
  /** Salesforce: the origin of the instance stored for this connection, set at each exercise. */
  instanceOrigin?: string;
  /** The Delegation Token's capabilities: exercise is held within them. */
  capabilities?: CredDelegationDetail[];
  /**
   * RFC 7638 thumbprint of `agentDid`'s key when it is a did:key. Every
   * /api/v1/use of the handle must carry a DPoP proof (RFC 9449) by that
   * key, so the handle id alone is not a bearer credential.
   */
  dpopJkt?: string;
  /**
   * Set by a cascading revocation that reached this handle. /api/v1/use
   * refuses the handle from then on (and re-checks right before the
   * upstream call, so a request already in flight is refused too).
   */
  revoked?: { at: number; revokedAncestorId: string };
}


interface WebBotAuthDirectoryResponse {
  keys: Array<{
    kty: 'OKP';
    crv: 'Ed25519';
    x: string;
    kid: string;
    alg: 'EdDSA';
    use: 'sig';
  }>;
}

type WebBotAuthDirectoryKey = WebBotAuthDirectoryResponse['keys'][number];

interface DirectorySignatureHeaders {
  'Signature-Input': string;
  'Signature': string;
}

interface WebBotAuthKeyResponse {
  agent_id: string;
  fingerprint: string;
  key_id: string;
  previous_fingerprint?: string | null;
  previous_key_id?: string | null;
  rotation_grace_expires_at?: string | null;
  status: string;
  initial_scopes: string[];
  metadata: Record<string, unknown>;
  signature_agent: string;
  created_at: string;
  updated_at: string;
  claimed_at: string | null;
  revoked_at: string | null;
}

interface ParsedSignatureInput {
  label: string;
  rawParams: string;
  components: string[];
  params: Record<string, string>;
}

interface VerifiedWebBotAuthIdentity {
  keyId: string;
  signatureAgent: string;
  agentId?: string;
  fingerprint?: string;
}

const ADMIN_SESSION_COOKIE = 'cred_admin_session';
const ADMIN_SESSION_TTL_SECONDS = 60 * 60;
const PROVIDER_REVOKE_TIMEOUT_MS = 5_000;
// draft-sweeney-wimse-credential-delegation Section 10.6: 15 minutes by
// default, never more than 1 hour.
const DEFAULT_RECEIPT_TTL_SECONDS = 900;
const MAX_RECEIPT_TTL_SECONDS = 3600;
// The fixed issuer receipts carried before they named the Delegation Server.
// Never minted here. Accepted only on a receipt issued before this process
// started, so the allowance ends one receipt lifetime (at most an hour)
// after an upgrade. Remove once no deployment can hold such a receipt.
const LEGACY_RECEIPT_ISSUER = 'did:key:local-cred';
const DEFAULT_DELEGATION_GRANT_TTL_SECONDS = 60;
const RECEIPT_CLOCK_SKEW_SECONDS = 60;
const MAX_BROKER_RESPONSE_BYTES = 32_768;
const ED25519_PUBLIC_KEY_BYTES = 32;

const SERVICE_ALLOWLIST: Record<string, string[]> = {
  google: [
    'https://www.googleapis.com/',
    'https://gmail.googleapis.com/',
    'https://calendar.googleapis.com/',
    'https://drive.googleapis.com/',
    'https://sheets.googleapis.com/',
    'https://docs.googleapis.com/',
    'https://admin.googleapis.com/',
    'https://people.googleapis.com/',
    'https://openidconnect.googleapis.com/',
  ],
  github: ['https://api.github.com/'],
  slack: ['https://slack.com/api/'],
  notion: ['https://api.notion.com/'],
  salesforce: [],
  // Linear: only the GraphQL endpoint (an exact match, see
  // SERVICE_EXACT_ENDPOINTS); never /oauth/revoke.
  linear: [],
  // HubSpot: data API prefixes only, never /oauth/.
  hubspot: [
    'https://api.hubapi.com/crm/',
    'https://api.hubapi.com/cms/',
    'https://api.hubapi.com/content/',
    'https://api.hubapi.com/automation/',
  ],
};

/** Exact endpoint URLs (no trailing path) a service may call, besides its prefixes. */
const SERVICE_EXACT_ENDPOINTS: Record<string, string[]> = {
  linear: ['https://api.linear.app/graphql'],
};

/**
 * Endpoints never brokered even though their prefix is allowed: they
 * revoke or uninstall the shared authorization, which would break every
 * connection of that account (compared lowercase, path prefix).
 */
const BROKER_BLOCKED_ENDPOINTS: Record<string, string[]> = {
  slack: ['https://slack.com/api/auth.revoke', 'https://slack.com/api/apps.uninstall'],
};

/** The fixed origins the broker can call. Salesforce instance hosts follow a pattern instead. */
const KNOWN_PROVIDER_ORIGINS: ReadonlySet<string> = new Set(
  [...Object.values(SERVICE_ALLOWLIST), ...Object.values(SERVICE_EXACT_ENDPOINTS)].flat().map((url) => new URL(url).origin),
);

/**
 * Resource id of a refusal that names no authorized user. It holds no '/', so
 * the agent-facing feed, which splits ids into service and user, can never read
 * a user out of it. Only the admin log shows these.
 */
const GUARD_DENIAL_RESOURCE_PREFIX = 'guard-denial:';

/** The service an audit resource id is about. */
function auditEventService(resourceId: string): string {
  return resourceId.startsWith(GUARD_DENIAL_RESOURCE_PREFIX)
    ? resourceId.slice(GUARD_DENIAL_RESOURCE_PREFIX.length)
    : resourceId.split('/')[0]!;
}

/** The fields of an audit event that say a Web Bot Auth signature identified the caller. */
const WEB_BOT_AUTH_SIGNS: readonly string[] = ['webBotAuthKeyId', 'signatureAgent'];
const WEB_BOT_AUTH_FIELDS: readonly string[] = [...WEB_BOT_AUTH_SIGNS, 'identitySource'];

const BLOCKED_BROKER_EXTRA_HEADERS = new Set([
  'authorization',
  'connection',
  'content-length',
  'cookie',
  'forwarded',
  'host',
  'proxy-authenticate',
  'proxy-authorization',
  'set-cookie',
  'signature',
  'signature-agent',
  'signature-input',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  // Method overrides: an upstream that honours one (Google APIs do) would
  // run a different method than the one the call was authorized for.
  'x-http-method-override',
  'x-http-method',
  'x-method-override',
  'x-original-url',
  'x-rewrite-url',
  'x-original-method',
]);

function isForwardableBrokerHeader(key: string, value: unknown): value is string {
  if (typeof value !== 'string') return false;
  return !BLOCKED_BROKER_EXTRA_HEADERS.has(key.trim().toLowerCase());
}

/**
 * Whether a service has a brokered-use path (`POST /api/v1/use`) at all.
 * Sub-delegated tokens are always issued as brokered handles — never raw
 * provider tokens — so a service outside this allowlist cannot be the
 * target of a sub-delegation, since the resulting handle could never be
 * redeemed.
 */
function isBrokerableService(service: string): boolean {
  return Object.prototype.hasOwnProperty.call(SERVICE_ALLOWLIST, service);
}

function requestedProtocolVersion(req: Request): string | undefined {
  const advertised = req.get(CRED_PROTOCOL_VERSION_HEADER);
  return advertised === undefined ? undefined : advertised.trim();
}

function sendProtocolVersionUnsupported(res: Response, requestedVersion: string): void {
  res.status(426).json({
    error: CRED_PROTOCOL_VERSION_UNSUPPORTED_ERROR,
    message: `Cred Protocol version ${requestedVersion || '<empty>'} is not supported`,
    requested_version: requestedVersion,
    supported_versions: [...CRED_PROTOCOL_SUPPORTED_VERSIONS],
    minimum_version: CRED_PROTOCOL_VERSION_MINIMUM,
    current_version: CRED_PROTOCOL_VERSION,
  });
}

// ── Server factory ───────────────────────────────────────────────────────────

export function createServer(config: ServerConfig) {
  const startedAtSeconds = Math.floor(Date.now() / 1000);
  if (!config.agentToken && !config.agentRequestVerifier) {
    throw new Error('Either agentToken or agentRequestVerifier is required');
  }
  assertLinkConfig(config);

  const app = express();
  const invalidConstraintJson = new WeakSet<object>();
  // cred_req of each /api/v1/use request, computed from the bytes the client
  // sent, before any middleware adds members to req.body (Web Bot Auth adds
  // web_bot_auth_key_id and signature_agent). Null: no canonical JSON form.
  const useRequestHashes = new WeakMap<object, string | null>();
  // The exact bytes of a request that carries a Workload Identity Token, for
  // Content-Digest (draft-ietf-wimse-http-signature-08 §3). Only kept when
  // external identity is configured.
  const workloadRequestBodies = new WeakMap<object, Buffer>();
  const capturesWorkloadBody = (req: { headers: Record<string, unknown> }) =>
    Boolean(config.externalIdentity) && req.headers['workload-identity-token'] !== undefined;
  app.use(express.json({
    verify(req, _res, buffer) {
      if (capturesWorkloadBody(req)) workloadRequestBodies.set(req, Buffer.from(buffer));
      if (req.method === 'POST' && /^\/api\/v1\/use\/?(?:\?|$)/i.test(req.url ?? '')) {
        let hash: string | null = null;
        try {
          hash = dpopRequestHash(JSON.parse(buffer.toString('utf8')));
        } catch {
          hash = null;
        }
        useRequestHashes.set(req, hash);
        return;
      }
      if (req.method !== 'POST' || !/^\/api\/v1\/(?:delegate|subdelegate)\/?(?:\?|$)/i.test(req.url ?? '')) return;
      // JSON.parse is only for selecting constraint-bearing requests. Validate
      // the original bytes before duplicate members or unsafe numbers disappear.
      // Retain only a boolean, never the raw payload or parser error text.
      try {
        const text = buffer.toString('utf8');
        const body: unknown = JSON.parse(text);
        if (body && typeof body === 'object' && Object.prototype.hasOwnProperty.call(body, 'constraints')) {
          parseStrictJson(text);
        }
      } catch {
        invalidConstraintJson.add(req);
      }
    },
  }));
  // Any other content type on a WIT-bearing request: keep its bytes too, so
  // its Content-Digest can be checked. Routes read JSON only, so nothing else
  // consumes these bodies.
  app.use(express.raw({
    type: (req) => capturesWorkloadBody(req as any) && !workloadRequestBodies.has(req),
    verify(req, _res, buffer) {
      workloadRequestBodies.set(req, Buffer.from(buffer));
    },
  }));
  app.use(express.urlencoded({ extended: false }));

  // Advertise the selected wire-protocol version on every response. During the
  // 0.1.0 compatibility window, missing version headers are accepted because
  // there is no earlier wire version to downgrade to. Explicit unsupported
  // versions fail before auth, guard policy, or credential handling.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader(CRED_PROTOCOL_VERSION_HEADER, CRED_PROTOCOL_VERSION);
    const version = requestedProtocolVersion(req);
    if (version !== undefined && !isCredProtocolVersionSupported(version)) {
      sendProtocolVersionUnsupported(res, version);
      return;
    }
    next();
  });

  // ── State ──────────────────────────────────────────────────────────────────

  const vault = new CredVault({
    passphrase: config.vaultPassphrase,
    storage: config.vaultStorage,
    path: config.vaultPath,
  });
  const tofu = new AgentVault({
    storage: config.tofuStorage,
    path: config.tofuPath,
  });

  // In-memory map of provider slug → ProviderConfig
  const providerMap = new Map<string, ProviderConfig>();
  for (const p of config.providers) {
    providerMap.set(p.slug, p);
  }

  // Pending OAuth sessions (state → PendingOAuth). Cleaned up after 10 min.
  const pendingOAuth = new Map<string, PendingOAuth>();
  // Pending connect requests (SHA-256 of the request id → request). Single
  // use, 10 minutes.
  const pendingConnect = new Map<string, PendingConnectRequest>();
  const CONNECT_REQUEST_TTL_MS = 10 * 60 * 1000;
  const brokeredDelegations = new Map<string, BrokeredDelegation>();
  // Single writer of cumulative-constraint running totals (cumulative-ledger.ts in vault).
  const cumulativeLedger: CumulativeLedger = new SqliteCumulativeLedger(
    config.cumulativeLedgerPath ? { path: config.cumulativeLedgerPath } : {},
  );
  // Sub-Delegation Exchange: single-use grants and the actor-token replay cache.
  const delegationGrants = createDelegationGrantStore();
  const actorTokenJtiSeen = createJtiReplayCache();
  // DPoP proof replay cache, keyed by key thumbprint and jti.
  const dpopJtiSeen = createJtiReplayCache();
  // TOFU proofs spent on root delegation, per process (like the caches above).
  const tofuProofSeen = createJtiReplayCache();
  const allowRawTokens = config.allowRawTokens ?? false;
  const webBotAuthMaxLifetimeSeconds = config.webBotAuthMaxSignatureLifetimeSeconds ?? 300;
  const allowAgentsWithoutPermission = config.allowAgentsWithoutPermission === true;
  const allowRedelegationAfterRevocation = config.allowRedelegationAfterRevocation === true;
  const classifyBrokerCalls = config.allowUnclassifiedBrokerCalls !== true;
  const webBotAuthDirectoryCache = new Map<string, { expiresAt: number; directory: WebBotAuthDirectoryResponse }>();
  const webBotAuthNonceStore = createWebBotAuthNonceStore({
    store: config.webBotAuthNonceStore ?? 'memory',
    path: config.webBotAuthNoncePath,
  });

  // Legacy routes: does a request without user_id act on the shared
  // 'default' user (single-user mode) or is it refused (multi-user mode)?
  const singleUserMode = config.singleUserMode === true;
  console.log(singleUserMode
    ? '[cred] SINGLE_USER_MODE=true: legacy requests without user_id act on the shared "default" user'
    : '[cred] Multi-user mode: legacy requests must name user_id (set SINGLE_USER_MODE=true for a single shared user)');

  // Cred Link (Phase 1): off unless config.linkEnabled. Routes are mounted
  // here; delegate and use call into it below.
  const linkService: LinkService | null = config.linkEnabled
    ? createLinkService({
        vault,
        tofu,
        providers: config.providers,
        baseUrl: config.linkBaseUrl ?? config.redirectBaseUri,
        redirectBaseUri: config.redirectBaseUri,
        storePath: resolveLinkStorePath(config),
        customVerifier: Boolean(config.agentRequestVerifier),
        checkAgentKey: (req, res, resourceId) => checkLinkAgentKey(req, res, resourceId),
        issueToken: (req, res, input) => issueLinkDelegationToken(req, res, input),
        allowRawTokens: config.allowRawTokens ?? false,
        classifyBrokerCalls,
        allowRedelegationAfterRevocation,
        ...(config.linkHandleTtlSeconds !== undefined ? { handleTtlSeconds: config.linkHandleTtlSeconds } : {}),
        makeRateLimiter: (max) => makeRateLimiter(max),
      })
    : null;
  if (linkService) linkService.mount(app, requireAdminAuth);

  // Hash bearer/admin tokens once at startup for constant-time comparison
  const adminTokenHash = crypto.createHash('sha256').update(config.adminToken).digest('hex');
  const agentTokenHash = config.agentToken
    ? crypto.createHash('sha256').update(config.agentToken).digest('hex')
    : null;

  // ── Helpers ────────────────────────────────────────────────────────────────

  function getProviderConfig(slug: string): ProviderConfig | undefined {
    return providerMap.get(slug);
  }

  function makeOAuthClient(providerConfig: ProviderConfig): OAuthClient {
    const adapter = createAdapter(providerConfig.slug);
    return new OAuthClient({
      adapter,
      clientId: providerConfig.clientId,
      clientSecret: providerConfig.clientSecret,
      redirectUri: `${config.redirectBaseUri}/connect/${providerConfig.slug}/callback`,
    });
  }

  async function buildWebBotAuthDirectory(): Promise<WebBotAuthDirectoryResponse> {
    const agents = await tofu.listAgents();
    const agentKeys: WebBotAuthDirectoryKey[] = agents
      .filter((agent) => agent.status !== 'revoked')
      .flatMap((agent) => agentIdentityToDirectoryJwks(agent));
    const signingKey = getDirectorySigningJwk();
    const keysByKid = new Map<string, WebBotAuthDirectoryKey>();
    keysByKid.set(signingKey.kid, signingKey);
    for (const key of agentKeys) {
      if (!keysByKid.has(key.kid)) {
        keysByKid.set(key.kid, key);
      }
    }
    const keys: WebBotAuthDirectoryKey[] = Array.from(keysByKid.values());

    return { keys };
  }

  function getSignatureAgentUrl(): string {
    return `${config.redirectBaseUri}/.well-known/http-message-signatures-directory`;
  }

  function getAllowedSignatureAgentOrigins(): Set<string> {
    const allowedOrigins = new Set<string>();
    allowedOrigins.add(new URL(config.redirectBaseUri).origin);
    for (const origin of config.webBotAuthAllowedOrigins ?? []) {
      allowedOrigins.add(new URL(origin).origin);
    }
    return allowedOrigins;
  }

  function mapAgentToWebBotAuthKey(agent: Awaited<ReturnType<typeof tofu.listAgents>>[number]): WebBotAuthKeyResponse {
    return {
      agent_id: agent.agentId,
      fingerprint: agent.fingerprint,
      key_id: agent.keyId,
      previous_fingerprint: agent.previousFingerprint,
      previous_key_id: agent.previousKeyId,
      rotation_grace_expires_at: agent.rotationGraceExpiresAt ? agent.rotationGraceExpiresAt.toISOString() : null,
      status: agent.status,
      initial_scopes: agent.initialScopes,
      metadata: agent.metadata,
      signature_agent: getSignatureAgentUrl(),
      created_at: agent.createdAt.toISOString(),
      updated_at: agent.updatedAt.toISOString(),
      claimed_at: agent.claimedAt ? agent.claimedAt.toISOString() : null,
      revoked_at: agent.revokedAt ? agent.revokedAt.toISOString() : null,
    };
  }

  function decodeWebBotAuthPublicKey(publicKeyBase64: string): Uint8Array | null {
    const publicKey = new Uint8Array(Buffer.from(publicKeyBase64, 'base64'));
    if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) return null;
    return publicKey;
  }

  function hashTokenValue(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  function tokenMatchesHash(token: string, expectedHash: string): boolean {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const actual = Buffer.from(tokenHash, 'hex');
    const expected = Buffer.from(expectedHash, 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }

  function extractBearerToken(req: Request): string | null {
    const auth = req.headers.authorization ?? '';
    if (!auth.startsWith('Bearer ')) return null;
    const token = auth.slice(7).trim();
    return token || null;
  }

  function routeParam(value: string | string[] | undefined): string | undefined {
    return Array.isArray(value) ? value[0] : value;
  }

  function queryStringValue(value: unknown): string | undefined {
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) {
      return value.find((item): item is string => typeof item === 'string');
    }
    return undefined;
  }

  /**
   * Accept only a same-origin, absolute-path redirect target. The result is
   * rebuilt from the parsed path and query rather than echoed back, so a
   * caller cannot smuggle a scheme, authority, backslash host trick, control
   * character, or fragment into the Location header. Anything that does not
   * resolve to the placeholder origin falls back.
   */
  function safeRelativePath(rawPath: string | undefined, fallback = '/connect'): string {
    if (typeof rawPath !== 'string' || rawPath.length === 0 || rawPath.length > 2048) return fallback;
    if (!rawPath.startsWith('/') || rawPath.startsWith('//') || rawPath.startsWith('/\\')) return fallback;
    if (/[\u0000-\u001f\u007f\\]/.test(rawPath)) return fallback;
    let parsed: URL;
    try {
      parsed = new URL(rawPath, 'https://cred.invalid');
    } catch {
      return fallback;
    }
    if (parsed.origin !== 'https://cred.invalid' || !parsed.pathname.startsWith('/')) return fallback;
    const result = `${parsed.pathname}${parsed.search}`;
    // Dot-segment normalization can collapse '/a/..//host' into '//host',
    // which a browser reparses as protocol-relative. Reparse the rebuilt
    // string the way the browser will and require it to stay same-origin.
    if (result.startsWith('//')) return fallback;
    if (new URL(result, 'https://cred.invalid').origin !== 'https://cred.invalid') return fallback;
    return result;
  }

  // ── User id resolution (legacy, non-Link routes) ───────────────────────
  //
  // One resolver for every legacy handler that acts on a user's stored
  // tokens. Rules, in order:
  //   1. An agent principal that carries a userId (only a custom
  //      agentRequestVerifier can set one) binds the request to it: no
  //      user_id means that user, a different user_id is 403
  //      user_id_mismatch. Admin routes never apply this rule.
  //   2. An explicit, non-blank user_id is used as given (trimmed),
  //      'default' included.
  //   3. Otherwise SINGLE_USER_MODE decides: true acts on 'default', false
  //      (the default) refuses with 400 user_id_required.
  // The reserved Link user ids are refused after resolution.

  type UserIdResolution =
    | { ok: true; userId: string }
    | { ok: false; status: 400 | 403; error: 'user_id_required' | 'user_id_mismatch'; message: string };

  const USER_ID_REQUIRED_MESSAGE =
    'user_id is required: send the user_id of the user this call is for, or set SINGLE_USER_MODE=true on the server to act on the shared "default" user when user_id is omitted.';

  /** A user_id value as given, trimmed; undefined when absent, not a string, or blank. */
  function explicitUserIdValue(value: unknown): string | undefined {
    if (typeof value !== 'string') return undefined;
    const trimmed = value.trim();
    return trimmed === '' ? undefined : trimmed;
  }

  /** user_id from the JSON body, else from the query string. */
  function explicitRequestUserId(req: Request): string | undefined {
    return explicitUserIdValue(req.body?.user_id) ?? explicitUserIdValue(queryStringValue(req.query.user_id));
  }

  /** The user id the authenticated agent principal is bound to, if any. */
  function principalBoundUserId(req: Request): string | undefined {
    const principal = (req as any).agentPrincipal as RequestAgentPrincipal | undefined;
    if (!principal || principal.type === 'static-bearer') return undefined;
    return explicitUserIdValue(principal.userId);
  }

  function resolveUserId(req: Request, input: { explicit: string | undefined; agent: boolean }): UserIdResolution {
    const bound = input.agent ? principalBoundUserId(req) : undefined;
    if (bound !== undefined) {
      if (input.explicit !== undefined && input.explicit !== bound) {
        return {
          ok: false,
          status: 403,
          error: 'user_id_mismatch',
          message: 'user_id does not match the user the authenticated agent is bound to',
        };
      }
      return { ok: true, userId: bound };
    }
    if (input.explicit !== undefined) return { ok: true, userId: input.explicit };
    if (singleUserMode) return { ok: true, userId: 'default' };
    return { ok: false, status: 400, error: 'user_id_required', message: USER_ID_REQUIRED_MESSAGE };
  }

  /**
   * Resolve the request's user id for a JSON route, or send the refusal
   * (user_id_required, user_id_mismatch, or the reserved-id 400) and
   * return null. `source` 'body' reads only the JSON body (delegate,
   * subdelegate); the default reads the body, then the query string.
   */
  function requestUserId(
    req: Request,
    res: Response,
    opts: { agent: boolean; source?: 'body' | 'body-or-query' },
  ): string | null {
    const explicit = opts.source === 'body' ? explicitUserIdValue(req.body?.user_id) : explicitRequestUserId(req);
    const resolved = resolveUserId(req, { explicit, agent: opts.agent });
    if (!resolved.ok) {
      res.status(resolved.status).json({ error: resolved.error, message: resolved.message });
      return null;
    }
    if (rejectReservedUserId(res, resolved.userId)) return null;
    return resolved.userId;
  }

  /**
   * The same for the admin browser pages (/connect, and /providers when the
   * client prefers HTML): a short readable page instead of raw JSON.
   */
  function adminPageUserId(req: Request, res: Response, html: boolean): string | null {
    if (!html) return requestUserId(req, res, { agent: false });
    const resolved = resolveUserId(req, { explicit: explicitRequestUserId(req), agent: false });
    if (!resolved.ok) {
      const path = req.path === '/providers' ? '/providers' : '/connect';
      res.status(400).type('html').send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Cred: user_id required</title></head>
<body style="background:#0a0a0a;color:#e0e0e0;font-family:-apple-system,system-ui,sans-serif;padding:40px;max-width:640px;margin:0 auto;">
<h2>Which user?</h2>
<p>This server runs in multi-user mode, so this page needs the user whose connections you want to manage.</p>
<p>Add <code>?user_id=&lt;user id&gt;</code> to the address, for example <code>${escapeHtml(path)}?user_id=alice</code>.</p>
<p style="color:#888;">To act on the shared <code>default</code> user when no user_id is given, set <code>SINGLE_USER_MODE=true</code> on the server.</p>
</body></html>`);
      return null;
    }
    if (rejectReservedUserId(res, resolved.userId)) return null;
    return resolved.userId;
  }

  /**
   * Cred Link keeps its tokens in the vault under reserved user ids
   * (`link:<connection_id>`, `link-staged:<tid>`). No legacy entry point may
   * reach those rows with a caller-supplied user id, since that would bypass
   * the Link access check. Applied whether or not Link is enabled (tokens
   * may outlive a configuration change). Sends 400 and returns true when the
   * id is reserved.
   */
  function rejectReservedUserId(res: Response, userId: string): boolean {
    if (!isReservedLinkVaultUserId(userId)) return false;
    res.status(400).json({ error: 'invalid_user_id', message: 'This user_id is reserved' });
    return true;
  }

  /**
   * The vault itself refuses reserved Link user ids (ReservedVaultUserIdError).
   * Routes reject them before any vault call; if one still reaches the vault,
   * it is a 400, never a 500.
   */
  function sendReservedUserIdError(res: Response, err: unknown): boolean {
    const reserved = err instanceof ReservedVaultUserIdError
      || (typeof err === 'object' && err !== null && (err as { name?: unknown }).name === 'ReservedVaultUserIdError');
    if (!reserved || res.headersSent) return false;
    res.status(400).json({ error: 'invalid_user_id', message: 'This user_id is reserved' });
    return true;
  }

  /**
   * The consent URL handed to an agent: a single-use connect request bound
   * to the user id that already passed the user id rules, so the URL itself
   * carries no user id and no scopes.
   */
  function buildConsentUrl(input: {
    service: string;
    userId: string;
    appClientId?: string;
    scopes?: string[];
  }): string {
    const id = mintConnectRequest({
      provider: input.service,
      userId: input.userId,
      scopes: input.scopes ?? [],
      ...(input.appClientId ? { appClientId: input.appClientId } : {}),
    });
    return new URL(connectRequestPath(input.service, id), config.redirectBaseUri).toString();
  }

  /**
   * Brokered handles are the default: the provider token stays on the
   * server, and the handle is bound to its caller and revocable. A raw
   * provider token leaves the server and cannot be recalled, so it is an
   * explicit opt-in (`token_format: 'raw'`).
   */
  function tokenFormatFromBody(req: Request): 'raw' | 'handle' {
    return req.body?.token_format === 'raw' ? 'raw' : 'handle';
  }

  // The Google family table and the scope matching live in google-scopes.ts,
  // shared with Link's narrow response so the two cannot drift.
  const scopeEquivalent = brokerScopeEquivalent;

  const SALESFORCE_HOST_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.(?:salesforce\.com|force\.com)$/;
  const SAFE_PATH_AND_QUERY_PATTERN = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/;

  /**
   * Resolve the upstream URL the broker will call for a delegated request.
   *
   * Returns null when the request is not allowed. When it is, the returned
   * string is assembled from a server-side origin (the matched allowlist entry,
   * or a Salesforce instance host that passed the strict host grammar) plus the
   * caller's already-normalized path and query, so the scheme and authority of
   * the outbound request are never copied from caller input.
   */
  function resolveBrokerUrl(service: string, url: string, scopes?: string[]): string | null {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }

    if (parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) return null;
    if (parsed.port !== '' && parsed.port !== '443') return null;

    const hostname = parsed.hostname.toLowerCase();
    // WHATWG parsing has already resolved dot segments and percent-encoded
    // anything outside the path/query character set; reject anything else.
    const pathAndQuery = `${parsed.pathname}${parsed.search}`;
    if (!SAFE_PATH_AND_QUERY_PATTERN.test(pathAndQuery)) return null;
    if (pathAndQuery.startsWith('//')) return null;

    // Percent-encoding must not be able to hide a segment from the rules
    // below, here or at the provider: refuse an encoded dot, slash,
    // backslash or percent (double encoding) anywhere in the path, any case.
    if (/%(2e|2f|5c|25)/i.test(parsed.pathname)) return null;
    // Then match on the decoded path: no dot segments, no empty segments
    // (double slash), no backslash, no control characters.
    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(parsed.pathname);
    } catch {
      return null;
    }
    if (decodedPath.includes('\\') || decodedPath.includes('//') || /[\u0000-\u001f\u007f]/.test(decodedPath)) return null;
    if (decodedPath.split('/').some((segment) => segment === '.' || segment === '..')) return null;

    if (service === 'salesforce') {
      if (!SALESFORCE_HOST_PATTERN.test(hostname)) return null;
      if (/^(\d{1,3}\.){3}\d{1,3}\./.test(hostname)) return null;
      return `https://${hostname}${pathAndQuery}`;
    }

    const allowed = SERVICE_ALLOWLIST[service];
    if (!allowed) return null;
    const decodedUrl = `https://${hostname}${decodedPath}`;
    if ((BROKER_BLOCKED_ENDPOINTS[service] ?? []).some((blocked) => decodedUrl.toLowerCase().startsWith(blocked))) return null;
    // Matched constants must also be spelled literally in the encoded path,
    // so the outbound URL (constant plus the caller's remainder) means
    // exactly what was matched.
    const exact = (SERVICE_EXACT_ENDPOINTS[service] ?? []).find((endpoint) => (
      decodedUrl === endpoint && parsed.pathname === new URL(endpoint).pathname
    ));
    // Built from the constant endpoint plus the already-validated query.
    if (exact) return `${exact}${parsed.search}`;
    const base = allowed.find((candidate) => (
      decodedUrl.startsWith(candidate) && parsed.pathname.startsWith(new URL(candidate).pathname)
    ));
    if (!base) return null;
    if (service === 'google' && !isAllowedGoogleScopeEndpoint(decodedUrl, scopes, classifyBrokerCalls)) return null;

    // The base is a constant that ends in '/'; everything after it is the
    // caller's path below that base plus the query string.
    const remainder = `${parsed.pathname.slice(new URL(base).pathname.length)}${parsed.search}`;
    if (remainder.startsWith('/')) return null;
    return `${base}${remainder}`;
  }

  /**
   * Validate agent Bearer token. Constant-time comparison via hash.
   */
  function validateAgentToken(req: Request): boolean {
    if (!agentTokenHash) return false;
    const token = extractBearerToken(req);
    return token ? tokenMatchesHash(token, agentTokenHash) : false;
  }

  function parseCookies(req: Request): Record<string, string> {
    const raw = req.get('cookie') ?? '';
    const cookies: Record<string, string> = {};
    for (const part of raw.split(';')) {
      const eq = part.indexOf('=');
      if (eq <= 0) continue;
      const key = part.slice(0, eq).trim();
      const rawValue = part.slice(eq + 1).trim();
      try {
        if (key) cookies[key] = decodeURIComponent(rawValue);
      } catch {
        continue;
      }
    }
    return cookies;
  }

  function createAdminSessionValue(nowMs = Date.now()): string {
    const issuedAt = Math.floor(nowMs / 1000).toString();
    const signature = crypto
      .createHmac('sha256', config.adminToken)
      .update(issuedAt)
      .digest('base64url');
    return `${issuedAt}.${signature}`;
  }

  function validateAdminSessionValue(value: string | undefined, nowMs = Date.now()): boolean {
    if (!value) return false;
    const parts = value.split('.');
    if (parts.length !== 2) return false;
    const [issuedAtRaw, signature] = parts;
    if (!issuedAtRaw || !signature) return false;
    const issuedAt = Number.parseInt(issuedAtRaw, 10);
    if (!Number.isFinite(issuedAt)) return false;

    const nowSeconds = Math.floor(nowMs / 1000);
    if (issuedAt > nowSeconds + 60 || nowSeconds - issuedAt > ADMIN_SESSION_TTL_SECONDS) {
      return false;
    }

    const expected = crypto
      .createHmac('sha256', config.adminToken)
      .update(issuedAtRaw)
      .digest('base64url');
    const actualBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);
    return actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
  }

  function setAdminSessionCookie(res: Response): void {
    const secure = new URL(config.redirectBaseUri).protocol === 'https:' ? '; Secure' : '';
    res.setHeader(
      'Set-Cookie',
      `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(createAdminSessionValue())}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ADMIN_SESSION_TTL_SECONDS}${secure}`,
    );
  }

  /**
   * Which admin credential the request carries: the Bearer admin token, the
   * admin session cookie, or neither. A Bearer header cannot be sent by a
   * cross-site navigation; the session cookie (SameSite=Lax) can, on a
   * top-level GET.
   */
  function validateAdminRequest(req: Request): 'bearer' | 'cookie' | null {
    const token = extractBearerToken(req);
    if (token && tokenMatchesHash(token, adminTokenHash)) {
      return 'bearer';
    }
    const cookies = parseCookies(req);
    return validateAdminSessionValue(cookies[ADMIN_SESSION_COOKIE]) ? 'cookie' : null;
  }

  /**
   * Admin auth middleware for provider-management browser routes.
   *
   * Browser login posts the admin token to `/admin/login`, then stores an
   * HttpOnly same-site cookie. API callers may also use Bearer admin auth.
   */
  function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
    const credential = validateAdminRequest(req);
    if (!credential) {
      res.status(401).json({ error: 'Unauthorized. Provide a valid admin Bearer token or sign in at /admin/login.' });
      return;
    }
    (req as any).adminCredential = credential;

    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  }

  function hashAgentPrincipal(principal: RequestAgentPrincipal): string {
    const stableId = principal.principalId ?? 'anonymous';
    return crypto.createHash('sha256').update(`${principal.type}:${stableId}`).digest('hex');
  }

  // ── External identity (opt-in) ────────────────────────────────────────────
  // A source verifies a credential Cred did not issue; an exact mapping names
  // the existing agent it acts as. The request then runs as that agent's DID.
  const externalIdentity = config.externalIdentity;
  // Separate from dpopJtiSeen: a route that checks the same proof again (for
  // example /api/v1/delegate) keeps its own replay check.
  const externalDpopJtiSeen = createJtiReplayCache();
  /** The agent a verified external identity mapped to, per request. */
  const provenExternalAgent = new WeakMap<Request, { agentDid: string; identity: VerifiedExternalIdentity }>();

  function refuseExternalIdentity(
    req: Request,
    res: Response,
    kind: ExternalIdentityKind,
    code: string,
    detail: string,
    subject?: string,
    proof?: VerifiedExternalIdentity['proof'],
  ): 'refused' {
    // The response never says which check failed; the detail is for the
    // operator's log and audit trail only.
    console.warn(`[cred] ${kind} identity refused: ${code}: ${detail}`);
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: subject ?? 'unknown' },
      action: 'deny',
      resource: { type: 'agent', id: subject ?? 'unknown' },
      outcome: 'denied',
      correlationId: crypto.randomUUID(),
      metadata: { identitySource: kind, reason: code, route: req.originalUrl.split('?')[0], ...(proof ? { proof } : {}) },
    });
    if (proof === 'http-sig') {
      // draft-ietf-wimse-http-signature-08 §3.6: 400 with one problem type,
      // whatever failed (the WIT, the signature, or the identity after them).
      sendWimseSignatureInvalid(res);
      return 'refused';
    }
    if (code === 'agent_mismatch') {
      res.status(403).json({ error: 'agent_mismatch', message: 'agent_did does not name the agent this identity maps to' });
      return 'refused';
    }
    if (kind === 'wimse') res.setHeader('WWW-Authenticate', 'WPT');
    res.status(401).json({ error: kind === 'wimse' ? 'invalid_workload_identity' : 'invalid_tailnet_identity' });
    return 'refused';
  }

  function sendWimseSignatureInvalid(res: Response): void {
    res.status(400).type('application/problem+json').send(JSON.stringify({
      type: WIMSE_PROBLEM_TYPES.signatureInvalid,
      title: 'Workload authentication failed',
      status: 400,
    }));
  }

  /**
   * Runs every configured source. `false`: no source credential on this
   * request (the agent token path applies). `true`: authenticated, with
   * `req.provenAgent` set. `'refused'`: a response was sent.
   */
  async function authenticateExternalIdentity(req: Request, res: Response): Promise<boolean | 'refused'> {
    if (!externalIdentity || externalIdentity.sources.length === 0) return false;
    const targetUri = `${publicBaseUri()}${req.originalUrl.split('?')[0]}`;
    const queryAt = req.originalUrl.indexOf('?');
    const contentLength = Number(req.headers['content-length'] ?? 0);
    const request: IdentityRequest = {
      method: req.method.toUpperCase(),
      targetUri,
      headers: req.headers,
      rawHeaders: req.rawHeaders,
      socket: req.socket,
      path: req.originalUrl.split('?')[0],
      ...(queryAt === -1 ? {} : { query: req.originalUrl.slice(queryAt + 1) }),
      hasBody: contentLength > 0 || req.headers['transfer-encoding'] !== undefined,
      body: workloadRequestBodies.get(req),
    };
    const found: VerifiedExternalIdentity[] = [];
    for (const source of externalIdentity.sources) {
      try {
        const identity = await source.authenticate(request);
        if (identity) found.push(identity);
      } catch (err) {
        if (err instanceof IdentityRefusal) return refuseExternalIdentity(req, res, err.kind, err.code, err.detail, undefined, err.proof);
        return refuseExternalIdentity(req, res, source.kind, 'source_error', err instanceof Error ? err.message : String(err));
      }
    }
    if (found.length === 0) return false;
    if (found.length > 1) {
      return refuseExternalIdentity(req, res, found[0].kind, 'multiple_identities', found.map((i) => i.kind).join(','), undefined, found.some((i) => i.proof === 'http-sig') ? 'http-sig' : undefined);
    }
    const identity = found[0];
    // Sources apply their own clock skew to exp; this backstop allows the same 60s.
    if (identity.expiresAt + 60 <= Math.floor(Date.now() / 1000)) {
      return refuseExternalIdentity(req, res, identity.kind, 'expired', 'identity expired', identity.subject, identity.proof);
    }
    const agentDid = mappedAgentDid(externalIdentity.mappings, identity);
    if (!agentDid) return refuseExternalIdentity(req, res, identity.kind, 'unmapped', 'no mapping for subject', identity.subject, identity.proof);
    // The mapped agent must already exist and be active. Nothing is created
    // from an identity Cred has not been told about.
    const record = vault.getAgentByDid ? await vault.getAgentByDid(agentDid) : null;
    if (!record) return refuseExternalIdentity(req, res, identity.kind, 'agent_not_found', agentDid, identity.subject, identity.proof);
    if (record.status !== 'active') {
      return refuseExternalIdentity(req, res, identity.kind, `agent_${record.status}`, agentDid, identity.subject, identity.proof);
    }
    if (identity.proof === 'channel') {
      // A channel identity (Tailscale) proves the node, not the agent on it:
      // the mapped agent's did:key must sign this request too.
      const proof = readDpopHeader(req.headers.dpop);
      const checked = proof === 'multiple'
        ? { ok: false as const, message: 'multiple DPoP headers' }
        : verifyDpopProof(proof, { agentDid, htm: request.method, htu: targetUri, seenJti: externalDpopJtiSeen });
      if (!checked.ok) return refuseExternalIdentity(req, res, identity.kind, 'dpop_required', checked.message, identity.subject, identity.proof);
    }
    const named = req.body?.agent_did;
    if (typeof named === 'string' && named !== agentDid && named !== record.id) {
      return refuseExternalIdentity(req, res, identity.kind, 'agent_mismatch', `${named} != ${agentDid}`, identity.subject, identity.proof);
    }
    const principal: RequestAgentPrincipal = {
      type: identity.kind,
      principalId: agentDid,
      metadata: {
        externalIdentity: {
          kind: identity.kind,
          subject: identity.subject,
          trustDomain: identity.trustDomain,
          attributes: identity.attributes,
        },
      },
    };
    if (identity.attributes.signResponse === 'true') {
      // §3.3/§3.6: Cred does not sign responses, so a request that requires a
      // signed response gets 501 rather than a successful unsigned answer.
      res.status(501).type('application/problem+json').send(JSON.stringify({
        type: WIMSE_PROBLEM_TYPES.signedResponseUnsupported,
        title: 'Signed responses are not supported',
        status: 501,
      }));
      return 'refused';
    }
    (req as any).agentPrincipal = principal;
    (req as any).agentTokenHash = hashAgentPrincipal(principal);
    provenExternalAgent.set(req, { agentDid, identity });
    return true;
  }

  /**
   * A WIT with an HTTP signature on /api/v1/use. The signature must cover
   * Authorization (so the Delegation Token cannot be swapped), and the
   * workload must map to the agent the Delegation Token was issued to.
   */
  async function authenticateUseWorkload(req: Request, res: Response, tokenAgentDid: string): Promise<'ok' | 'refused'> {
    // Guard and audit keep keying on the Delegation Token's binding.
    const keepHash = (req as any).agentTokenHash;
    const keepPrincipal = (req as any).agentPrincipal;
    const result = await authenticateExternalIdentity(req, res);
    if (result === 'refused') return 'refused';
    const proven = provenExternalAgent.get(req);
    (req as any).agentTokenHash = keepHash;
    (req as any).agentPrincipal = keepPrincipal;
    if (!result || !proven || proven.identity.kind !== 'wimse') {
      return refuseExternalIdentity(req, res, 'wimse', 'proof_required', 'no workload identity verified on /use', undefined, 'http-sig');
    }
    const { identity, agentDid } = proven;
    if (identity.proof !== 'http-sig') {
      return refuseExternalIdentity(req, res, 'wimse', 'proof_required', '/use needs an HTTP signature', identity.subject, 'http-sig');
    }
    const covered = identity.attributes.covered;
    if (!Array.isArray(covered) || !covered.includes('authorization')) {
      return refuseExternalIdentity(req, res, 'wimse', 'authorization_not_covered', 'signature does not cover Authorization', identity.subject, 'http-sig');
    }
    if (agentDid !== tokenAgentDid) {
      return refuseExternalIdentity(req, res, 'wimse', 'agent_mismatch', 'workload maps to another agent than the Delegation Token', identity.subject, 'http-sig');
    }
    return 'ok';
  }

  /**
   * Agent auth middleware for /api/* routes.
   */
  async function requireAgentAuth(req: Request, res: Response, next: NextFunction) {
    try {
      const external = await authenticateExternalIdentity(req, res);
      if (external === 'refused') return;
      if (external) {
        next();
        return;
      }
    } catch (err) {
      next(err);
      return;
    }
    if (config.agentRequestVerifier) {
      try {
        const result = await config.agentRequestVerifier(req);
        if (result.ok) {
          const principal: RequestAgentPrincipal = result.principal ?? { type: 'custom-verifier' };
          (req as any).agentPrincipal = principal;
          (req as any).agentTokenHash = hashAgentPrincipal(principal);
          next();
          return;
        }
        res.status(result.status ?? 401).json({
          error: result.error ?? 'Unauthorized. Provide valid agent credentials.',
        });
        return;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Agent request verification failed';
        res.status(401).json({ error: message });
        return;
      }
    }

    if (!validateAgentToken(req)) {
      res.status(401).json({ error: 'Unauthorized. Provide a valid Bearer token.' });
      return;
    }
    const principal: RequestAgentPrincipal = { type: 'static-bearer' };
    (req as any).agentPrincipal = principal;
    (req as any).agentTokenHash = hashTokenValue(extractBearerToken(req) ?? '');
    next();
  }

  /**
   * Runs Web Bot Auth signature verification when Signature headers are present,
   * independent of `config.webBotAuthMode`. Populates `req.webBotAuthIdentity` on
   * success; no-ops (does not throw) when no signature headers are present at all.
   * Returns whether signature headers were present, so callers with their own
   * mode-specific behavior (e.g. `require` mode's 401-when-absent) don't need to
   * re-derive header presence themselves.
   */
  /**
   * Whether Signature-Input carries a WIMSE-tagged member. Throws when it
   * carries one alongside any other member: such a request is ambiguous
   * between Web Bot Auth and WIMSE, and is refused rather than guessed at.
   */
  function carriesWimseSignature(req: Request): boolean {
    const input = req.get('Signature-Input');
    if (!input) return false;
    let dict;
    try {
      dict = parseDictionary(input);
    } catch {
      return false; // Not parseable: Web Bot Auth verification refuses it.
    }
    let wimse = 0;
    for (const member of dict.values()) {
      const tag = member.params.get('tag');
      if (tag?.type === 'string' && tag.value === WIMSE_SIGNATURE_TAG) wimse++;
    }
    if (wimse === 0) return false;
    if (dict.size > wimse) throw new Error('a WIMSE signature cannot be combined with another message signature here');
    return true;
  }

  async function attemptWebBotAuthIdentity(req: Request): Promise<boolean> {
    const hasHeaders = Boolean(req.get('Signature') || req.get('Signature-Input') || req.get('Signature-Agent'));
    if (!hasHeaders) {
      return false;
    }
    if (externalIdentity && carriesWimseSignature(req)) {
      // A WIMSE workload signature is verified by the external identity
      // source, never as Web Bot Auth, and never satisfies Web Bot Auth
      // identity. A request mixing it with another signature is refused here.
      return false;
    }

    const verifiedIdentity = await verifyIncomingWebBotAuthRequest(req);
    (req as any).webBotAuthIdentity = verifiedIdentity;

    if (req.body && typeof req.body === 'object') {
      const body = req.body as Record<string, unknown>;
      if (typeof body.web_bot_auth_key_id !== 'string') {
        body.web_bot_auth_key_id = verifiedIdentity.keyId;
      }
      if (typeof body.signature_agent !== 'string') {
        body.signature_agent = verifiedIdentity.signatureAgent;
      }
    }
    return true;
  }

  async function verifyWebBotAuth(req: Request, res: Response, next: NextFunction) {
    const mode = config.webBotAuthMode ?? 'off';
    if (mode === 'off') {
      next();
      return;
    }

    try {
      const hadHeaders = await attemptWebBotAuthIdentity(req);
      if (!hadHeaders && mode === 'require') {
        res.status(401).json({ error: 'Web Bot Auth signature required' });
        return;
      }
      next();
    } catch (err) {
      res.status(401).json({
        error: 'invalid_web_bot_auth',
        message: err instanceof Error ? err.message : 'Web Bot Auth verification failed',
      });
    }
  }

  /**
   * Like `verifyWebBotAuth`, but ignores `config.webBotAuthMode` entirely — always
   * attempts verification when signature headers are present. Used only on routes
   * where ownership of a specific `:agentId` must be provable regardless of the
   * deployment's global Web Bot Auth posture (`rotate`, `revoke-all`).
   */
  async function requireVerifiedIdentityRegardlessOfMode(req: Request, res: Response, next: NextFunction) {
    try {
      await attemptWebBotAuthIdentity(req);
      next();
    } catch (err) {
      res.status(401).json({
        error: 'invalid_web_bot_auth',
        message: err instanceof Error ? err.message : 'Web Bot Auth verification failed',
      });
    }
  }

  type OwnershipCheckResult = { ok: true } | { ok: false; status: number; error: string };

  /**
   * The caller's custom-verifier principalId, but only when it came from an
   * actual custom `agentRequestVerifier` — never from the shared static-bearer
   * principal (which never populates `principalId` today, but this guards
   * against that invariant silently changing later). Shared by
   * `assertOwnsAgentId` and deny-audit-event actor attribution so a
   * static-bearer-tagged principal can never be trusted as an identity in
   * either place.
   */
  function verifiedPrincipalId(req: Request): string | undefined {
    const agentPrincipal = (req as any).agentPrincipal as RequestAgentPrincipal | undefined;
    return agentPrincipal && agentPrincipal.type !== 'static-bearer' ? agentPrincipal.principalId : undefined;
  }

  /**
   * Verifies the calling principal's verified identity matches `targetAgentId` in
   * the given namespace. Takes only pre-loaded records — never reads storage itself,
   * so there is no time-of-check/time-of-use gap between loading a record and
   * checking it. See docs/plans/2026-08-31-002-fix-agent-ownership-check-plan.md.
   */
  function assertOwnsAgentId(req: Request, targetAgentId: string, namespace: 'tofu'): OwnershipCheckResult;
  function assertOwnsAgentId(
    req: Request,
    targetAgentId: string,
    namespace: 'vault',
    vaultAgent: AgentRecord,
  ): OwnershipCheckResult;
  function assertOwnsAgentId(
    req: Request,
    targetAgentId: string,
    namespace: 'tofu' | 'vault',
    vaultAgent?: AgentRecord,
  ): OwnershipCheckResult {
    const webBotAuthIdentity = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;

    if (namespace === 'tofu') {
      const candidate = webBotAuthIdentity?.agentId;
      if (candidate && candidate === targetAgentId) {
        return { ok: true };
      }
    } else {
      const candidate = webBotAuthIdentity?.fingerprint;
      const recordFingerprint = vaultAgent?.fingerprint;
      if (candidate && recordFingerprint && candidate === recordFingerprint) {
        return { ok: true };
      }
    }

    const principalId = verifiedPrincipalId(req);
    if (principalId && principalId === targetAgentId) {
      return { ok: true };
    }

    return {
      ok: false,
      status: 403,
      error: 'Forbidden. A verified identity matching this agent is required for this action.',
    };
  }

  function connectRequestKey(id: string): string {
    return crypto.createHash('sha256').update(id).digest('hex');
  }

  /** Mint a single-use connect request; returns its id (256 random bits). */
  function mintConnectRequest(input: { provider: string; userId: string; scopes: string[]; appClientId?: string }): string {
    const now = Date.now();
    for (const [key, pending] of pendingConnect) {
      if (pending.expiresAt <= now) pendingConnect.delete(key);
    }
    const id = crypto.randomBytes(32).toString('base64url');
    pendingConnect.set(connectRequestKey(id), {
      provider: input.provider,
      userId: input.userId,
      scopes: [...input.scopes],
      ...(input.appClientId ? { appClientId: input.appClientId } : {}),
      expiresAt: now + CONNECT_REQUEST_TTL_MS,
    });
    return id;
  }

  /** Consume a connect request: null when unknown, expired, already used, or for another provider. */
  function consumeConnectRequest(id: string, provider: string): PendingConnectRequest | null {
    const key = connectRequestKey(id);
    const pending = pendingConnect.get(key);
    if (!pending) return null;
    pendingConnect.delete(key);
    if (pending.expiresAt <= Date.now() || pending.provider !== provider) return null;
    return pending;
  }

  function connectRequestPath(provider: string, id: string): string {
    return `/connect/${encodeURIComponent(provider)}?request=${encodeURIComponent(id)}`;
  }

  /**
   * Clean up expired pending OAuth sessions (older than 10 minutes).
   */
  function cleanPendingOAuth() {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [state, pending] of pendingOAuth) {
      if (pending.createdAt < cutoff) {
        pendingOAuth.delete(state);
      }
    }
  }

  function escapeHtml(value: string): string {
    return value.replace(/[&<>"']/g, (char) => {
      switch (char) {
        case '&':
          return '&amp;';
        case '<':
          return '&lt;';
        case '>':
          return '&gt;';
        case '"':
          return '&quot;';
        case '\'':
          return '&#39;';
        default:
          return char;
      }
    });
  }

  function jsonScriptString(value: string): string {
    return JSON.stringify(value).replace(/</g, '\\u003c');
  }

  function derivePassphraseKey(context: string): Buffer {
    return crypto.scryptSync(config.vaultPassphrase, `cred:${context}:v1`, 32);
  }

  function getDirectorySigningKey() {
    const seed = derivePassphraseKey('web-bot-auth-directory');
    return createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        seed,
      ]),
      format: 'der',
      type: 'pkcs8',
    });
  }

  function getDirectorySigningJwk(): WebBotAuthDirectoryKey {
    const publicKey = createPublicKey(getDirectorySigningKey());
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const rawPublicKey = new Uint8Array(spki.slice(-32));
    const jwk = publicKeyToJwkWithKid(rawPublicKey);
    return {
      ...jwk,
      alg: 'EdDSA',
      use: 'sig',
    };
  }

  function createDirectorySignatureHeaders(authority: string): DirectorySignatureHeaders {
    const signingKey = getDirectorySigningKey();
    const signingJwk = getDirectorySigningJwk();
    const created = Math.floor(Date.now() / 1000);
    const expires = created + 60;
    const signatureParams =
      `("@authority";req);created=${created};expires=${expires};keyid="${signingJwk.kid}";tag="http-message-signatures-directory"`;
    const signatureBase = [
      `"@authority";req: ${authority}`,
      `"@signature-params": ${signatureParams}`,
    ].join('\n');
    const signature = sign(null, Buffer.from(signatureBase, 'utf8'), signingKey).toString('base64');

    return {
      'Signature-Input': `sig0=${signatureParams}`,
      'Signature': `sig0=:${signature}:`,
    };
  }

  function parseQuotedHeaderValue(value: string | undefined): string | null {
    if (!value) return null;
    const trimmed = value.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  }

  function parseSignatureInput(headerValue: string | undefined): ParsedSignatureInput {
    if (!headerValue) {
      throw new Error('Missing Signature-Input header');
    }

    const trimmed = headerValue.trim();
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex <= 0) {
      throw new Error('Invalid Signature-Input header');
    }

    const label = trimmed.slice(0, eqIndex);
    const rawParams = trimmed.slice(eqIndex + 1);
    const componentMatch = rawParams.match(/^\(([^)]*)\)/);
    if (!componentMatch) {
      throw new Error('Signature-Input is missing component list');
    }

    const components = componentMatch[1]
      .trim()
      .split(/\s+/)
      .map((component) => component.replace(/^"|"$/g, ''))
      .filter(Boolean);

    const params: Record<string, string> = {};
    const paramRegex = /;([a-zA-Z@_-]+)=("(?:[^"\\]|\\.)*"|[^;]+)/g;
    let match: RegExpExecArray | null;
    while ((match = paramRegex.exec(rawParams)) !== null) {
      const [, name, rawValue] = match;
      params[name] = rawValue.startsWith('"') && rawValue.endsWith('"')
        ? rawValue.slice(1, -1)
        : rawValue;
    }

    return { label, rawParams, components, params };
  }

  function parseSignatureHeader(headerValue: string | undefined, expectedLabel: string): Buffer {
    if (!headerValue) {
      throw new Error('Missing Signature header');
    }

    const trimmed = headerValue.trim();
    const match = trimmed.match(/^([A-Za-z0-9_-]+)=:([^:]+):$/);
    if (!match) {
      throw new Error('Invalid Signature header');
    }
    if (match[1] !== expectedLabel) {
      throw new Error('Signature label does not match Signature-Input');
    }

    return Buffer.from(match[2], 'base64');
  }

  function assertSignatureTimeWindow(params: Record<string, string>, now = Date.now()): number {
    const created = Number.parseInt(params.created ?? '', 10);
    const expires = Number.parseInt(params.expires ?? '', 10);
    if (!Number.isFinite(created) || !Number.isFinite(expires)) {
      throw new Error('Signature-Input must include created and expires');
    }

    const nowSeconds = Math.floor(now / 1000);
    const allowedSkewSeconds = 60;
    if (created > nowSeconds + allowedSkewSeconds) {
      throw new Error('Signature created timestamp is in the future');
    }
    if (expires < nowSeconds - allowedSkewSeconds) {
      throw new Error('Signature has expired');
    }
    // The nonce is kept until `expires`, so the signer must not choose how
    // long the replay store holds its entry.
    if (expires < created || expires - created > webBotAuthMaxLifetimeSeconds) {
      throw new Error(`Signature lifetime must be between 0 and ${webBotAuthMaxLifetimeSeconds} seconds`);
    }

    return expires;
  }

  function createEd25519PublicKeyFromDirectoryKey(key: WebBotAuthDirectoryKey) {
    return createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        Buffer.from(key.x, 'base64url'),
      ]),
      format: 'der',
      type: 'spki',
    });
  }

  function buildRequestSignatureBase(
    components: string[],
    authority: string,
    signatureAgent: string,
    rawSignatureParams: string,
  ): string {
    const lines = components.map((component) => {
      switch (component) {
        case '@authority':
          return `"@authority": ${authority}`;
        case 'signature-agent':
          return `"signature-agent": "${signatureAgent}"`;
        default:
          throw new Error(`Unsupported signed component: ${component}`);
      }
    });

    lines.push(`"@signature-params": ${rawSignatureParams}`);
    return lines.join('\n');
  }

  function verifyDirectorySignature(
    directory: WebBotAuthDirectoryResponse,
    signatureInputHeader: string | undefined,
    signatureHeader: string | undefined,
    authority: string,
  ): void {
    const parsed = parseSignatureInput(signatureInputHeader);
    if (parsed.params.tag !== 'http-message-signatures-directory') {
      throw new Error('Directory signature is missing http-message-signatures-directory tag');
    }
    if (parsed.components.length !== 1 || parsed.components[0] !== '@authority') {
      throw new Error('Directory signature must cover @authority');
    }

    assertSignatureTimeWindow(parsed.params);
    const signature = parseSignatureHeader(signatureHeader, parsed.label);
    const signingKeyId = parsed.params.keyid;
    if (!signingKeyId) {
      throw new Error('Directory signature is missing keyid');
    }

    const signingKey = directory.keys.find((key) => key.kid === signingKeyId);
    if (!signingKey) {
      throw new Error('Directory signing key not found');
    }

    const valid = verify(
      null,
      Buffer.from([
        `"@authority";req: ${authority}`,
        `"@signature-params": ${parsed.rawParams}`,
      ].join('\n'), 'utf8'),
      createEd25519PublicKeyFromDirectoryKey(signingKey),
      signature,
    );

    if (!valid) {
      throw new Error('Directory signature verification failed');
    }
  }

  function assertSafeSignatureAgentUrl(signatureAgent: string): URL {
    const url = new URL(signatureAgent);
    const hostname = url.hostname;
    const isExplicitLocalhost = ['localhost', '127.0.0.1'].includes(hostname);
    const expectedPath = '/.well-known/http-message-signatures-directory';

    // Enforce existing scheme requirements: HTTPS everywhere, HTTP only for explicit localhost.
    if (url.protocol !== 'https:' && !(isExplicitLocalhost && url.protocol === 'http:')) {
      throw new Error('Signature-Agent must use HTTPS unless it targets localhost');
    }

    if (url.username || url.password) {
      throw new Error('Signature-Agent must not include credentials');
    }

    if (url.pathname !== expectedPath || url.search || url.hash) {
      throw new Error(`Signature-Agent must point to ${expectedPath}`);
    }

    // Block private/loopback IPv4 ranges (excluding the explicitly allowed localhost values).
    const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    if (!isExplicitLocalhost && isIPv4) {
      const octets = hostname.split('.').map((part) => parseInt(part, 10));
      if (
        octets.length === 4 &&
        (
          octets[0] === 10 ||                                                   // 10.0.0.0/8
          (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||         // 172.16.0.0/12
          (octets[0] === 192 && octets[1] === 168) ||                           // 192.168.0.0/16
          (octets[0] === 169 && octets[1] === 254) ||                           // 169.254.0.0/16 (cloud metadata, APIPA)
          (octets[0] === 0)                                                      // 0.0.0.0/8 (routes to loopback on many systems)
        )
      ) {
        throw new Error('Signature-Agent must not target private network addresses');
      }
    }

    // Block private/loopback IPv6 ranges.
    // URL spec wraps IPv6 addresses in brackets; strip them for comparison.
    const isIPv6 = hostname.startsWith('[') && hostname.endsWith(']');
    if (!isExplicitLocalhost && isIPv6) {
      const addr = hostname.slice(1, -1).toLowerCase();
      const isPrivateIPv6 =
        addr === '::1' ||                         // loopback
        addr.startsWith('::ffff:') ||             // IPv4-mapped (e.g. ::ffff:10.0.0.1)
        addr.startsWith('fc') ||                  // unique local fc00::/7
        addr.startsWith('fd') ||                  // unique local fd00::/8
        addr.startsWith('fe8') ||                 // link-local fe80::/10
        addr.startsWith('fe9') ||
        addr.startsWith('fea') ||
        addr.startsWith('feb');
      if (isPrivateIPv6) {
        throw new Error('Signature-Agent must not target private network addresses');
      }
    }

    if (!getAllowedSignatureAgentOrigins().has(url.origin)) {
      throw new Error('Signature-Agent origin is not trusted');
    }

    return new URL(expectedPath, `${url.origin}/`);
  }

  async function resolveWebBotAuthDirectory(signatureAgent: string): Promise<WebBotAuthDirectoryResponse> {
    if (signatureAgent === getSignatureAgentUrl()) {
      return buildWebBotAuthDirectory();
    }

    const cached = webBotAuthDirectoryCache.get(signatureAgent);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.directory;
    }

    const url = assertSafeSignatureAgentUrl(signatureAgent);

    const response = await fetch(url.toString(), {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/http-message-signatures-directory+json, application/json',
      },
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch Signature-Agent directory (${response.status})`);
    }

    const directory = await response.json() as WebBotAuthDirectoryResponse;
    if (!directory || !Array.isArray(directory.keys)) {
      throw new Error('Signature-Agent directory returned invalid JSON');
    }

    verifyDirectorySignature(
      directory,
      response.headers.get('signature-input') ?? undefined,
      response.headers.get('signature') ?? undefined,
      url.host,
    );

    const parsed = parseSignatureInput(response.headers.get('signature-input') ?? undefined);
    const expires = Number.parseInt(parsed.params.expires ?? '', 10);
    if (Number.isFinite(expires)) {
      webBotAuthDirectoryCache.set(signatureAgent, {
        expiresAt: expires * 1000,
        directory,
      });
    }

    return directory;
  }

  async function verifyIncomingWebBotAuthRequest(req: Request): Promise<VerifiedWebBotAuthIdentity> {
    const signatureAgent = parseQuotedHeaderValue(req.get('Signature-Agent'));
    if (!signatureAgent) {
      throw new Error('Missing Signature-Agent header');
    }

    const parsed = parseSignatureInput(req.get('Signature-Input') ?? undefined);
    if (parsed.params.tag !== 'web-bot-auth') {
      throw new Error('Signature-Input is missing web-bot-auth tag');
    }
    if (!parsed.params.keyid) {
      throw new Error('Signature-Input is missing keyid');
    }
    if (!parsed.params.nonce) {
      throw new Error('Signature-Input is missing nonce');
    }
    if (!parsed.components.includes('@authority') || !parsed.components.includes('signature-agent')) {
      throw new Error('Signature-Input must cover @authority and signature-agent');
    }

    const expires = assertSignatureTimeWindow(parsed.params);
    const signature = parseSignatureHeader(req.get('Signature') ?? undefined, parsed.label);
    const directory = await resolveWebBotAuthDirectory(signatureAgent);
    const key = directory.keys.find((candidate) => candidate.kid === parsed.params.keyid);
    if (!key) {
      throw new Error('Signing key not found in Signature-Agent directory');
    }

    const authority = req.get('host') ?? new URL(config.redirectBaseUri).host;
    const valid = verify(
      null,
      Buffer.from(buildRequestSignatureBase(parsed.components, authority, signatureAgent, parsed.rawParams), 'utf8'),
      createEd25519PublicKeyFromDirectoryKey(key),
      signature,
    );

    if (!valid) {
      throw new Error('Web Bot Auth signature verification failed');
    }
    // Recorded only once the signature verifies, so unsigned requests cannot
    // fill the store or claim a nonce a real signer will send later.
    webBotAuthNonceStore.remember({
      signatureAgent,
      keyId: parsed.params.keyid,
      nonce: parsed.params.nonce,
      expiresAtSeconds: expires,
    });

    const identity: VerifiedWebBotAuthIdentity = {
      keyId: parsed.params.keyid,
      signatureAgent,
    };
    const localAgent = (await tofu.listAgents()).find((agent) => agent.keyId === parsed.params.keyid);
    if (localAgent) {
      identity.agentId = localAgent.agentId;
      identity.fingerprint = localAgent.fingerprint;
    }
    return identity;
  }

  function invalidRateLimit(limit: unknown): boolean {
    if (limit === undefined || limit === null) return false;
    const { maxRequests, windowMs } = limit as { maxRequests?: unknown; windowMs?: unknown };
    return !Number.isSafeInteger(maxRequests) || (maxRequests as number) < 1 || !Number.isSafeInteger(windowMs) || (windowMs as number) < 1;
  }

  function rateLimitKey(req: Request): string {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    return ipKeyGenerator(ip);
  }

  function makeRateLimiter(max: number) {
    return rateLimit({
      windowMs: 60_000,
      max,
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: rateLimitKey,
    });
  }

  const connectUiRateLimiter = makeRateLimiter(30);
  const connectRateLimiter = makeRateLimiter(20);
  const callbackRateLimiter = makeRateLimiter(60);
  const tokenRateLimiter = makeRateLimiter(120);
  const delegateRateLimiter = makeRateLimiter(60);
  const auditRateLimiter = makeRateLimiter(30);
  const subdelegateRateLimiter = makeRateLimiter(60);
  const revokeRateLimiter = makeRateLimiter(30);
  const tofuRegisterRateLimiter = makeRateLimiter(10);
  const directoryRateLimiter = makeRateLimiter(60);  // /.well-known/… — crypto work per request
  const healthRateLimiter = makeRateLimiter(120);    // /health       — cheap but still DoS-able
  const providersRateLimiter = makeRateLimiter(30);  // /providers     — vault DB query per request
  const adminPermissionsRateLimiter = makeRateLimiter(30);  // /admin/permissions* — sqlite query per request
  const adminAuditRateLimiter = makeRateLimiter(30);  // /admin/audit          — vault audit query per request
  const adminAgentsRateLimiter = makeRateLimiter(30);  // /admin/agents*        — tofu/vault query per request

  function writeAuditEventIfSupported(event: Parameters<CredVault['writeAuditEvent']>[0]) {
    try {
      vault.writeAuditEvent(event);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('not supported')) {
        return;
      }
      throw err;
    }
  }

  // A flood of one refusal by one agent is one event and a count.
  const refusals = createRefusalAggregator({ write: writeAuditEventIfSupported });
  const refusalSweep = setInterval(() => {
    try {
      refusals.flushExpired();
    } catch (err) {
      console.error('[audit] Failed to write a refusal summary:', err instanceof Error ? err.message : err);
    }
  }, 30_000);
  if (refusalSweep.unref) refusalSweep.unref();

  /** Who made a brokered call: its agent's DID, else its Link agent, else the shared identity. */
  function brokeredActor(delegation: BrokeredDelegation): AuditActor {
    return {
      type: 'agent',
      id: delegation.agentDid ?? delegation.link?.agentId ?? 'server-agent',
      ...(delegation.dpopJkt ? { fingerprint: delegation.dpopJkt } : {}),
    };
  }

  /** What every /api/v1/use event says about the call. Never the query string. */
  function brokeredCallMetadata(delegationId: string, delegation: BrokeredDelegation, url?: string): Record<string, unknown> {
    return {
      delegationId,
      ...(classifyBrokerCalls ? {} : { enforcementOptOuts: ['unclassified_broker_calls'] }),
      ...(delegation.link ? { linkAgentId: delegation.link.agentId } : {}),
      // A fixed provider host, or the Salesforce instance stored for this
      // connection. Any other host, even one a pattern would admit, is a value
      // the caller chose.
      ...(url !== undefined ? auditOriginAndRoute(url, (origin) => KNOWN_PROVIDER_ORIGINS.has(origin)
        || (delegation.service === 'salesforce' && origin === delegation.instanceOrigin)) : {}),
    };
  }

  /** Record a refused /api/v1/use call, aggregated per agent. */
  function refuseBrokeredCall(
    delegationId: string,
    delegation: BrokeredDelegation,
    url: string,
    error: string,
    metadata: Record<string, unknown> = {},
    outcome: AuditEvent['outcome'] = 'denied',
  ): void {
    refusals.record({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: brokeredActor(delegation),
      action: outcome === 'denied' ? 'deny' : 'access',
      resource: { type: 'token', id: `${delegation.service}/${delegation.userId}` },
      outcome,
      correlationId: crypto.randomUUID(),
      errorMessage: error,
      metadata: { ...brokeredCallMetadata(delegationId, delegation, url), ...metadata },
    });
  }

  /** Batched writeAuditEventIfSupported(): one transaction on SQLite. */
  function writeAuditEventsIfSupported(events: AuditEvent[]) {
    if (events.length === 0) return;
    try {
      vault.writeAuditEvents(events);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('not supported')) {
        return;
      }
      throw err;
    }
  }

  // ── Receipt helpers (Ed25519, same key derivation as SDK local mode) ──────

  function getReceiptSigningKey() {
    const seed = derivePassphraseKey('local-receipt');
    return createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        seed,
      ]),
      format: 'der',
      type: 'pkcs8',
    });
  }

  let receiptKeys: ReceiptKeys | undefined;
  /** Signer, accepted algorithms and key resolver for receipts. See receipt-signing.ts. */
  function getReceiptKeys(): ReceiptKeys {
    receiptKeys ??= createReceiptKeys({
      derivedKey: getReceiptSigningKey(),
      ...(config.receiptSigner ? { signer: config.receiptSigner } : {}),
      ...(config.receiptSigningKeyPem ? { signingKeyPem: config.receiptSigningKeyPem } : {}),
      ...(config.receiptVerificationKeys ? { verificationKeys: config.receiptVerificationKeys } : {}),
      ...(config.receiptAcceptedAlgs ? { acceptedAlgs: config.receiptAcceptedAlgs } : {}),
    });
    return receiptKeys;
  }
  // A misconfigured signer (algorithm off the accepted list, or a custom
  // signer with no matching verification key) fails createServer, not the
  // first delegation.
  if (config.receiptSigner || config.receiptSigningKeyPem || config.receiptAcceptedAlgs || config.receiptVerificationKeys) {
    getReceiptKeys();
  }
  // Known limitation: a static agent token carries no user, so on the legacy
  // routes the user comes from the request's user_id. With more than one user,
  // anyone holding the token can name any of them. A single-user deployment, or
  // an agentRequestVerifier that binds each principal to its user, is not affected.
  if (config.agentToken && !config.agentRequestVerifier && !singleUserMode) {
    console.warn('[cred] One static AGENT_TOKEN serves every user on this server: the legacy routes take the user from the request\'s user_id, so anyone holding the token can act for any user. Run one server per user with SINGLE_USER_MODE=true, or bind each agent to its user with an agentRequestVerifier.');
  }
  if (allowRawTokens) {
    console.warn('[cred] DEPRECATED: CRED_ALLOW_RAW_TOKENS=true hands provider access tokens to callers. A raw token is a bearer credential with the connection\'s full scope that the server can neither bind to an agent key nor revoke per delegation. Use brokered handles; this setting will be removed.');
  }
  if (config.vaultStorage === 'file' && !allowAgentsWithoutPermission) {
    console.warn('[cred] VAULT_STORAGE=file cannot store Permissions, so every agent is refused a delegation. Move to VAULT_STORAGE=sqlite (connect providers again there), or set the deprecated CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true to keep issuing without them.');
  }
  if (allowAgentsWithoutPermission) {
    console.warn('[cred] DEPRECATED: CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true issues delegations to agents that hold no Permission, up to the whole connection, so any did:key presented with the agent token can act for the user. A revocation still holds: while one is in force on a service and user, a did:key with no agent record is refused there too, but a revoked agent can otherwise come back under a registered key. Grant each agent a Permission at POST /admin/permissions; this setting will be removed.');
  }
  if (!classifyBrokerCalls) {
    console.warn('[cred] DEPRECATED: CRED_ALLOW_UNCLASSIFIED_BROKER_CALLS=true forwards brokered calls without checking them against the grant, so a read-only scope can reach a write endpoint on an allowed host. Remove it, and map any call that needs mapping; this setting will be removed.');
  }
  if (allowRedelegationAfterRevocation) {
    console.warn('[cred] DEPRECATED: CRED_ALLOW_REDELEGATION_AFTER_REVOCATION=true lets an agent whose delegation or Permission was revoked ask again at once, so a revocation does not hold. Re-grant at POST /admin/permissions instead; this setting will be removed.');
  }
  if (config.receiptTtlSeconds !== undefined
    && (!Number.isInteger(config.receiptTtlSeconds) || config.receiptTtlSeconds <= 0 || config.receiptTtlSeconds > MAX_RECEIPT_TTL_SECONDS)) {
    throw new Error(`receiptTtlSeconds must be a positive integer of at most ${MAX_RECEIPT_TTL_SECONDS} (1 hour)`);
  }
  if ((config as unknown as Record<string, unknown>).requireDpop !== undefined) {
    console.warn('[cred] requireDpop is ignored: every delegation, Cred Link\'s included, is a Delegation Token bound to the agent\'s key (DPoP). Remove the setting.');
  }
  const consentRetentionDays = config.consentRetentionDays ?? 90;
  if (!Number.isInteger(consentRetentionDays) || consentRetentionDays < 90) {
    throw new Error('consentRetentionDays (CONSENT_RETENTION_DAYS) must be an integer of at least 90: the draft keeps consent records at least 90 days');
  }
  if (config.cibaConsentTtlSeconds !== undefined && (!Number.isInteger(config.cibaConsentTtlSeconds) || config.cibaConsentTtlSeconds <= 0)) {
    throw new Error('cibaConsentTtlSeconds must be a positive integer');
  }
  if (config.requireAgentIdentity === false) {
    console.warn('[cred] CRED_REQUIRE_AGENT_IDENTITY=false is ignored: /api/v1/subdelegate always requires the delegating agent\'s actor_token, so a leaked receipt cannot mint a Delegation Token. This setting will be removed.');
  }

  function getReceiptTtlSeconds(): number {
    return config.receiptTtlSeconds ?? DEFAULT_RECEIPT_TTL_SECONDS;
  }

  /**
   * A handle lives no longer than the provider token it brokers and no
   * longer than a receipt (15 minutes by default, 1 hour at most).
   */
  function handleLifetimeSeconds(providerExpiresAt: Date | undefined | null): number {
    const cap = getReceiptTtlSeconds();
    if (!providerExpiresAt) return cap;
    return Math.max(1, Math.min(cap, Math.floor((providerExpiresAt.getTime() - Date.now()) / 1000)));
  }

  function getReceiptAudience(): string | undefined {
    return config.receiptAudience ?? config.redirectBaseUri ?? undefined;
  }

  function createReceipt(input: {
    agentDid: string;
    service: string;
    userId: string;
    appClientId: string;
    scopes: string[];
    delegationId: string;
    chainDepth: number;
    parentDelegationId?: string;
    parentReceiptHash?: string;
    receiptClaims?: string[];
    /**
     * DIDs of every ancestor above `agentDid` in the delegation chain,
     * oldest (root) first — i.e. the parent's own `lineage` plus the
     * parent's DID. Carried forward (and re-signed) at every hop so that
     * `/api/v1/subdelegate` can check the live status of the *entire*
     * chain, not just the immediate parent, without needing a persisted
     * delegation-chain store: the signed receipt chain itself is the
     * source of truth, since only the trusted issuer can add to it.
     */
    lineage?: string[];
    /**
     * Constraint ceilings that travel with the receipt and narrow
     * monotonically down the chain (asor-01 sections 4.2/4.3). Already
     * validated by the caller (parseConstraints). Omitted or empty means
     * the receipt carries no ceilings.
     */
    constraints?: DelegationConstraint[];
    /**
     * Upper bound on this receipt's `exp`, in Unix seconds. Sub-delegation
     * passes the parent's expiry here so a child receipt can never outlive
     * the receipt it was derived from (monotonic expiry down the chain).
     */
    expiresAtSecondsCeiling?: number;
    /**
     * Set when the hop also issued a token under the Chain-Verifiable
     * Profile: the receipt records that token's jti and how the delegated
     * scopes map onto its scope strings.
     */
    chainProfile?: { format: 'agent_delegation'; jti: string; scopeMapping: 'identity' };
  }): string {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const aud = getReceiptAudience();
    const ttlExp = nowSeconds + getReceiptTtlSeconds();
    const exp = typeof input.expiresAtSecondsCeiling === 'number'
      ? Math.min(ttlExp, input.expiresAtSecondsCeiling)
      : ttlExp;
    // Who the receipt names. draft-02 layout (the default), per
    // draft-sweeney-wimse-credential-delegation-02 "Delegation Token Format"
    // and draft-ietf-wimse-aims Section 10.3: the principal in `sub`, the
    // acting agent in `client_id` and `act.sub`, the prior agents in nested
    // `act` (attribution only), the delegation id as `jti`, and `cnf` bound
    // to the agent's did:key. The legacy layout keeps the agent in `sub`.
    // readReceiptActor() reads both.
    const cnf = didKeyConfirmation(input.agentDid);
    const actor = (config.receiptClaimLayout ?? 'draft-02') === 'draft-02'
      ? {
          ...receiptActorClaims({ principal: input.userId, agentDid: input.agentDid, priorActors: input.lineage }),
          jti: input.delegationId,
          ...(cnf ? { cnf } : {}),
        }
      : { sub: input.agentDid, client_id: input.agentDid };
    const payload = {
      // The Delegation Server's identifier (Section 5.1 of the draft): the
      // same value its chain-verifiable tokens carry in iss.
      iss: config.redirectBaseUri,
      ...actor,
      iat: nowSeconds,
      exp,
      ...(aud ? { aud } : {}),
      service: input.service,
      scopes: input.scopes,
      userId: input.userId,
      appClientId: input.appClientId,
      delegationId: input.delegationId,
      chainDepth: input.chainDepth,
      ...(input.receiptClaims && input.receiptClaims.length > 0 ? { receiptClaims: input.receiptClaims } : {}),
      ...(input.parentDelegationId ? { parentDelegationId: input.parentDelegationId } : {}),
      ...(input.parentReceiptHash ? { parentReceiptHash: input.parentReceiptHash } : {}),
      ...(input.lineage && input.lineage.length > 0 ? { lineage: input.lineage } : {}),
      ...(input.constraints && input.constraints.length > 0 ? { constraints: input.constraints } : {}),
      ...(input.chainProfile ? { chain_profile: { format: input.chainProfile.format, jti: input.chainProfile.jti, scope_mapping: input.chainProfile.scopeMapping } } : {}),
    };
    return signCompactJws(payload, getReceiptKeys().signer, { typ: 'JWT' });
  }

  function parseAndVerifyReceipt(receipt: string): {
    /** The acting agent's DID (`act.sub`, or `sub` on a legacy receipt). */
    sub: string;
    service: string;
    scopes: string[];
    userId: string;
    appClientId: string;
    delegationId: string;
    chainDepth: number;
    receiptClaims: string[];
    /** Ancestor DIDs above `sub`, oldest (root) first. See createReceipt(). */
    lineage: string[];
    /** Validated ceilings carried by the receipt; empty on legacy receipts. */
    constraints: DelegationConstraint[];
    /** Unix seconds. Absent only on legacy receipts minted before these claims existed. */
    iat?: number;
    exp?: number;
  } {
    const parts = receipt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid receipt format');
    }

    const payloadB64 = parts[1];

    // Verify signature: header alg on the accepted list and equal to the
    // algorithm of the key its kid names (receipt-signing.ts).
    if (checkReceiptSignature(receipt, getReceiptKeys()) !== null) {
      throw new Error('Invalid receipt signature');
    }

    // Strict JSON: a duplicate member or an integer outside the binary64
    // exact range makes the receipt invalid, never last-value-wins or
    // silently rounded (RFC 7493 Section 2.2 and 2.3; RFC 8785).
    // The field reads below were written against an untyped JSON.parse
    // result and validate each claim they use; keep that contract.
    let payload: Record<string, any>;
    try {
      const parsedPayload = parseStrictJson(Buffer.from(payloadB64, 'base64url').toString('utf8'));
      if (typeof parsedPayload !== 'object' || parsedPayload === null || Array.isArray(parsedPayload)) {
        throw new Error('Receipt payload is not a JSON object');
      }
      payload = parsedPayload as Record<string, any>;
    } catch (err) {
      if (err instanceof StrictJsonError) throw new Error(`Receipt payload is malformed (${err.code}): ${err.message}`);
      throw err;
    }
    const legacyIssuer = payload.iss === LEGACY_RECEIPT_ISSUER
      && typeof payload.iat === 'number' && payload.iat <= startedAtSeconds;
    if (payload.iss !== config.redirectBaseUri && !legacyIssuer) {
      throw new Error('Receipt was not issued by this Delegation Server');
    }
    if (!payload.delegationId) {
      throw new Error('Receipt is missing delegationId');
    }
    const actor = readReceiptActor(payload);
    if (!actor.ok) {
      throw new Error(`Receipt actor claims are malformed: ${actor.message}`);
    }

    // Constraint ceilings fail closed (asor-01 section 4.2): a receipt
    // whose constraints claim does not parse is invalid outright, before
    // any subsumption is evaluated. Absent parses to an empty list.
    const parsedConstraints = parseConstraints(payload.constraints);
    if (!parsedConstraints.ok) {
      throw new Error(`Receipt constraints are malformed: ${parsedConstraints.message}`);
    }

    // Expiry enforcement. Receipts minted with an `exp` claim are rejected
    // once they age past it (with a small allowance for clock skew).
    // Legacy receipts (minted before `exp` existed) fall back to aging out
    // based on `iat` + the configured receipt TTL, so they don't live
    // forever.
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number') {
      if (nowSeconds > payload.exp + RECEIPT_CLOCK_SKEW_SECONDS) {
        throw new Error('Receipt has expired');
      }
    } else if (typeof payload.iat === 'number') {
      if (nowSeconds > payload.iat + getReceiptTtlSeconds()) {
        throw new Error('Receipt has expired');
      }
    }

    return {
      // The acting agent: act.sub on draft-02 receipts, sub on legacy ones.
      sub: actor.agentDid,
      service: payload.service,
      scopes: payload.scopes ?? [],
      userId: actor.principal,
      appClientId: payload.appClientId ?? 'local',
      delegationId: payload.delegationId,
      chainDepth: payload.chainDepth ?? 0,
      receiptClaims: Array.isArray(payload.receiptClaims)
        ? payload.receiptClaims.filter((claim: unknown): claim is string => typeof claim === 'string' && claim.trim().length > 0)
        : [],
      // Legacy receipts (minted before this claim existed) carry no lineage
      // — they degrade to a parent-only ancestor check at the next hop
      // (see the subdelegate route), which naturally self-heals as those
      // receipts age out under the receipt TTL.
      lineage: Array.isArray(payload.lineage)
        ? payload.lineage.filter((did: unknown): did is string => typeof did === 'string' && did.trim().length > 0)
        : [],
      constraints: parsedConstraints.constraints,
      ...(typeof payload.iat === 'number' ? { iat: payload.iat } : {}),
      ...(typeof payload.exp === 'number' ? { exp: payload.exp } : {}),
    };
  }

  /**
   * The instant a parent receipt stops being valid, in Unix seconds, as the
   * bound for any child minted from it. Receipts carry `exp`; legacy receipts
   * without one age out at `iat` + the configured receipt TTL, which is the
   * same rule parseAndVerifyReceipt() applies when checking them.
   */
  function receiptExpiryBound(parent: { iat?: number; exp?: number }): number | undefined {
    if (typeof parent.exp === 'number') return parent.exp;
    if (typeof parent.iat === 'number') return parent.iat + getReceiptTtlSeconds();
    return undefined;
  }

  // ── Chain-Verifiable Profile ──────────────────────────────────────────────
  // draft-sweeney-wimse-credential-delegation-02 "Chain-Verifiable Profile":
  // on request (`token_profile: "agent_delegation"`), a hop also yields a
  // token in the draft-asor-wimse-agent-delegation-chain-02 Delegation Chain
  // format, unchanged, that a party holding only the chain can verify. The
  // receipt records its jti (the delegation id) and that the delegated
  // scope strings are used as the token's scopes as they are.

  type ChainProfileRequest =
    | { ok: true; wanted: false }
    | { ok: true; wanted: true; audience: string | string[]; delMaxDepth?: number }
    | { ok: false; body: Record<string, unknown> };

  function chainProfileRequest(body: Record<string, unknown> | undefined, agentDid: unknown): ChainProfileRequest {
    const profile = body?.token_profile;
    if (profile === undefined) return { ok: true, wanted: false };
    if (profile !== 'agent_delegation') {
      return { ok: false, body: { error: 'invalid_request', message: "token_profile must be 'agent_delegation'" } };
    }
    if (typeof agentDid !== 'string' || !didKeyConfirmation(agentDid)) {
      return { ok: false, body: { error: 'invalid_request', message: 'token_profile agent_delegation needs agent_did to be an Ed25519 or P-256 did:key, so the token can carry cnf' } };
    }
    const audience = body?.audience ?? getReceiptAudience() ?? config.redirectBaseUri;
    const audienceOk = typeof audience === 'string' ? audience !== ''
      : Array.isArray(audience) && audience.length > 0 && audience.every((a) => typeof a === 'string' && a !== '');
    if (!audienceOk) {
      return { ok: false, body: { error: 'invalid_request', message: 'audience must be a string or a non-empty array of strings' } };
    }
    const maxDepth = body?.max_depth;
    if (maxDepth !== undefined && (!Number.isSafeInteger(maxDepth) || (maxDepth as number) < 0)) {
      return { ok: false, body: { error: 'invalid_request', message: 'max_depth must be a non-negative integer' } };
    }
    return {
      ok: true,
      wanted: true,
      audience: audience as string | string[],
      ...(maxDepth !== undefined ? { delMaxDepth: (maxDepth as number) + 1 } : {}),
    };
  }

  /** Default leaf depth bound for a root token: the draft's RECOMMENDED chain depth of 5. */
  const DEFAULT_CHAIN_PROFILE_MAX_DEPTH = 5;

  function mintChainProfileToken(input: {
    receipt: string;
    agentDid: string;
    userId: string;
    scopes: string[];
    constraints: DelegationConstraint[];
    delegationId: string;
    audience: string | string[];
    delMaxDepth?: number;
    /** The verified parent token, for a child. */
    parentToken?: string;
    /** Tightest del_max_depth in the parent's verified chain. */
    chainDepthBound?: number;
  }): { ok: true; token: string } | { ok: false; body: Record<string, unknown> } {
    const receiptPayload = JSON.parse(Buffer.from(input.receipt.split('.')[1]!, 'base64url').toString('utf8')) as { iat: number; exp: number };
    const cnf = didKeyConfirmation(input.agentDid);
    if (!cnf) return { ok: false, body: { error: 'invalid_request', message: 'agent_did is not a did:key' } };
    try {
      const token = mintAgentDelegationToken({
        signer: getReceiptKeys().signer,
        iss: config.redirectBaseUri,
        sub: input.userId,
        clientId: input.agentDid,
        aud: input.audience,
        cnf,
        jti: input.delegationId,
        iat: receiptPayload.iat,
        exp: receiptPayload.exp,
        scopes: input.scopes,
        constraints: input.constraints,
        ...(input.parentToken ? { parent: input.parentToken } : {}),
        ...(input.chainDepthBound !== undefined ? { chainDepthBound: input.chainDepthBound } : {}),
        ...(input.delMaxDepth !== undefined
          ? { delMaxDepth: input.delMaxDepth }
          : input.parentToken ? {} : { delMaxDepth: DEFAULT_CHAIN_PROFILE_MAX_DEPTH + 1 }),
      });
      return { ok: true, token };
    } catch (err) {
      if (err instanceof AgentDelegationMintError) {
        return { ok: false, body: { error: 'chain_profile_unavailable', reason: err.reason, message: `This delegation cannot be expressed as an agent_delegation token: ${err.message}` } };
      }
      throw err;
    }
  }

  /**
   * Verify a presented agent_delegation chain (root first) that ends in the
   * token for `parent`, under this server's own keys, before a child token
   * is minted from it.
   */
  function verifyParentChainProfile(chain: unknown, parent: { delegationId: string; sub: string; userId: string }):
    { ok: true; parentToken: string; depthBound: number } | { ok: false; body: Record<string, unknown> } {
    if (!Array.isArray(chain) || chain.length === 0 || chain.some((t) => typeof t !== 'string')) {
      return { ok: false, body: { error: 'invalid_request', message: 'agent_delegation_chain must be the parent\'s agent_delegation token chain, root first' } };
    }
    const keys = getReceiptKeys();
    const verified = verifyAgentDelegationChain(chain, { acceptedAlgs: keys.acceptedAlgs, resolveKey: keys.resolveKey });
    if (!verified.ok) {
      return { ok: false, body: { error: 'invalid_parent_chain', reason: verified.reason, hop: verified.hop, message: verified.message } };
    }
    if (verified.leaf.claims.jti !== parent.delegationId || verified.actingAgent !== parent.sub || verified.principal !== parent.userId) {
      return { ok: false, body: { error: 'invalid_parent_chain', message: 'agent_delegation_chain does not end in the token issued with parent_receipt' } };
    }
    return { ok: true, parentToken: chain[chain.length - 1] as string, depthBound: verified.depthBound };
  }

  function extractTrustedReceiptClaims(req: Request): string[] | undefined {
    const principal = (req as any).agentPrincipal as RequestAgentPrincipal | undefined;
    const rawClaims = principal?.metadata?.receiptClaims;
    if (!Array.isArray(rawClaims)) {
      return undefined;
    }
    const claims = rawClaims
      .filter((claim): claim is string => typeof claim === 'string' && claim.trim().length > 0);
    return claims.length > 0 ? claims : undefined;
  }

  const attachParentReceiptClaimsForGuard: express.RequestHandler = (req, res, next) => {
    const parentReceipt = req.body?.parent_receipt;
    if (typeof parentReceipt !== 'string' || parentReceipt.trim() === '') {
      next();
      return;
    }
    try {
      const parent = parseAndVerifyReceipt(parentReceipt);
      (req as any).verifiedParentReceipt = parent;
      req.body = {
        ...(req.body ?? {}),
        receipt_claims: parent.receiptClaims,
        metadata: {
          ...((req.body?.metadata && typeof req.body.metadata === 'object') ? req.body.metadata : {}),
          receiptClaims: parent.receiptClaims,
        },
      };
      next();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Invalid receipt';
      res.status(403).json({ error: message });
    }
  };

  // ── Routes ─────────────────────────────────────────────────────────────────

  /**
   * GET /health — liveness check
   */
  app.get('/.well-known/http-message-signatures-directory', directoryRateLimiter, async (_req: Request, res: Response) => {
    try {
      const directory = await buildWebBotAuthDirectory();
      const authority = _req.get('host') ?? new URL(config.redirectBaseUri).host;
      const signatureHeaders = createDirectorySignatureHeaders(authority);
      res
        .type('application/http-message-signatures-directory+json')
        .set(signatureHeaders)
        .status(200)
        .json(directory);
    } catch (err) {
      console.error('[/\\.well-known/http-message-signatures-directory] Error:', err);
      res.status(500).json({ error: 'Failed to build Web Bot Auth directory' });
    }
  });

  /**
   * GET /health — liveness check
   */
  app.get('/health', healthRateLimiter, (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      providers: config.providers.map((p) => p.slug),
      vault: config.vaultStorage,
      tofu: config.tofuStorage,
    });
  });

  app.get('/admin/login', connectUiRateLimiter, (req: Request, res: Response) => {
    const nextPath = queryStringValue(req.query.next) ?? '/connect';
    const safeNext = escapeHtml(safeRelativePath(nextPath));
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cred Admin Login</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background:#0a0a0a; color:#e0e0e0; min-height:100vh; display:grid; place-items:center; margin:0; }
  form { width:min(360px, calc(100vw - 32px)); display:grid; gap:14px; }
  h1 { font-size:22px; margin:0 0 4px; }
  label { display:grid; gap:6px; font-size:13px; color:#999; }
  input { padding:10px 12px; border-radius:6px; border:1px solid #333; background:#141414; color:#fff; font-family:monospace; }
  button { padding:10px 14px; border:0; border-radius:6px; background:#166534; color:#fff; font-weight:600; cursor:pointer; }
</style>
</head>
<body>
<form method="POST" action="/admin/login">
  <h1>Cred Admin</h1>
  <input type="hidden" name="next" value="${safeNext}">
  <label>Admin token
    <input name="admin_token" type="password" autocomplete="current-password" autofocus required>
  </label>
  <button type="submit">Sign in</button>
</form>
</body>
</html>`);
  });

  app.post('/admin/login', connectUiRateLimiter, (req: Request, res: Response) => {
    const token = typeof req.body?.admin_token === 'string' ? req.body.admin_token.trim() : '';
    const nextPathRaw = typeof req.body?.next === 'string' ? req.body.next : '/connect';
    const nextPath = safeRelativePath(nextPathRaw);

    if (!token || !tokenMatchesHash(token, adminTokenHash)) {
      res.status(401).send('Unauthorized');
      return;
    }

    res.setHeader('Referrer-Policy', 'no-referrer');
    setAdminSessionCookie(res);
    res.redirect(303, nextPath);
  });

  /**
   * GET /providers — list configured providers and connection status
   */
  app.get('/providers', providersRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const userId = adminPageUserId(req, res, req.accepts(['json', 'html']) === 'html');
      if (userId === null) return;
      const entries = await vault.list({ userId });
      const connected = new Set(entries.map((e) => e.provider));

      const providers = config.providers.map((p) => ({
        slug: p.slug,
        connected: connected.has(p.slug),
      }));

      res.json({ providers });
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/providers] Error:', err);
      res.status(500).json({ error: 'Failed to list providers' });
    }
  });

  const PERMISSION_STORAGE_NOT_SUPPORTED_MESSAGE =
    'Permission storage not supported by this vault backend. This deployment must use vaultStorage: "sqlite".';

  /**
   * Parses an optional `expiresAt` request-body field into a Date, or throws
   * a plain Error with a 400-worthy message on an unparseable value. Unlike
   * `new Date(value)` alone, this rejects invalid-date strings up front
   * instead of letting an Invalid Date reach vault.createPermission /
   * updatePermission, where `.toISOString()` throws a RangeError that
   * mapPermissionErrorResponse doesn't recognize and surfaces as an opaque
   * 500.
   */
  function parseOptionalExpiresAt(value: string | null | undefined): Date | undefined {
    if (!value) return undefined;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      throw new Error(`expiresAt is not a valid date: ${value}`);
    }
    return parsed;
  }

  /**
   * With Link enabled, a Permission on a Link connection (conn_ id) may only
   * hold scopes within that connection's grant (spec 3). Sends 400 and
   * returns false otherwise. Legacy connection ids (provider slugs) pass.
   */
  async function linkPermissionScopesAllowed(res: Response, connectionId: string, scopes: string[]): Promise<boolean> {
    if (!linkService || !isConnectionId(connectionId)) return true;
    const grant = await linkService.context.store.getGrantForConnection(connectionId);
    if (!grant || !isScopeSubset(scopes, grant.scopes)) {
      res.status(400).json({ error: 'invalid_scope', message: 'allowedScopes must be within the Link connection grant' });
      return false;
    }
    return true;
  }

  function mapPermissionErrorResponse(res: Response, err: unknown, fallbackMessage: string): void {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('not supported')) {
      res.status(501).json({ error: PERMISSION_STORAGE_NOT_SUPPORTED_MESSAGE });
      return;
    }
    if (message.includes('not found')) {
      res.status(404).json({ error: 'Permission not found' });
      return;
    }
    if (message.includes('not a valid date')) {
      res.status(400).json({ error: message });
      return;
    }
    console.error(`[admin/permissions] Error:`, err);
    res.status(500).json({ error: fallbackMessage });
  }

  /**
   * POST /admin/permissions — create a Permission record (admin-authenticated).
   *
   * Permission records enforce an agent's scope ceiling, rate limit, TTL
   * override, and delegation depth for a given connection — this is the
   * only way to manage them without reaching into @credninja/vault
   * directly. Sqlite-only: the file storage backend has no Permission
   * support, so an operator on the file backend gets an explicit 501 (see
   * mapPermissionErrorResponse) rather than a generic 500 on first use.
   */
  app.post('/admin/permissions', adminPermissionsRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const body = (req.body ?? {}) as {
        agentId?: unknown;
        connectionId?: unknown;
        allowedScopes?: unknown;
        rateLimit?: { maxRequests: number; windowMs: number } | null;
        ttlOverride?: number | null;
        requiresApproval?: boolean;
        approver?: 'subject' | 'admin' | 'both';
        delegatable?: boolean;
        maxDelegationDepth?: number;
        expiresAt?: string | null;
        createdBy?: unknown;
      };

      if (typeof body.agentId !== 'string' || !body.agentId) {
        res.status(400).json({ error: 'agentId is required' });
        return;
      }
      if (typeof body.connectionId !== 'string' || !body.connectionId) {
        res.status(400).json({ error: 'connectionId is required' });
        return;
      }
      if (!Array.isArray(body.allowedScopes) || !body.allowedScopes.every((s) => typeof s === 'string')) {
        res.status(400).json({ error: 'allowedScopes must be an array of strings' });
        return;
      }

      if (!(await linkPermissionScopesAllowed(res, body.connectionId, body.allowedScopes))) return;
      if (body.approver !== undefined && !['subject', 'admin', 'both'].includes(body.approver)) {
        res.status(400).json({ error: "approver must be 'subject', 'admin' or 'both'" });
        return;
      }

      // Replacing a row replaces all of it, so a re-grant that does not mention an
      // approval gate or rate limit would drop it silently. Restoring keeps them.
      const replaced = await getPermissionIfSupported(body.agentId, body.connectionId);
      const wouldDrop = !replaced ? [] : [
        ...(replaced.requiresApproval && body.requiresApproval === undefined ? ['requiresApproval'] : []),
        ...(replaced.rateLimit && !('rateLimit' in body) ? ['rateLimit'] : []),
        ...(replaced.expiresAt && !('expiresAt' in body) ? ['expiresAt'] : []),
        ...(replaced.ttlOverride !== undefined && !('ttlOverride' in body) ? ['ttlOverride'] : []),
        ...((replaced.approver === 'admin' || replaced.approver === 'both') && body.approver === undefined ? ['approver'] : []),
      ];
      if (wouldDrop.length > 0) {
        res.status(409).json({
          error: 'permission_limits_would_drop',
          message: `This would replace a Permission and drop its ${wouldDrop.join(', ')}. Name them in the body to change them. Replacing also ends the live delegations issued under the old row, which must ask again. To end a hold and keep both the limits and those delegations, POST /admin/permissions/${replaced!.id}/restore.`,
          fields: wouldDrop,
        });
        return;
      }

      if (invalidRateLimit(body.rateLimit)) {
        res.status(400).json({ error: 'invalid_rate_limit', message: 'rateLimit needs maxRequests and windowMs as positive whole numbers' });
        return;
      }
      const permission = await vault.createPermission({
        agentId: body.agentId,
        connectionId: body.connectionId,
        allowedScopes: body.allowedScopes,
        rateLimit: body.rateLimit ?? undefined,
        ttlOverride: body.ttlOverride ?? undefined,
        requiresApproval: body.requiresApproval ?? false,
        ...(body.approver ? { approver: body.approver } : {}),
        delegatable: body.delegatable ?? false,
        maxDelegationDepth: body.maxDelegationDepth ?? 1,
        expiresAt: parseOptionalExpiresAt(body.expiresAt),
        createdBy: typeof body.createdBy === 'string' && body.createdBy ? body.createdBy : 'admin',
      });
      // Granting ends a revocation of this agent on this connection, under
      // whichever of its ids (record id or DID) the revocation named.
      const regranted = await vault.clearAgentRevocations(await agentIdsOf(permission.agentId), permission.connectionId);

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'system', id: 'admin' },
        action: 'create',
        resource: { type: 'permission', id: permission.id },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
        metadata: { agentId: permission.agentId, connectionId: permission.connectionId, ...(regranted > 0 ? { revocationsEnded: regranted } : {}) },
      });

      res.status(201).json({ permission });
    } catch (err) {
      mapPermissionErrorResponse(res, err, 'Failed to create permission');
    }
  });

  /**
   * GET /admin/permissions — list permissions for an agent, or fetch a
   * single permission for an agent/connection pair (admin-authenticated).
   *
   * Mirrors CredVault.listPermissions(agentId) / getPermission(agentId,
   * connectionId) exactly — query-param shaped rather than an `/:id` lookup,
   * since neither underlying vault method supports fetching a permission by
   * id alone.
   */
  app.get('/admin/permissions', adminPermissionsRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const agentId = queryStringValue(req.query.agent_id);
      const connectionId = queryStringValue(req.query.connection_id);

      if (!agentId) {
        res.status(400).json({ error: 'agent_id query parameter is required' });
        return;
      }

      if (connectionId) {
        const permission = await vault.getPermission(agentId, connectionId);
        if (!permission) {
          res.status(404).json({ error: 'Permission not found' });
          return;
        }
        res.json({ permission });
        return;
      }

      const permissions = await vault.listPermissions(agentId);
      res.json({ permissions });
    } catch (err) {
      mapPermissionErrorResponse(res, err, 'Failed to list permissions');
    }
  });

  /**
   * PATCH /admin/permissions/:id — update an existing Permission record
   * (admin-authenticated).
   *
   * Narrowing allowedScopes constrains future delegations, and POST /api/v1/use
   * re-reads the Permission on each exercise, so it reaches live ones too.
   */
  app.patch('/admin/permissions/:id', adminPermissionsRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const id = routeParam(req.params.id);
      if (!id) {
        res.status(400).json({ error: 'Missing permission id' });
        return;
      }

      const body = (req.body ?? {}) as {
        allowedScopes?: string[];
        rateLimit?: { maxRequests: number; windowMs: number } | null;
        ttlOverride?: number | null;
        requiresApproval?: boolean;
        approver?: 'subject' | 'admin' | 'both';
        delegatable?: boolean;
        maxDelegationDepth?: number;
        expiresAt?: string | null;
      };

      if ('allowedScopes' in body && linkService) {
        if (!Array.isArray(body.allowedScopes) || !body.allowedScopes.every((s) => typeof s === 'string')) {
          res.status(400).json({ error: 'allowedScopes must be an array of strings' });
          return;
        }
        // No read-by-id exists: an empty update returns the row (it only
        // bumps updatedAt) so its connectionId can be checked first.
        const current = await vault.updatePermission(id, {});
        if (!(await linkPermissionScopesAllowed(res, current.connectionId, body.allowedScopes))) return;
      }

      const input: UpdatePermissionInput = {};
      if ('allowedScopes' in body) input.allowedScopes = body.allowedScopes;
      if (invalidRateLimit(body.rateLimit)) {
        res.status(400).json({ error: 'invalid_rate_limit', message: 'rateLimit needs maxRequests and windowMs as positive whole numbers' });
        return;
      }
      if ('rateLimit' in body) input.rateLimit = body.rateLimit ?? undefined;
      if ('ttlOverride' in body) input.ttlOverride = body.ttlOverride ?? undefined;
      if ('requiresApproval' in body) input.requiresApproval = body.requiresApproval;
      if (body.approver !== undefined) {
        if (!['subject', 'admin', 'both'].includes(body.approver)) {
          res.status(400).json({ error: "approver must be 'subject', 'admin' or 'both'" });
          return;
        }
        // Stored with requiresApproval, so naming an approver keeps approval on.
        input.approver = body.approver;
        input.requiresApproval ??= true;
      }
      if ('delegatable' in body) input.delegatable = body.delegatable;
      if ('maxDelegationDepth' in body) input.maxDelegationDepth = body.maxDelegationDepth;
      if ('expiresAt' in body) input.expiresAt = parseOptionalExpiresAt(body.expiresAt);

      const before = input.requiresApproval === true ? await vault.getPermissionById(id) : null;
      const permission = await vault.updatePermission(id, input);

      // Turning approval on ends what was issued without it: a live token
      // would otherwise keep working until it expires. Consents and holds stay,
      // so an approved request can be issued again at once.
      let delegationsRevoked = 0;
      if (before && !before.requiresApproval && permission.requiresApproval) {
        const started = performance.now();
        const cause = `permission-approval:${id}`;
        const agentDids = (await agentIdsOf(permission.agentId)).filter((agentId) => agentId.startsWith('did:'));
        for (const agentDid of agentDids) {
          const cascade = await applyRevocation(await vault.revokeDelegations({ agentOnService: { agentDid, service: permission.connectionId } }), started, {
            actor: { type: 'system', id: 'admin' },
            correlationId: crypto.randomUUID(),
            cause,
          });
          delegationsRevoked += cascade.count;
        }
      }

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'system', id: 'admin' },
        action: 'update',
        resource: { type: 'permission', id },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
        metadata: { changed: Object.keys(input), ...(delegationsRevoked > 0 ? { delegationsRevoked } : {}) },
      });

      res.json({ permission });
    } catch (err) {
      mapPermissionErrorResponse(res, err, 'Failed to update permission');
    }
  });

  /**
   * DELETE /admin/permissions/:id — revoke a Permission record (admin-authenticated).
   *
   * The revocation holds: the agent's consents and live delegations on the
   * service are revoked, and it is issued nothing new there until it is granted a
   * Permission again at POST /admin/permissions.
   */
  app.delete('/admin/permissions/:id', adminPermissionsRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const id = routeParam(req.params.id);
      if (!id) {
        res.status(400).json({ error: 'Missing permission id' });
        return;
      }

      const started = performance.now();
      const correlationId = crypto.randomUUID();
      // A Permission that is gone authorizes nothing, including what it already
      // authorized: the agent's consents and live delegations on the service end
      // with it. The row goes last, so a call that fails can simply be repeated.
      const existing = await vault.getPermissionById(id);
      let delegationsRevoked = 0;
      if (existing) {
        const cause = `permission:${id}`;
        const agentDids = (await agentIdsOf(existing.agentId)).filter((agentId) => agentId.startsWith('did:'));
        for (const agentDid of agentDids) {
          await vault.revokeConsents({ agentDid, service: existing.connectionId }, cause);
          approvals.cancel({ agentDid, service: existing.connectionId }, 'permission_revoked');
          const cascade = await applyRevocation(await vault.revokeDelegations({ agentOnService: { agentDid, service: existing.connectionId } }, { hold: { cause } }), started, {
            actor: { type: 'system', id: 'admin' },
            correlationId,
            cause,
          });
          delegationsRevoked += cascade.count;
        }
      }
      const removed = await vault.revokePermission(id);

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'system', id: 'admin' },
        action: 'revoke',
        resource: { type: 'permission', id },
        outcome: 'success',
        correlationId,
        ...(removed ? { metadata: { agentId: removed.agentId, connectionId: removed.connectionId, delegationsRevoked } } : {}),
      });

      res.status(204).send();
    } catch (err) {
      mapPermissionErrorResponse(res, err, 'Failed to revoke permission');
    }
  });

  /**
   * POST /admin/permissions/:id/restore — end the holds on this Permission's
   * agent, for one user (`user_id`) or all, leaving the Permission exactly as it
   * is. The way back for a revoked delegation. A revoked Permission has no row to
   * restore: grant it again at POST /admin/permissions.
   */
  app.post('/admin/permissions/:id/restore', adminPermissionsRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const id = routeParam(req.params.id);
      const permission = id ? await vault.getPermissionById(id) : null;
      if (!permission) {
        res.status(404).json({ error: 'permission_not_found', message: 'No such Permission. A revoked one is granted again at POST /admin/permissions.' });
        return;
      }
      const userId = (req.body as { user_id?: unknown } | undefined)?.user_id;
      if (userId !== undefined && (typeof userId !== 'string' || !userId)) {
        res.status(400).json({ error: 'invalid_request', message: 'user_id must be a non-empty string' });
        return;
      }
      const ended = await vault.clearAgentRevocations(await agentIdsOf(permission.agentId), permission.connectionId, userId ? { userId } : {});
      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'system', id: 'admin' },
        action: 'update',
        resource: { type: 'permission', id: permission.id },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
        metadata: { stage: 'holds_ended', count: ended, ...(userId ? { userId } : {}) },
      });
      res.json({ holds_ended: ended, permission });
    } catch (err) {
      mapPermissionErrorResponse(res, err, 'Failed to restore permission');
    }
  });

  /** GET /admin/agent-holds — the revocations holding agents out (agent_id, service, user_id filters). */
  app.get('/admin/agent-holds', adminPermissionsRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const agentId = queryStringValue(req.query.agent_id);
      const service = queryStringValue(req.query.service);
      const userId = queryStringValue(req.query.user_id);
      const holds = await vault.listAgentRevocations({
        ...(agentId ? { agentIds: await agentIdsOf(agentId) } : {}),
        ...(service ? { service } : {}),
        ...(userId ? { userId } : {}),
      });
      res.json({ holds: holds.map((hold) => ({ agent_id: hold.agentId, service: hold.service, user_id: hold.userId, cause: hold.cause, revoked_at: hold.revokedAt })) });
    } catch (err) {
      mapPermissionErrorResponse(res, err, 'Failed to list holds');
    }
  });

  /**
   * GET /admin/audit — query audit events across ALL agents/users
   * (admin-authenticated).
   *
   * These are new routes, not modifications to the existing agent-facing
   * GET /api/v1/audit — that route continues to scope results to a single
   * `userId` exactly as before. This admin route reads the same underlying
   * vault instance (no new storage plumbing) but applies no userId
   * scoping, so an operator can see the full cross-agent audit trail.
   * Supports the same `service`/`limit` filters as the agent-facing route.
   */
  // Recompute the tamper-evident audit chain and report its head, so an
  // operator can record the head somewhere this host cannot rewrite.
  app.get('/admin/audit/verify', adminAuditRateLimiter, requireAdminAuth, (_req: Request, res: Response) => {
    let result;
    try {
      result = vault.verifyAuditChain();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('not supported')) {
        res.status(501).json({ error: 'audit_chain_unsupported', message });
        return;
      }
      console.error('Audit chain verification failed:', message);
      res.status(500).json({ error: 'audit_chain_verify_failed' });
      return;
    }
    res.status(result.ok ? 200 : 409).json(result.ok ? result : { error: 'audit_chain_broken', ...result });
  });

  app.get('/admin/audit', adminAuditRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const service = typeof req.query.service === 'string' ? req.query.service : undefined;
      const limitRaw = typeof req.query.limit === 'string' ? req.query.limit : undefined;
      const limit = limitRaw ? Number.parseInt(limitRaw, 10) : 50;

      if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
        res.status(400).json({ error: 'Invalid limit: must be between 1 and 200' });
        return;
      }

      let events;
      try {
        events = vault.queryAuditEvents({ limit });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('not supported')) {
          res.status(501).json({ error: 'Audit query not supported by this vault backend' });
          return;
        }
        throw err;
      }

      const entries = events
        .filter((event) => {
          if (!service) return true;
          return auditEventService(event.resource.id) === service;
        })
        .map((event) => {
          const eventService = auditEventService(event.resource.id);
          const eventUserId = event.resource.id.split('/')[1];
          return {
            id: event.id,
            action: event.action,
            resourceType: event.resource.type,
            service: eventService || event.resource.type,
            userId: eventUserId ?? null,
            actor: event.actor,
            timestamp: event.timestamp.toISOString(),
            metadata: buildAuditEntryMetadata(event),
          };
        });

      res.json({ entries });
    } catch (err) {
      console.error('[/admin/audit] Error:', err);
      res.status(500).json({ error: 'Failed to fetch audit log' });
    }
  });

  /**
   * GET /admin/agents — list registered agent identities with their status
   * (admin-authenticated).
   *
   * This is the admin-authenticated equivalent of the existing
   * agent-facing GET /api/v1/web-bot-auth/keys route — same TOFU identity
   * registry, same response shape (mapAgentToWebBotAuthKey), just reachable
   * without holding an agent Bearer token. The agent-facing route is
   * unchanged.
   */
  app.get('/admin/agents', adminAgentsRateLimiter, requireAdminAuth, async (_req: Request, res: Response) => {
    try {
      const agents = await tofu.listAgents();
      res.json({
        keys: agents.map((agent) => mapAgentToWebBotAuthKey(agent)),
      });
    } catch (err) {
      console.error('[/admin/agents] Error:', err);
      res.status(500).json({ error: 'Failed to list agent identities' });
    }
  });

  /**
   * DELETE /admin/agents/:agentId — revoke the target agent identity
   * (admin-authenticated).
   *
   * Mirrors POST /api/v1/agents/:agentId/revoke-all (vault-side, now
   * ownership-checked for agent-initiated revocation) but via admin auth
   * instead of requiring the agent to prove its own identity — an admin
   * can revoke ANY agent, which is the whole point of this route existing.
   * Writes a `revoke` audit event via writeAuditEventIfSupported, actor
   * recorded as the admin principal, matching the existing agent-facing
   * revoke route's action name — without this, an admin-initiated
   * revocation would leave no audit trail and would not appear on a
   * future observability unit's revoke-event stream.
   */
  app.delete('/admin/agents/:agentId', adminAgentsRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const agentIdParam = req.params.agentId;
      if (typeof agentIdParam !== 'string') {
        res.status(400).json({ error: 'agentId must be a string' });
        return;
      }
      const agentId = agentIdParam;
      const agent = await vault.getAgent(agentId);
      if (!agent) {
        res.status(404).json({ error: 'Agent not found' });
        return;
      }

      const started = performance.now();
      const correlationId = crypto.randomUUID();
      const actor: AuditActor = { type: 'system', id: 'admin' };
      const cascade = await applyRevocation(await vault.revokeAgentCascade(agentId, { hold: { cause: `agent:${agent.id}` } }), started, {
        actor,
        correlationId,
        cause: `agent:${agent.id}`,
      });

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor,
        action: 'revoke',
        resource: { type: 'agent', id: agent.id },
        outcome: 'success',
        correlationId,
        metadata: {
          agentDid: agent.did,
          revokedCount: cascade.count,
          elapsedMs: cascade.elapsedMs,
        },
      });

      res.status(204).send();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('not supported')) {
        res.status(501).json({ error: 'Agent storage not supported by this vault backend' });
        return;
      }
      console.error('[/admin/agents/:agentId] Error:', err);
      res.status(500).json({ error: 'Failed to revoke agent' });
    }
  });

  /**
   * GET /connect — Admin UI for managing provider connections
   *
   * Lists all configured providers with connection status, scope selection,
   * and connect/disconnect buttons.
   */
  app.get('/connect', connectUiRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const userId = adminPageUserId(req, res, true);
      if (userId === null) return;
      const safeUserId = escapeHtml(userId);
      const encodedUserId = encodeURIComponent(userId);
      const entries = await vault.list({ userId });
      const connected = new Map(entries.map((e) => [e.provider, e]));

      const COMMON_SCOPES: Record<string, { label: string; value: string }[]> = {
        google: [
          { label: 'OpenID', value: 'openid' },
          { label: 'Email', value: 'email' },
          { label: 'Profile', value: 'profile' },
          { label: 'Gmail (read)', value: 'gmail.readonly' },
          { label: 'Gmail (send)', value: 'gmail.send' },
          { label: 'Gmail (compose)', value: 'gmail.compose' },
          { label: 'Calendar (read)', value: 'calendar.readonly' },
          { label: 'Calendar (events)', value: 'calendar.events' },
          { label: 'Drive (read)', value: 'drive.readonly' },
          { label: 'Drive (full)', value: 'drive' },
          { label: 'Sheets', value: 'spreadsheets' },
          { label: 'Docs', value: 'documents' },
        ],
        github: [
          { label: 'Repos (public)', value: 'public_repo' },
          { label: 'Repos (all)', value: 'repo' },
          { label: 'User', value: 'user' },
          { label: 'Gists', value: 'gist' },
          { label: 'Notifications', value: 'notifications' },
          { label: 'Workflow', value: 'workflow' },
        ],
        slack: [
          { label: 'Chat (write)', value: 'chat:write' },
          { label: 'Channels (read)', value: 'channels:read' },
          { label: 'Users (read)', value: 'users:read' },
          { label: 'Files (write)', value: 'files:write' },
        ],
        notion: [
          // Notion takes no scopes: its capabilities are set on the integration.
          // These are what Cred's broker holds an agent to.
          { label: 'Read content', value: 'notion.read' },
          { label: 'Read and change content', value: 'content' },
        ],
        salesforce: [
          { label: 'API', value: 'api' },
          { label: 'Refresh token', value: 'refresh_token' },
        ],
        linear: [
          { label: 'Read', value: 'read' },
          { label: 'Write', value: 'write' },
          { label: 'Issues (create)', value: 'issues:create' },
        ],
        hubspot: [
          { label: 'CRM (objects)', value: 'crm.objects.contacts.read' },
          { label: 'CRM (write)', value: 'crm.objects.contacts.write' },
        ],
      };

      const providerCards = config.providers.map((p) => {
        const conn = connected.get(p.slug);
        const isConnected = !!conn;
        const scopes = COMMON_SCOPES[p.slug] ?? [];
        const defaultChecked = p.defaultScopes;
        const safeSlug = escapeHtml(p.slug);
        const encodedSlug = encodeURIComponent(p.slug);
        const currentScopes = conn?.scopes?.map((scope) => escapeHtml(scope)).join(', ');
        const safeScopeItems = scopes.map((s) => {
          const safeLabel = escapeHtml(s.label);
          const safeValue = escapeHtml(s.value);
          const isChecked = defaultChecked.includes(s.value) ? 'checked' : '';
          return `
                  <label class="scope-item">
                    <input type="checkbox" name="scope" value="${safeValue}" ${isChecked}>
                    <span class="scope-label">${safeLabel}</span>
                    <code class="scope-value">${safeValue}</code>
                  </label>
                `;
        }).join('');

        return `
          <div class="provider-card ${isConnected ? 'connected' : ''}">
            <div class="provider-header">
              <h3>${safeSlug}</h3>
              <span class="status ${isConnected ? 'status-ok' : 'status-none'}">
                ${isConnected ? '● Connected' : '○ Not connected'}
              </span>
            </div>
            ${isConnected && currentScopes ? `<div class="current-scopes">Current scopes: <code>${currentScopes}</code></div>` : ''}
            <form class="scope-form" action="/connect/${encodedSlug}/start" method="POST" data-provider="${safeSlug}" data-user-id="${safeUserId}">
              <div class="scope-grid">
                ${safeScopeItems}
              </div>
              <div class="custom-scope">
                <input type="text" name="customScopes" placeholder="Additional scopes (comma-separated)">
              </div>
              <div class="actions">
                <button type="submit" class="btn btn-connect">${isConnected ? 'Reconnect' : 'Connect'}</button>
                ${isConnected ? `<button type="button" class="btn btn-revoke" data-revoke-provider="${safeSlug}">Revoke</button>` : ''}
              </div>
            </form>
          </div>
        `;
      }).join('');

      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cred — Provider Connections</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #0a0a0a;
    color: #e0e0e0;
    padding: 32px 24px;
    min-height: 100vh;
  }
  .container { max-width: 720px; margin: 0 auto; }
  h1 { font-size: 24px; font-weight: 600; margin-bottom: 4px; }
  .subtitle { color: #888; font-size: 14px; margin-bottom: 32px; }
  .provider-card {
    background: #141414;
    border: 1px solid #222;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 20px;
    transition: border-color 0.2s;
  }
  .provider-card.connected { border-color: #1a3a2a; }
  .provider-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  .provider-header h3 {
    font-size: 18px;
    font-weight: 600;
    text-transform: capitalize;
  }
  .status { font-size: 13px; font-family: monospace; }
  .status-ok { color: #4ade80; }
  .status-none { color: #666; }
  .current-scopes {
    font-size: 12px;
    color: #888;
    margin-bottom: 16px;
    padding: 8px 12px;
    background: #0d0d0d;
    border-radius: 6px;
  }
  .current-scopes code { color: #d4a73a; font-size: 11px; }
  .scope-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 8px;
    margin-bottom: 12px;
  }
  .scope-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: #1a1a1a;
    border: 1px solid #252525;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.15s;
    font-size: 13px;
  }
  .scope-item:hover { border-color: #444; background: #1f1f1f; }
  .scope-item input[type="checkbox"] { accent-color: #4ade80; }
  .scope-label { flex: 1; }
  .scope-value { font-size: 10px; color: #555; }
  .custom-scope { margin-bottom: 16px; }
  .custom-scope input {
    width: 100%;
    padding: 8px 12px;
    background: #1a1a1a;
    border: 1px solid #252525;
    border-radius: 6px;
    color: #e0e0e0;
    font-size: 13px;
    font-family: monospace;
  }
  .custom-scope input:focus { outline: none; border-color: #4ade80; }
  .custom-scope input::placeholder { color: #444; }
  .actions { display: flex; gap: 10px; }
  .btn {
    padding: 8px 20px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
  }
  .btn-connect { background: #166534; color: #fff; }
  .btn-connect:hover { background: #15803d; }
  .btn-revoke { background: #1a1a1a; color: #f87171; border: 1px solid #7f1d1d; }
  .btn-revoke:hover { background: #2a1010; }
  .health { font-size: 12px; color: #444; text-align: center; margin-top: 32px; font-family: monospace; }
  .health a { color: #555; }
</style>
</head>
<body>
<div class="container">
  <h1>Cred</h1>
  <p class="subtitle">Credential delegation for AI agents · <code>${safeUserId}</code></p>
  ${providerCards}
  <p class="health"><a href="/health">/health</a> · <a href="/providers?user_id=${encodedUserId}">/providers</a></p>
</div>
<script>
const currentUserId = ${jsonScriptString(userId)};
async function buildScopes(e, provider) {
  e.preventDefault();
  const form = e.target;
  const checked = [...form.querySelectorAll('input[name="scope"]:checked')].map(i => i.value);
  const custom = form.querySelector('input[name="customScopes"]').value;
  if (custom) checked.push(...custom.split(',').map(s => s.trim()).filter(Boolean));
  if (checked.length === 0) {
    alert('Select at least one scope');
    return;
  }
  // Mint a single-use connect request, then open it.
  const res = await fetch('/connect/' + encodeURIComponent(provider) + '/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ user_id: currentUserId, scopes: checked }),
  });
  if (!res.ok) { alert('Failed: ' + res.status); return; }
  const data = await res.json();
  window.location.href = data.url;
}
async function revoke(provider) {
  if (!confirm('Revoke ' + provider + ' credentials?')) return;
  const res = await fetch('/connect/' + encodeURIComponent(provider) + '?user_id=' + encodeURIComponent(currentUserId), {
    method: 'DELETE'
  });
  if (res.ok) { alert('Revoked'); location.reload(); }
  else { alert('Failed: ' + res.status); }
}
for (const form of document.querySelectorAll('.scope-form')) {
  form.addEventListener('submit', (event) => {
    buildScopes(event, form.dataset.provider || '');
  });
}
for (const button of document.querySelectorAll('[data-revoke-provider]')) {
  button.addEventListener('click', () => {
    revoke(button.dataset.revokeProvider || '');
  });
}
</script>
</body>
</html>`);
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/connect] Error:', err);
      res.status(500).json({ error: 'Failed to render admin UI' });
    }
  });

  /**
   * DELETE /connect/:provider — revoke a provider connection from the admin UI.
   */
  app.delete('/connect/:provider', connectUiRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      if (!getProviderConfig(slug)) {
        res.status(404).json({ error: `Provider '${slug}' not configured` });
        return;
      }

      const userId = requestUserId(req, res, { agent: false });
      if (userId === null) return;
      await revokeStoredProvider(slug, userId);
      res.status(204).send();
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/connect/:provider DELETE] Error:', err);
      res.status(500).json({ error: 'Failed to revoke provider connection' });
    }
  });

  /** Scopes from a list, a comma-separated string, or a list of those. */
  function parseScopeInput(value: unknown): string[] {
    const values = Array.isArray(value)
      ? value.filter((scope): scope is string => typeof scope === 'string')
      : (typeof value === 'string' ? [value] : []);
    return values.flatMap((entry) => entry.split(',').map((scope) => scope.trim()).filter(Boolean));
  }

  async function startOAuth(res: Response, providerConfig: ProviderConfig, userId: string, requestedScopes: string[]): Promise<void> {
    const client = makeOAuthClient(providerConfig);
    // Requested scopes, else the provider's default scopes from config.
    const scopes = requestedScopes.length > 0 ? requestedScopes : providerConfig.defaultScopes;
    // The provider is asked for its own scopes, never a name only Cred knows.
    const providerScopes = providerScopesFor(providerConfig.slug, scopes);
    const { url, state, codeVerifier } = await client.getAuthorizationUrl({ scopes: providerScopes });
    cleanPendingOAuth();
    pendingOAuth.set(state, {
      provider: providerConfig.slug,
      userId,
      // Stored if the provider's answer names none. Notion never does, so what was
      // chosen here is all that records a read-only connection.
      scopes: providerConfig.slug === 'notion' ? scopes : providerScopes,
      state,
      codeVerifier,
      createdAt: Date.now(),
    });
    res.redirect(url);
  }

  function sendConnectRequestErrorPage(res: Response): void {
    // Generic: never say which check failed.
    const requestId = crypto.randomUUID();
    res.status(400).type('html').send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Cred: link not valid</title></head>
<body style="background:#0a0a0a;color:#e0e0e0;font-family:-apple-system,system-ui,sans-serif;padding:40px;max-width:640px;margin:0 auto;">
<h2>This connect link can't be used</h2>
<p>It may have expired or already been used. Start the connection again from the app or from the <a href="/connect" style="color:#4ade80;">connect page</a>.</p>
<p style="color:#888;">Request ID: <code>${requestId}</code></p>
</body></html>`);
  }

  /**
   * POST /connect/:provider/start: mint a single-use connect request.
   *
   * Admin auth (Bearer token or session cookie). JSON body
   * `{ user_id, scopes }` (user id rules apply). Answers `{ url }`, a
   * same-origin path `/connect/:provider?request=<id>` that starts the
   * OAuth flow once. Requires Content-Type: application/json, which a
   * cross-site form cannot send.
   */
  app.post('/connect/:provider/start', connectUiRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      if (!req.is('application/json')) {
        res.status(415).json({ error: 'unsupported_media_type', message: 'Send a JSON body with Content-Type: application/json' });
        return;
      }
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      const providerConfig = getProviderConfig(slug);
      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${slug}' not configured` });
        return;
      }
      const userId = requestUserId(req, res, { agent: false, source: 'body' });
      if (userId === null) return;
      const id = mintConnectRequest({ provider: slug, userId, scopes: parseScopeInput(req.body?.scopes) });
      res.setHeader('Cache-Control', 'no-store');
      res.json({ url: connectRequestPath(slug, id) });
    } catch (err) {
      console.error('[/connect/:provider/start] Error:', err);
      res.status(500).json({ error: 'Failed to start the connection' });
    }
  });

  /**
   * GET /connect/:provider: start the OAuth flow.
   *
   * Opens in a browser and redirects to the provider's authorization page.
   *   ?request=<id>  a single-use connect request (consent_url, or the
   *                  admin page via POST /connect/:provider/start): the
   *                  stored user id and scopes are used; any user_id or
   *                  scopes in the query are ignored.
   *   no request     with the Bearer admin token: ?user_id and
   *                  ?scopes=a,b as before (user id rules apply). With the
   *                  admin session cookie: nothing starts; the browser is
   *                  sent to the /connect page, where the operator starts
   *                  it with a click (a cross-site link carries the cookie
   *                  on a top-level GET and must not choose the user or
   *                  scopes).
   */
  app.get('/connect/:provider', connectRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      const requestIdParam = queryStringValue(req.query.request);
      if (requestIdParam !== undefined) {
        const pending = consumeConnectRequest(requestIdParam, slug);
        const providerConfig = pending ? getProviderConfig(slug) : undefined;
        if (!pending || !providerConfig || isReservedLinkVaultUserId(pending.userId)) {
          sendConnectRequestErrorPage(res);
          return;
        }
        await startOAuth(res, providerConfig, pending.userId, pending.scopes);
        return;
      }

      if ((req as any).adminCredential !== 'bearer') {
        const named = explicitRequestUserId(req);
        res.setHeader('Cache-Control', 'no-store');
        res.redirect(303, named !== undefined ? `/connect?user_id=${encodeURIComponent(named)}` : '/connect');
        return;
      }

      const userId = requestUserId(req, res, { agent: false });
      if (userId === null) return;
      const providerConfig = getProviderConfig(slug);
      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${slug}' not configured. Available: ${config.providers.map((p) => p.slug).join(', ')}` });
        return;
      }
      await startOAuth(res, providerConfig, userId, parseScopeInput(req.query.scopes));
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/connect] Error:', err);
      res.status(500).json({ error: 'Failed to start OAuth flow' });
    }
  });

  /**
   * GET /connect/:provider/callback — OAuth callback
   *
   * Handles the redirect from the provider, exchanges the code for tokens,
   * and stores them encrypted in the vault.
   */
  app.get('/connect/:provider/callback', callbackRateLimiter, async (req: Request, res: Response) => {
    try {
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      const { code, state, error: oauthError } = req.query as Record<string, string>;

      if (oauthError) {
        // Never render provider error text: generic message plus a request id.
        const requestId = crypto.randomUUID();
        console.warn('[/callback] Provider returned an OAuth error', { provider: slug, requestId });
        res.status(400).send(`<h2>OAuth Error</h2><p>The provider did not complete the connection.</p><p>Request ID: ${requestId}</p><p><a href="/providers">Back</a></p>`);
        return;
      }

      if (!code || !state) {
        res.status(400).json({ error: 'Missing code or state parameter' });
        return;
      }

      // Look up pending session
      const pending = pendingOAuth.get(state);
      if (!pending || pending.provider !== slug) {
        res.status(400).json({ error: 'Invalid or expired OAuth state. Try connecting again.' });
        return;
      }
      pendingOAuth.delete(state);
      if (rejectReservedUserId(res, pending.userId)) return;

      const providerConfig = getProviderConfig(slug);
      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${slug}' not configured` });
        return;
      }

      const client = makeOAuthClient(providerConfig);
      const tokens = await client.exchangeCode({
        code,
        codeVerifier: pending.codeVerifier,
      });

      // Store in vault
      const expiresAt = tokens.expires_in
        ? new Date(Date.now() + tokens.expires_in * 1000)
        : undefined;

      const scopes = tokens.scope
        ? tokens.scope.split(/[\s,]+/).map((scope) => scope.trim()).filter(Boolean)
        : pending.scopes;

      // A Salesforce token is good only at its org's instance, which the broker
      // holds it to. An answer naming no acceptable instance stores nothing.
      const instanceUrl = slug === 'salesforce' ? linkAudienceFor('salesforce', tokens.instance_url ?? null) : null;
      if (slug === 'salesforce' && !instanceUrl) {
        console.error('[connect] Salesforce named no acceptable instance', { provider: slug });
        res.status(502).send('Salesforce did not name an acceptable instance URL, so this connection was not stored.');
        return;
      }

      // A reconnect to another org ends what was issued and approved for the old
      // one. The agents did nothing wrong, so they may ask again.
      if (slug === 'salesforce') {
        const prior = await vault.getStored({ provider: slug, userId: pending.userId });
        if (prior && prior.instanceUrl !== instanceUrl) {
          // Approvals were given for the old org too: reusing one here would act on
          // an org nobody approved.
          await vault.revokeConsents({ subject: pending.userId, service: slug }, `reconnect:${slug}/${pending.userId}`);
          approvals.cancel({ subject: pending.userId, service: slug }, 'reconnected_to_another_instance');
          await applyRevocation(await vault.revokeDelegations({ connection: { service: slug, userId: pending.userId } }), performance.now(), {
            actor: { type: 'system', id: 'connect' },
            correlationId: crypto.randomUUID(),
            cause: `reconnect:${slug}/${pending.userId}`,
            agentsMayAskAgain: true,
          });
        }
      }

      await vault.store({
        provider: slug,
        userId: pending.userId,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt,
        scopes,
        ...(instanceUrl ? { instanceUrl } : {}),
      });

      console.log('[connect] Provider connected successfully', { provider: slug });

      const safeSlug = escapeHtml(slug);
      res.send(`
        <html>
        <body style="background:#0a0a0a;color:#fff;font-family:monospace;padding:40px;text-align:center;">
          <h2>✅ ${safeSlug} connected</h2>
          <p>Tokens stored in encrypted vault.</p>
          <p style="color:#888;">You can close this window.</p>
          <p><a href="/providers?user_id=${encodeURIComponent(pending.userId)}" style="color:#4ade80;">← Back to providers</a></p>
        </body>
        </html>
      `);
    } catch (err) {
      // Log the detail server-side; never render exception messages.
      const requestId = crypto.randomUUID();
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/callback] Error:', { requestId, err });
      res.status(500).send(`<h2>Connection Failed</h2><p>The connection could not be completed.</p><p>Request ID: ${requestId}</p><p><a href="/providers">Try again</a></p>`);
    }
  });

  // ── Guard middleware (optional) ─────────────────────────────────────────

  /**
   * If a CredGuard instance is provided in config, mount its express middleware
   * on the token delegation route. Guard runs after agent auth, before token
   * retrieval. Denied requests get 403 with policy details.
   */
  // The stored scopes a request naming none would be granted, shown to
  // Guard in its place (exposeStoredScopesToGuard).
  const storedScopesForGuard = new WeakMap<Request, string[]>();
  /** The DID a raw-token request proved with a DPoP proof, checked in front of Guard. */
  const provedRawAgentDid = new WeakMap<Request, string>();
  /** The scopes a request names, as the Guard middleware reads them. */
  function scopesNamedBy(req: Request): string[] {
    const scopes = req.body?.scopes || req.query.scopes;
    if (Array.isArray(scopes)) return scopes;
    if (typeof scopes === 'string') return scopes.split(',').map((scope) => scope.trim()).filter(Boolean);
    return [];
  }
  /**
   * Audit a Guard denial on a route's middleware, which runs before anything
   * in the request is authorized. The provider is recorded only if configured.
   * The event sits in a user's feed only when that user is known: a verifier
   * bound the caller to it, or this is a single-user server and none was named.
   * A named `user_id` or `agent_did` is a claim in the metadata, under a resource
   * with no user in it (the feed splits resource ids on '/').
   */
  function recordGuardRouteDenial(req: Request, decision: GuardDecision): void {
    const claim = (value: unknown, max: number): string | undefined => (
      typeof value === 'string' && value.length <= max && /^[\x21-\x7e]+$/.test(value) ? value : undefined
    );
    const principal = (req as any).agentPrincipal as RequestAgentPrincipal | undefined;
    const identity = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;
    const named = routeParam(req.params.provider);
    const provider = named !== undefined && providerMap.has(named) ? named : 'unknown';
    const explicitUser = explicitRequestUserId(req);
    const boundUser = principalBoundUserId(req);
    const knownUser = boundUser ?? (singleUserMode && explicitUser === undefined ? 'default' : undefined);
    const claimedUserId = explicitUser !== undefined && explicitUser !== knownUser ? claim(explicitUser, 128) : undefined;
    const claimedAgentDid = claim(req.body?.agent_did, 256);
    refusals.record({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: identity?.agentId ?? principal?.principalId ?? 'server-agent' },
      action: 'deny',
      resource: {
        type: 'token',
        id: knownUser !== undefined && !knownUser.includes('/') ? `${provider}/${knownUser}` : `${GUARD_DENIAL_RESOURCE_PREFIX}${provider}`,
      },
      outcome: 'denied',
      correlationId: crypto.randomUUID(),
      errorMessage: 'guard_denied',
      metadata: {
        policy: decision.deniedBy?.policy,
        // The route's template, not the request's path, which holds the provider it named.
        route: typeof req.route?.path === 'string' ? req.route.path : 'unknown',
        ...(claimedUserId ? { claimedUserId } : {}),
        ...(claimedAgentDid ? { claimedAgentDid } : {}),
      },
    });
  }

  /**
   * The agent DID Guard may judge. On /api/v1/delegate and /bc-authorize: the
   * `agent_did` whose key signed a DPoP proof for this route, or the DID the
   * raw-token check in front of Guard already proved. The proof's jti is not
   * recorded here: the route checks the proof again and refuses a replay. On
   * /api/v1/subdelegate: the receiving agent's did:key, which the request
   * names and the issued token or grant is bound to, so only the holder of
   * that key can use what a policy allowed. Undefined otherwise.
   */
  function agentDidForGuard(req: Request): string | undefined {
    // An external identity Cred verified and mapped is proven identity.
    const external = provenExternalAgent.get(req);
    if (external) return external.agentDid;
    const proved = provedRawAgentDid.get(req);
    if (proved !== undefined) return proved;
    const path = req.route?.path;
    const agentDid = req.body?.agent_did;
    if (typeof agentDid !== 'string' || !dpopBindingFor(agentDid)) return undefined;
    if (path === '/api/v1/subdelegate') return agentDid;
    if (path !== '/api/v1/delegate' && path !== '/bc-authorize') return undefined;
    if (path === '/api/v1/delegate' && tokenFormatFromBody(req) === 'raw') return undefined;
    const header = readDpopHeader(req.headers.dpop);
    if (header === 'multiple') return undefined;
    const result = verifyDpopProof(header, {
      agentDid,
      htm: 'POST',
      htu: `${publicBaseUri()}${path}`,
      seenJti: () => false,
    });
    return result.ok ? agentDid : undefined;
  }

  const guardMiddleware = config.guard
    ? createExpressMiddleware(config.guard, {
        extractScopes: (req) => storedScopesForGuard.get(req) ?? scopesNamedBy(req),
        // Link context from verified state only (set by the Link precheck).
        resolveLinkContext: (req) => linkService?.resolveGuardLinkContext(req),
        // Identity a policy may rely on, from verified state only: a checked Web Bot
        // Auth signature, a verified parent receipt, or claims a request verifier
        // attached to the caller. Never the request body, which is the caller's word.
        resolveVerifiedIdentity: async (req) => {
          const external = provenExternalAgent.get(req);
          const signature = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;
          const parent = (req as any).verifiedParentReceipt as { receiptClaims?: string[] } | undefined;
          let tofuFingerprint: string | undefined;
          // Only root delegation supports TOFU proofs. Other routes cannot
          // acquire a TOFU identity by naming a fingerprint in their body.
          if (req.route?.path === '/api/v1/delegate' && req.body?.connection_id === undefined) {
            const { tofu_fingerprint, tofu_payload, tofu_signature, service, appClientId = 'local' } = req.body ?? {};
            const user = resolveUserId(req, { explicit: explicitRequestUserId(req), agent: true });
            if (user.ok && typeof service === 'string' && typeof appClientId === 'string'
              && typeof tofu_fingerprint === 'string' && typeof tofu_payload === 'string' && typeof tofu_signature === 'string') {
              try {
                const verified = await resolveTofuPrincipal(tofu,
                  { fingerprint: tofu_fingerprint, payloadBase64: tofu_payload, signatureBase64: tofu_signature },
                  { service, userId: user.userId, appClientId, requestedScopes: normalizeRequestedScopes(req.body.scopes) });
                tofuFingerprint = verified.principal.fingerprint;
              } catch {
                // No verified fact for Guard. The route still refuses an
                // invalid proof if a policy allows requests without TOFU.
              }
            }
          }
          return {
            agentDid: agentDidForGuard(req),
            tofuFingerprint,
            webBotAuthKeyId: signature?.keyId,
            signatureAgent: signature?.signatureAgent,
            receiptClaims: extractTrustedReceiptClaims(req) ?? parent?.receiptClaims,
            ...(external
              ? { externalIdentity: { kind: external.identity.kind, subject: external.identity.subject, trustDomain: external.identity.trustDomain, attributes: external.identity.attributes } }
              : {}),
          };
        },
        onDeny: (req, res, decision) => {
          // Log guard denials for audit
          console.warn('[guard] DENIED', {
            policy: decision.deniedBy?.policy,
            reason: decision.deniedBy?.reason,
          });
          recordGuardRouteDenial(req, decision);
          const code = decision.deniedBy?.code;
          res.status(403).json({
            error: 'Request denied by guard policy',
            policy: decision.deniedBy?.policy,
            reason: decision.deniedBy?.reason,
            ...(typeof code === 'string' ? { code } : {}),
          });
        },
      })
    : null;

  /**
   * A request naming no scopes asks for every stored scope. Guard decides
   * on the scopes it is shown, so show it those: its scope policies then
   * filter what would actually be granted. `subject` says where the user
   * id is named; a request whose user or connection cannot be resolved here
   * goes on unchanged and is refused by the route.
   */
  function exposeStoredScopesToGuard(subject: 'user_id' | 'login_hint'): express.RequestHandler {
    return async (req, _res, next) => {
      try {
        const service = typeof req.params.provider === 'string' ? req.params.provider : undefined;
        if (service && scopesNamedBy(req).length === 0 && req.body?.connection_id === undefined) {
          const explicit = subject === 'login_hint' ? explicitUserIdValue(req.body?.login_hint) : explicitRequestUserId(req);
          const resolved = resolveUserId(req, { explicit, agent: true });
          if (resolved.ok && !isReservedLinkVaultUserId(resolved.userId)) {
            const stored = await vault.getStored({ provider: service, userId: resolved.userId });
            if (stored) {
              // Through the agent's Permission: Guard judges what could be issued.
              // With none the route refuses, and says what fixes it.
              const agentDid = req.body?.agent_did;
              const record = typeof agentDid === 'string' ? await vault.getAgentByDid?.(agentDid) ?? null : null;
              const permission = typeof agentDid === 'string' ? await permissionForDidAgent(agentDid, record, service) : null;
              storedScopesForGuard.set(req, permission
                ? withoutRedundantDerivedScopes(service, scopesForDidAgent(service, stored.scopes ?? [], record, permission))
                : stored.scopes ?? []);
            }
          }
        }
      } catch {
        // Nothing shown: the route decides, and refuses if Guard allowed nothing.
      }
      next();
    };
  }

  const assignProviderFromBody: express.RequestHandler = (req, res, next) => {
    const service = req.body?.service;
    if (typeof service !== 'string' || service.trim() === '') {
      res.status(400).json({ error: 'service is required' });
      return;
    }
    req.params.provider = service;
    next();
  };

  async function getVaultEntry(service: string, userId: string): Promise<VaultEntryResult> {
    if (isReservedLinkVaultUserId(userId)) {
      return { status: 400, body: { error: 'invalid_user_id', message: 'This user_id is reserved' } } as const;
    }
    const providerConfig = getProviderConfig(service);
    if (!providerConfig) {
      return {
        status: 404,
        body: { error: `Provider '${service}' not configured` },
      } as const;
    }

    const adapter = createAdapter(providerConfig.slug as BuiltinAdapterSlug);
    const entry = await vault.get({
      provider: service,
      userId,
      // The bridge carries a scope the provider states for the refreshed token,
      // so the stored list follows it; an unstated scope keeps the stored list.
      adapter: toVaultRefreshAdapter(adapter),
      clientId: providerConfig.clientId,
      clientSecret: providerConfig.clientSecret,
    });

    if (!entry) {
      return {
        status: 404,
        body: {
          error: `No credentials stored for '${service}/${userId}'. Connect it first: an operator opens /connect?user_id=${encodeURIComponent(userId)} and clicks Connect for ${service}, or POST /api/v1/delegate returns a consent_url.`,
        },
      } as const;
    }

    return { entry } as const;
  }

  function normalizeRequestedScopes(scopes: unknown): string[] | undefined {
    if (Array.isArray(scopes)) {
      return scopes
        .filter((scope): scope is string => typeof scope === 'string')
        .map((scope) => scope.trim())
        .filter(Boolean);
    }
    if (typeof scopes === 'string') {
      const parsed = scopes.split(',').map((scope) => scope.trim()).filter(Boolean);
      return parsed.length > 0 ? parsed : undefined;
    }
    return undefined;
  }

  type VaultEntryResult =
    | { entry: Awaited<ReturnType<typeof vault.get>> extends infer T ? Exclude<T, null> : never }
    | { status: number; body: Record<string, unknown> };

  /**
   * Revoke a stored connection's grant at the provider (never throws). The
   * refresh token is revoked where that ends the whole authorization, as
   * Link does; otherwise the access token.
   */
  async function revokeAtProvider(
    providerConfig: ProviderConfig,
    stored: { accessToken: string; refreshToken?: string },
  ): Promise<void> {
    const slug = providerConfig.slug;
    const token = slug === 'hubspot'
      ? stored.refreshToken
      : (slug === 'google' || slug === 'salesforce')
        ? stored.refreshToken ?? stored.accessToken
        : stored.accessToken;
    if (!token) return;
    try {
      await Promise.race([
        makeOAuthClient(providerConfig).revokeToken(token),
        new Promise((_, reject) => {
          const timer = setTimeout(() => reject(new Error('provider revocation timed out')), PROVIDER_REVOKE_TIMEOUT_MS);
          if (timer.unref) timer.unref();
        }),
      ]);
    } catch (err) {
      console.warn('[revoke] provider revocation failed', { provider: slug, kind: err instanceof Error ? err.name : 'unknown' });
    }
  }

  async function revokeStoredProvider(slug: string, userId: string): Promise<void> {
    if (isReservedLinkVaultUserId(userId)) throw new ReservedVaultUserIdError('delete');
    // getStored, not get: an expired access token must not hide the refresh
    // token the provider revocation below needs.
    const stored = await vault.getStored({ provider: slug, userId });
    await vault.delete({ provider: slug, userId });

    // Handles minted from this connection hold a copy of its access token.
    // Revoking the connection ends them too, not only at their expiry. Link
    // handles hold no token and re-check their connection on every use.
    // Every delegation issued from this connection is revoked in the vault
    // too, so no Delegation Token minted from it can be restored later
    // against a credential stored again for the same service and user.
    const cascade = await vault.revokeDelegations({ connection: { service: slug, userId } });
    await applyRevocation(cascade, performance.now(), {
      actor: { type: 'agent', id: 'server-agent' },
      correlationId: crypto.randomUUID(),
      cause: `connection:${slug}/${userId}`,
      // The connection is what ended, not the agents' standing: they may be
      // delegated to again once the user reconnects.
      agentsMayAskAgain: true,
    });
    let handlesRevoked = 0;
    for (const [id, delegation] of brokeredDelegations) {
      if (delegation.link || delegation.service !== slug || delegation.userId !== userId) continue;
      // Mark before removing: a /api/v1/use call that already loaded this
      // handle re-checks the mark right before its upstream call.
      delegation.revoked = { at: Date.now(), revokedAncestorId: id };
      brokeredDelegations.delete(id);
      handlesRevoked += 1;
    }

    // Raw tokens already handed out can only be stopped by the provider.
    // Best effort, in the background, so a slow provider never holds up the
    // revocation that has already happened here.
    const providerConfig = getProviderConfig(slug);
    if (stored && providerConfig) void revokeAtProvider(providerConfig, stored);

    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: 'server-agent' },
      action: 'revoke',
      resource: { type: 'connection', id: `${slug}/${userId}` },
      outcome: 'success',
      correlationId: crypto.randomUUID(),
      metadata: { handlesRevoked, delegationsRevoked: cascade.count },
    });
  }

  function storeBrokeredDelegation(input: {
    delegationId: string;
    accessToken: string;
    service: string;
    userId: string;
    scopes: string[];
    /**
     * The stored scopes of the row `accessToken` was read from, for the handle
     * to decide over at each exercise (see BrokeredDelegation.credentialScopes).
     * Omitted only for a handle that holds no provider token (a Link one).
     */
    credentialScopes?: string[];
    expiresIn: number;
    link?: LinkHandleBinding;
    constraints?: DelegationConstraint[];
    agentDid?: string;
    dpopJkt?: string;
    capabilities?: CredDelegationDetail[];
  }): void {
    const expiresAt = Date.now() + Math.max(1, input.expiresIn) * 1000;
    brokeredDelegations.set(input.delegationId, {
      accessToken: input.accessToken,
      service: input.service,
      userId: input.userId,
      scopes: input.scopes,
      ...(input.credentialScopes ? { credentialScopes: input.credentialScopes } : {}),
      expiresAt,
      createdAt: Date.now(),
      ...(input.link ? { link: input.link } : {}),
      ...(input.constraints && input.constraints.length > 0 ? { constraints: input.constraints } : {}),
      ...(input.agentDid ? { agentDid: input.agentDid } : {}),
      ...(input.dpopJkt ? { dpopJkt: input.dpopJkt } : {}),
      ...(input.capabilities ? { capabilities: input.capabilities } : {}),
    });
    const timeout = setTimeout(() => brokeredDelegations.delete(input.delegationId), Math.max(1, input.expiresIn) * 1000);
    if (timeout.unref) timeout.unref();
  }

  /** REDIRECT_BASE_URI without trailing slashes: the audience of actor tokens. */
  function publicBaseUri(): string {
    let base = config.redirectBaseUri;
    while (base.endsWith('/')) base = base.slice(0, -1);
    return base;
  }

  /** Audit a /api/v1/use refusal under a cumulative constraint. */
  function denyCumulative(delegationId: string, delegation: BrokeredDelegation, error: string, keys: string[], url?: string): void {
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: brokeredActor(delegation),
      action: 'deny',
      // service/userId, like every other deny event, so the owning user's
      // /api/v1/audit and audit stream can see it.
      resource: { type: 'token', id: `${delegation.service}/${delegation.userId}` },
      outcome: 'denied',
      correlationId: crypto.randomUUID(),
      errorMessage: error,
      metadata: { ...brokeredCallMetadata(delegationId, delegation, url), constraints: keys },
    });
  }


  function refuseRawToken(res: Response): void {
    res.status(403).json({
      error: 'raw_token_disabled',
      message: 'This server does not hand out provider tokens. Request a brokered handle (token_format "handle") and make calls through /api/v1/use.',
    });
  }

  /** A raw request that names no agent identifies nobody a Permission could be for. */
  function refuseAnonymousRawToken(res: Response): void {
    res.status(403).json({
      error: 'permission_required',
      message: 'A raw token request must name an agent (agent_did) that holds a Permission. CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true allows one that names none.',
    });
  }

  function refuseDpop(res: Response, status: 400 | 401, error: string, message: string): void {
    if (status === 401) {
      res.set('WWW-Authenticate', `DPoP error="${error === 'agent_key_required' ? 'invalid_request' : 'invalid_dpop_proof'}", algs="${DPOP_ACCEPTED_ALGS.join(' ')}"`);
    }
    res.status(status).json({ error, message });
  }

  /**
   * Check the DPoP proof on a request, for the agent named by `agentDid`.
   * Answers the request and returns false on failure.
   */
  function checkDpop(
    req: Request,
    res: Response,
    input: { agentDid: string | undefined; path: string; ath?: string; req?: string; resource: { type: 'token' | 'connection'; id: string } },
  ): boolean {
    if (!input.agentDid || !dpopBindingFor(input.agentDid)) {
      refuseDpop(res, 400, 'agent_key_required', 'A brokered handle is issued only to a did:key agent (agent_did) that proves its key with a DPoP proof (RFC 9449)');
      return false;
    }
    const header = readDpopHeader(req.headers.dpop);
    const result = header === 'multiple'
      ? { ok: false as const, message: 'exactly one DPoP header is allowed' }
      : verifyDpopProof(header, {
        agentDid: input.agentDid,
        htm: 'POST',
        htu: `${publicBaseUri()}${input.path}`,
        ...(input.ath !== undefined ? { ath: input.ath } : {}),
        ...(input.req !== undefined ? { req: input.req } : {}),
        seenJti: dpopJtiSeen,
      });
    if (result.ok) return true;
    // The audit log is readable by any Bearer caller for the user, so at
    // /api/v1/use it does not name the agent the handle is bound to either.
    const reason = input.path === '/api/v1/use' ? result.message.split(input.agentDid).join('the bound agent') : result.message;
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: input.agentDid },
      action: 'deny',
      resource: input.resource,
      outcome: 'denied',
      correlationId: crypto.randomUUID(),
      errorMessage: 'invalid_dpop_proof',
      metadata: { path: input.path, reason },
    });
    // At /api/v1/use the reason stays in the audit log: it would tell a
    // caller which agent a handle it does not hold is bound to.
    refuseDpop(res, 401, 'invalid_dpop_proof', input.path === '/api/v1/use' ? 'DPoP proof is missing or invalid for this handle' : result.message);
    return false;
  }

  function getBrokeredDelegation(id: string): BrokeredDelegation | null {
    const delegation = brokeredDelegations.get(id);
    if (!delegation) return null;
    if (Date.now() >= delegation.expiresAt) {
      brokeredDelegations.delete(id);
      return null;
    }
    return delegation;
  }

  /**
   * Record an issued delegation and its parent linkage, so a later
   * revocation can reach it. Refuses with 401 delegation_revoked (or 403
   * agent_revoked) when the parent or the agent was revoked meanwhile. On
   * SQLite the check and the insert are one transaction, so a child issued
   * while its parent is being revoked can never outlive the cascade.
   * Returns false when it has already answered the request.
   */
  async function recordIssuedDelegation(res: Response, input: RecordDelegationInput, correlationId: string): Promise<boolean> {
    try {
      await vault.recordDelegation(input);
      return true;
    } catch (err) {
      if (!(err instanceof DelegationRevokedError)) throw err;
      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: input.agentDid ?? 'server-agent' },
        action: 'deny',
        resource: { type: 'token', id: `${input.service}/${input.userId}` },
        outcome: 'denied',
        correlationId,
        errorMessage: err.code,
        metadata: { delegationId: input.id, parentDelegationId: input.parentId ?? null, revokedAncestorId: err.revokedAncestorId },
      });
      if (err.code === 'agent_revoked') {
        res.status(403).json({ error: 'agent_revoked', message: 'Agent has been revoked' });
      } else {
        res.status(401).json({
          error: 'delegation_revoked',
          message: 'The parent delegation has been revoked',
          revoked_ancestor_id: err.revokedAncestorId,
        });
      }
      return false;
    }
  }

  /**
   * The id of the revoked ancestor when `delegationId` has been revoked,
   * else null. The handle's own mark is the fast path; the vault record is
   * the source of truth, and also covers a handle stored just after a
   * cascade passed its record.
   */
  async function delegationRevokedBy(delegationId: string, delegation?: BrokeredDelegation): Promise<string | null> {
    if (delegation?.revoked) return delegation.revoked.revokedAncestorId;
    const record = await vault.getDelegation(delegationId);
    if (record?.status === 'revoked') return record.revokedAncestorId ?? record.id;
    return null;
  }

  function refuseRevokedDelegation(res: Response, delegationId: string, revokedAncestorId: string, delegation: BrokeredDelegation): void {
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: brokeredActor(delegation),
      action: 'deny',
      resource: { type: 'token', id: `${delegation.service}/${delegation.userId}` },
      outcome: 'denied',
      correlationId: crypto.randomUUID(),
      errorMessage: 'delegation_revoked',
      metadata: { delegationId, revokedAncestorId },
    });
    res.status(401).json({
      error: 'delegation_revoked',
      message: 'This delegation has been revoked',
      revoked_ancestor_id: revokedAncestorId,
    });
  }

  /**
   * Finish a cascade the vault has committed: mark every brokered handle it
   * reached as revoked, then write one `revoke` audit event per revoked
   * delegation naming the root cause. `elapsedMs` covers the vault
   * transaction and the handle marks, the invalidation the draft bounds at
   * 5 seconds; the audit writes follow it.
   */
  async function applyRevocation(
    result: DelegationRevocationResult,
    started: number,
    ctx: { actor: AuditActor; correlationId: string; cause: string; agentsMayAskAgain?: boolean },
  ): Promise<DelegationRevocationResult> {
    const at = Date.now();
    for (const revoked of result.revoked) {
      const handle = brokeredDelegations.get(revoked.id);
      if (handle) handle.revoked = { at, revokedAncestorId: revoked.revokedAncestorId };
    }
    const elapsedMs = performance.now() - started;
    // The holds and consents committed with the revocation (see the hold option);
    // an approval not yet redeemed must not issue after it.
    if (!ctx.agentsMayAskAgain) {
      for (const revoked of result.revoked) {
        if (revoked.agentDid) approvals.cancel({ agentDid: revoked.agentDid, subject: revoked.userId, service: revoked.service }, 'delegation_revoked');
      }
    }

    const revocationTime = new Date(at).toISOString();
    writeAuditEventsIfSupported(result.revoked.map((revoked): AuditEvent => ({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(at),
      actor: ctx.actor,
      action: 'revoke',
      resource: { type: 'token', id: `${revoked.service}/${revoked.userId}` },
      outcome: 'success',
      correlationId: ctx.correlationId,
      metadata: {
        delegationId: revoked.id,
        parentDelegationId: revoked.parentId,
        agentDid: revoked.agentDid,
        revokedAncestorId: revoked.revokedAncestorId,
        cascadeDepth: revoked.depth,
        cause: ctx.cause,
        revocationTime,
      },
    })));
    if (result.truncated) {
      console.error('[revocation] Cascade stopped at the depth bound; some descendants were not reached', { cause: ctx.cause });
    }
    return { ...result, elapsedMs };
  }

  function buildDelegationResponse(input: {
    tokenFormat: 'raw' | 'handle';
    accessToken: string;
    tokenType?: string;
    expiresIn: number;
    service: string;
    userId: string;
    scopes: string[];
    delegationId: string;
    receipt?: string;
    chainDepth?: number;
    parentDelegationId?: string;
    guard?: Record<string, unknown>;
    constraints?: DelegationConstraint[];
    agentDelegationToken?: string;
    agentDid?: string;
    /** The server-side state of the Delegation Token, as recorded. Required for tokenFormat 'handle'. */
    grant?: DelegationGrant;
    /** Ancestor agent DIDs, root first: the token's nested `act`. */
    lineage?: string[];
    /** The Cred Link binding, for a delegation of a Link connection. */
    link?: LinkHandleBinding;
    /**
     * The stored scopes of the row `accessToken` was read from, recorded on the
     * handle so each exercise decides over the authority of the credential it
     * forwards (BrokeredDelegation.credentialScopes). A Link handle reads its
     * token at each exercise and records none.
     */
    credentialScopes?: string[];
  }): Record<string, unknown> {
    // Every handle and every receipt-bearing delegation is registered with
    // the cumulative ledger, with its parent, so a descendant's max_subtree
    // debit can walk up through it even when this hop itself carries no
    // cumulative bound.
    if (input.receipt || input.tokenFormat === 'handle') {
      cumulativeLedger.register({
        id: input.delegationId,
        ...(input.parentDelegationId ? { parentId: input.parentDelegationId } : {}),
        constraints: input.constraints ?? [],
      });
    }
    let delegationToken: string | undefined;
    if (input.tokenFormat === 'handle') {
      if (!input.grant || !input.agentDid) throw new Error('A Delegation Token needs a recorded grant and an agent DID');
      delegationToken = mintDelegationTokenFor({
        delegationId: input.delegationId,
        agentDid: input.agentDid,
        userId: input.userId,
        lineage: input.lineage,
        grant: input.grant,
        expiresIn: input.expiresIn,
      });
      storeBrokeredDelegation({
        agentDid: input.agentDid,
        dpopJkt: input.grant.jkt,
        capabilities: input.grant.authorizationDetails as CredDelegationDetail[],
        delegationId: input.delegationId,
        accessToken: input.accessToken,
        service: input.service,
        userId: input.userId,
        scopes: input.scopes,
        expiresIn: input.expiresIn,
        ...(input.credentialScopes ? { credentialScopes: input.credentialScopes } : {}),
        ...(input.constraints ? { constraints: input.constraints } : {}),
        ...(input.link ? { link: input.link } : {}),
      });
    }

    return {
      ...(input.tokenFormat === 'raw'
        ? { access_token: input.accessToken, token_type: input.tokenType ?? 'Bearer' }
        // RFC 9449 Section 5: a DPoP-bound access token. Every exercise
        // presents it as `Authorization: DPoP` with a proof by the bound key.
        : { access_token: delegationToken, token_type: 'DPoP', cnf: { jkt: input.grant!.jkt } }),
      expires_in: input.expiresIn,
      service: input.service,
      user_id: input.userId,
      scopes: input.scopes,
      delegation_id: input.delegationId,
      ...(input.receipt ? { receipt: input.receipt } : {}),
      ...(input.chainDepth !== undefined ? { chain_depth: input.chainDepth } : {}),
      ...(input.parentDelegationId ? { parent_delegation_id: input.parentDelegationId } : {}),
      ...(input.guard ? { guard: input.guard } : {}),
      ...(input.agentDelegationToken ? { agent_delegation_token: input.agentDelegationToken } : {}),
    };
  }

  /** The capabilities a delegation of `scopes` grants: the scopes as operations. */
  function capabilitiesFor(service: string, scopes: string[]): CredDelegationDetail[] {
    return [{ type: CRED_DELEGATION_TYPE, provider: service, operations: scopes }];
  }

  /**
   * The server-side state behind a Delegation Token for one delegation, or
   * null when the agent has no did:key to bind the token to.
   */
  function newDelegationGrant(input: {
    agentDid: string | undefined;
    service: string;
    scopes: string[];
    appClientId: string;
    constraints?: DelegationConstraint[];
    consentId: string;
    prf: string[];
    /** Validated capabilities; defaults to the granted scopes as operations. */
    capabilities?: CredDelegationDetail[];
    /** The Cred Link binding, for a delegation of a Link connection. */
    link?: LinkHandleBinding;
    /** The stored connection's instance, for a Salesforce delegation. */
    instanceUrl?: string;
    /** The Permission that authorized it. */
    permissionId?: string;
  }): DelegationGrant | null {
    const jkt = dpopBindingFor(input.agentDid);
    if (!jkt) return null;
    return {
      // Random, so the token names neither the provider nor the user.
      credentialHandle: `ch_${crypto.randomBytes(16).toString('hex')}`,
      consentId: input.consentId,
      jkt,
      scopes: input.scopes,
      appClientId: input.appClientId,
      ...(input.constraints && input.constraints.length > 0 ? { constraints: input.constraints } : {}),
      authorizationDetails: input.capabilities ?? capabilitiesFor(input.service, input.scopes),
      prf: input.prf,
      ...(input.link ? { link: { ...input.link } } : {}),
      ...(input.service === 'salesforce' && input.instanceUrl ? { instanceOrigin: new URL(input.instanceUrl).origin } : {}),
      ...(input.permissionId ? { permissionId: input.permissionId } : {}),
    };
  }

  /** Record the consent behind a root delegation (draft Section 8.2) and return its id. */
  async function recordRootConsent(input: {
    userId: string;
    agentDid: string;
    service: string;
    scopes: string[];
    permission: Permission | null;
    delegationId: string;
    capabilities?: CredDelegationDetail[];
  }): Promise<string> {
    const record = await vault.recordConsent({
      id: `consent_${crypto.randomBytes(16).toString('hex')}`,
      subject: input.userId,
      agentDid: input.agentDid,
      service: input.service,
      capabilities: input.capabilities ?? capabilitiesFor(input.service, input.scopes),
      // Without an approval flow, consent is the admin's Permission when one
      // authorized the delegation, else the subject's own provider connection.
      source: input.permission ? 'permission' : 'connection',
      approvedBy: input.permission?.createdBy ?? input.userId,
      expiresAt: input.permission?.expiresAt ? input.permission.expiresAt.toISOString() : null,
      chainContext: { delegationId: input.delegationId, chainDepth: 0 },
    });
    return record.id;
  }

  /**
   * The agent's did:key on a Cred Link delegate call, proven by a DPoP
   * proof by that key, or null once the refusal is sent.
   */
  function checkLinkAgentKey(req: Request, res: Response, resourceId: string): string | null {
    const agentDid = typeof req.body?.agent_did === 'string' ? req.body.agent_did as string : undefined;
    if (!checkDpop(req, res, { agentDid, path: '/api/v1/delegate', resource: { type: 'connection', id: resourceId } })) return null;
    return agentDid!;
  }

  /**
   * Record a Cred Link delegation and send its Delegation Token: bound to
   * the agent's key and to the Link grant, restorable from the vault, and
   * exercised like any other delegation. Its consent is the Link grant the
   * end user confirmed.
   */
  async function issueLinkDelegationToken(req: Request, res: Response, input: {
    audit: () => void;
    delegationId: string;
    agentDid: string;
    service: string;
    userId: string;
    appClientId: string;
    scopes: string[];
    expiresIn: number;
    link: LinkHandleBinding;
    extra: Record<string, unknown>;
  }): Promise<void> {
    // The same did:key controls as any root delegation: a suspended agent,
    // or one asking past its scope ceiling, gets no Link token either.
    const agentCheck = await didAgentCheck(input.agentDid, input.service, input.scopes);
    if (!agentCheck.ok) {
      res.status(403).json({ error: agentCheck.error, message: agentCheck.message });
      return;
    }
    // No longer than the receipt its prf cites, as any other delegation.
    const expiresIn = Math.max(1, Math.min(input.expiresIn, getReceiptTtlSeconds()));
    const receipt = createReceipt({
      agentDid: input.agentDid,
      service: input.service,
      userId: input.userId,
      appClientId: input.appClientId,
      scopes: input.scopes,
      delegationId: input.delegationId,
      chainDepth: 0,
      receiptClaims: extractTrustedReceiptClaims(req),
    });
    const consentId = `consent_${crypto.randomBytes(16).toString('hex')}`;
    const grant = newDelegationGrant({
      agentDid: input.agentDid,
      service: input.service,
      scopes: input.scopes,
      appClientId: input.appClientId,
      consentId,
      prf: [receiptContentId(receipt)],
      link: input.link,
    })!;
    // The consent first: a delegation recorded after it never names a
    // consent that does not exist. A Link consent is never reused, so one
    // left behind by a refused issue grants nothing.
    await vault.recordConsent({
      id: consentId,
      subject: input.userId,
      agentDid: input.agentDid,
      service: input.service,
      capabilities: grant.authorizationDetails ?? capabilitiesFor(input.service, input.scopes),
      source: 'connection',
      approvedBy: `link:${input.link.grantId}`,
      expiresAt: null,
      chainContext: { delegationId: input.delegationId, chainDepth: 0, linkGrantId: input.link.grantId, linkGrantVersion: input.link.grantVersion },
    });
    const recorded = await recordIssuedDelegation(res, {
      id: input.delegationId,
      parentId: null,
      agentDid: input.agentDid,
      service: input.service,
      userId: input.userId,
      chainDepth: 0,
      expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
      grant,
    }, crypto.randomUUID());
    if (!recorded) return;
    input.audit();
    // The Link vault user id is internal: the response names the connection.
    const { user_id: _internalUserId, ...response } = buildDelegationResponse({
      tokenFormat: 'handle',
      grant,
      accessToken: '',
      expiresIn,
      service: input.service,
      userId: input.userId,
      scopes: input.scopes,
      delegationId: input.delegationId,
      receipt,
      agentDid: input.agentDid,
      link: input.link,
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ...response, ...input.extra });
  }

  /** Mint the Delegation Token for a recorded grant, signed with the receipt key. */
  function mintDelegationTokenFor(input: {
    delegationId: string;
    agentDid: string;
    userId: string;
    lineage?: string[];
    grant: DelegationGrant;
    expiresIn: number;
  }): string {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const actor = receiptActorClaims({ principal: input.userId, agentDid: input.agentDid, priorActors: input.lineage });
    return mintDelegationToken({
      iss: config.redirectBaseUri,
      sub: actor.sub,
      client_id: actor.client_id,
      act: actor.act,
      authorization_details: input.grant.authorizationDetails as CredDelegationDetail[],
      ...(input.grant.constraints && input.grant.constraints.length > 0 ? { delegation_constraints: input.grant.constraints } : {}),
      cnf: { jkt: input.grant.jkt },
      iat: nowSeconds,
      exp: nowSeconds + Math.max(1, Math.min(input.expiresIn, MAX_RECEIPT_TTL_SECONDS)),
      jti: input.delegationId,
      consent_id: input.grant.consentId,
      credential_handle: input.grant.credentialHandle,
      prf: input.grant.prf ?? [],
    }, getReceiptKeys().signer);
  }

  // Stored provider consent is compared exact-match on purpose (scopeEquivalent,
  // not scopeCovers): these are provider-defined identifiers, not Cred
  // delegation scopes, and are not expected to use the ".*" wildcard form.
  // Delegation-chain narrowing is wildcard-aware separately, in
  // validateSubDelegation and the per-agent scopeCeiling checks.
  //
  // Cred's derived read scopes are the exception, and storedScopes already
  // holds them (see scopesForDidAgent). A request naming no scope is issued what
  // was stored, not the derived scope as well.
  function resolveGrantedScopes(service: string, storedScopes: string[], requestedScopes?: string[]) {
    if (!requestedScopes || requestedScopes.length === 0) {
      return { grantedScopes: withoutRedundantDerivedScopes(service, storedScopes), widenedScopes: [] as string[] };
    }

    const widenedScopes = requestedScopes.filter(
      (requestedScope) => !storedScopes.some((storedScope) => scopeEquivalent(storedScope, requestedScope)),
    );
    if (widenedScopes.length > 0) {
      return {
        grantedScopes: [] as string[],
        widenedScopes,
      };
    }

    return {
      grantedScopes: storedScopes.filter((storedScope) =>
        requestedScopes.some((requestedScope) => scopeEquivalent(storedScope, requestedScope))
      ),
      widenedScopes: [] as string[],
    };
  }

  async function evaluateBrokerUseGuard(
    req: Request,
    res: Response,
    input: {
      delegationId: string;
      url: string;
      method: string;
      delegation: BrokeredDelegation;
      /** Link delegations: the scopes checkLinkAccess allowed for this call. */
      scopes?: string[];
      /** The did:key the Delegation Token is bound to, proven by DPoP on this call. */
      provenAgentDid?: string;
    },
  ): Promise<{ allowed: true; effectiveScopes: string[]; decision?: GuardDecision } | { allowed: false }> {
    const callScopes = input.scopes ?? input.delegation.scopes;
    if (!config.guard) {
      return { allowed: true, effectiveScopes: callScopes };
    }

    try {
      const webBotAuthIdentity = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;
      const principal = (req as any).agentPrincipal as RequestAgentPrincipal | undefined;
      const ctx: GuardContext = {
        provider: input.delegation.service,
        agentTokenHash: (req as any).agentTokenHash ?? hashAgentPrincipal(principal ?? { type: 'unknown' }),
        requestedScopes: callScopes,
        consentedScopes: callScopes,
        timestamp: new Date().toISOString(),
        targetUrl: input.url,
        targetMethod: input.method,
        delegationId: input.delegationId,
        metadata: {
          brokered: true,
          userId: input.delegation.userId,
          ...(principal ? { authPrincipal: principal } : {}),
        },
        identitySource: webBotAuthIdentity ? 'web-bot-auth' : 'agent-token',
        ...(input.provenAgentDid ? { agentDid: input.provenAgentDid } : {}),
        webBotAuthKeyId: webBotAuthIdentity?.keyId,
        signatureAgent: webBotAuthIdentity?.signatureAgent,
        ...(input.delegation.link
          ? {
              link: {
                connectionId: input.delegation.link.connectionId,
                agentId: input.delegation.link.agentId,
                operation: 'use' as const,
                grantId: input.delegation.link.grantId,
                grantVersion: input.delegation.link.grantVersion,
              },
            }
          : {}),
      };

      const decision = await config.guard.evaluate(ctx);
      (req as any).guardDecision = decision;
      (req as any).guardContext = ctx;

      if (!decision.allowed) {
        const code = decision.deniedBy?.code;
        refuseBrokeredCall(input.delegationId, input.delegation, input.url, 'guard_denied', { policy: decision.deniedBy?.policy, method: input.method });
        res.status(403).json({
          error: 'Request denied by guard policy',
          policy: decision.deniedBy?.policy,
          reason: decision.deniedBy?.reason,
          ...(typeof code === 'string' ? { code } : {}),
        });
        return { allowed: false };
      }

      return {
        allowed: true,
        effectiveScopes: decision.effectiveScopes,
        decision,
      };
    } catch (err) {
      refuseBrokeredCall(input.delegationId, input.delegation, input.url, 'guard_failed', { method: input.method });
      res.status(500).json({
        error: 'Guard evaluation failed',
        message: err instanceof Error ? err.message : String(err),
      });
      return { allowed: false };
    }
  }

  /**
   * The permission controls the server enforces on top of allowedScopes:
   * expiry, the per-permission rate limit, and human approval. The rate
   * limit is counted before approval, so an approval-gated permission is
   * still held to it. 'approval_required' tells the caller to look for a
   * consent that covers the request, or send the agent to /bc-authorize.
   * Returns the refusal code, or null when the permission allows it.
   */
  async function permissionRefusal(permission: Permission): Promise<string | null> {
    if (permission.expiresAt && permission.expiresAt.getTime() <= Date.now()) return 'permission_expired';
    for (const row of [permission, (permission as Permission & { alsoLimitedBy?: Permission }).alsoLimitedBy]) {
      if (row?.rateLimit && vault.checkPermissionRateLimit) {
        const allowed = await vault.checkPermissionRateLimit(row.id, row.rateLimit.maxRequests, row.rateLimit.windowMs);
        if (!allowed) return 'rate_limited';
      }
    }
    if (permission.requiresApproval) return 'approval_required';
    return null;
  }

  /**
   * The checks on a did:key agent's own record: revoked, suspended, or
   * asking past its scope ceiling. On success, the record (null when the
   * agent is not registered).
   */
  async function didAgentCheck(agentDid: string, service: string, requestedScopes: string[] | undefined): Promise<
    { ok: true; record: AgentRecord | null } | { ok: false; error: string; message: string }
  > {
    const record = vault.getAgentByDid ? await vault.getAgentByDid(agentDid) : null;
    if (record?.status === 'revoked') return { ok: false, error: 'agent_revoked', message: 'Agent has been revoked' };
    if (record?.status === 'suspended') return { ok: false, error: 'agent_suspended', message: 'Agent is suspended' };
    const over = record?.scopeCeiling.length && requestedScopes?.length
      ? requestedScopes.filter((scope) => !ceilingCovers(service, record.scopeCeiling, scope))
      : [];
    if (over.length > 0) return { ok: false, error: 'scope_ceiling_exceeded', message: `Agent scope ceiling exceeded: ${over.join(', ')}` };
    return { ok: true, record };
  }

  /**
   * The connection scopes a did:key agent may be given: within its scope
   * ceiling and within its Permission's allowedScopes. No Permission means
   * none, unless the deprecated opt-out is set.
   *
   * Both comparisons are made over what the stored connection covers, not over
   * its bare scope list. For Notion that matters: an existing entry with no
   * stored scopes is the whole connection, so a row naming only `read_content`
   * must not be issued `notion.read` through the wider scope the empty list
   * stands for.
   */
  function scopesForDidAgent(service: string, stored: string[], record: AgentRecord | null, permission: Permission | null): string[] {
    if (!permission && !allowAgentsWithoutPermission) return [];
    const held = withStoredDerivedScopes(service, stored);
    return held
      .filter((scope) => !publicRepoOverWiderToken(service, scope, stored))
      .filter((scope) => !record?.scopeCeiling.length || ceilingCovers(service, record.scopeCeiling, scope, held))
      .filter((scope) => !permission || permissionCovers(service, permission.allowedScopes, scope, held));
  }

  /** A ceiling covers a scope, or the wider scope a derived read scope comes from. Never the reverse. */
  function ceilingCovers(service: string, ceiling: string[], scope: string, held: string[] = []): boolean {
    return scopeCoveredBy(withDerivedScopesUnder(service, ceiling, held), scope);
  }

  /** Every id one agent can be named by: the id given, its DID and its record id. */
  async function agentIdsOf(agentId: string): Promise<string[]> {
    const record = agentId.startsWith('did:')
      ? await vault.getAgentByDid?.(agentId) ?? null
      : await vault.getAgent?.(agentId) ?? null;
    return [...new Set([agentId, ...(record?.did ? [record.did] : []), ...(record?.id ? [record.id] : [])])];
  }

  /**
   * The Permission of a did:key agent on a service. Stored under its agent
   * record id or under the DID itself, on every path.
   */
  async function permissionForDidAgent(agentDid: string, record: AgentRecord | null, service: string): Promise<Permission | null> {
    const byRecord = record ? await getPermissionIfSupported(record.id, service) : null;
    const byDid = await getPermissionIfSupported(agentDid, service);
    if (!byRecord || !byDid || byRecord.id === byDid.id) return byRecord ?? byDid;
    return tightestOf(service, byRecord, byDid);
  }

  /** Whether a Permission covers a scope, over a token holding `held`. */
  function permissionCovers(service: string, allowed: string[], scope: string, held: string[]): boolean {
    const expanded = withDerivedScopesUnder(service, allowed, held);
    return expanded.some((name) => scopeEquivalent(name, scope)) || scopeCoveredBy(expanded, scope);
  }

  /** One stored row, and what it covers, as a single read returned it. */
  type ConnectionSnapshot = { entry: VaultEntry | null; held: string[] };

  /**
   * What a stored connection covers, from one metadata read of its row: its
   * stored scopes plus the reads those derive, with an existing Notion entry's
   * empty list meaning the whole connection (its token carries no scopes,
   * because the capabilities are set on the integration). A row that cannot be
   * read — no entry at all — covers nothing here; the route refuses the hop
   * later when the credential itself cannot be read.
   *
   * The row is kept with its scopes, because the same entry is the credential a
   * hop issues against: see hopCredential(). A hop takes this read once and
   * answers every stored-scope question from it.
   *
   * `getStored` decrypts the row at rest, never refreshes it and never calls the
   * provider. Only its scope list is used for a decision, and it is neither
   * logged nor returned.
   */
  async function connectionSnapshot(service: string, userId: string): Promise<ConnectionSnapshot> {
    const entry = await vault.getStored({ provider: service, userId });
    return { entry, held: entry ? withStoredDerivedScopes(service, entry.scopes ?? []) : [] };
  }

  /**
   * The credential a hop issues against, taken from the row its decision was
   * made on.
   *
   * `snapshot` is that row. While the entry it holds is still usable it IS the
   * credential: there is no second read left to disagree with the decision, so
   * a connection replaced between the checks and the issuance cannot widen what
   * the hop hands out. An expired entry is the one case the stored read cannot
   * serve — refresh belongs to `get()`, which may also write the token back — so
   * that case re-reads, and the result must still be covered by the snapshot.
   * A re-read that reaches any scope the decision was not taken over is refused
   * rather than issued against, because a derived read's meaning turns on the
   * token behind it: `github.read` over a `repo` token reaches private
   * repositories, and a decision taken over `public_repo` never covered that.
   *
   * A hop on a service with no derived read scope takes no snapshot — it has no
   * stored-scope question to answer — and reads its credential once here.
   */
  async function hopCredential(
    service: string,
    snapshot: ConnectionSnapshot | undefined,
    getOpts: Parameters<typeof vault.get>[0],
  ): Promise<{ entry: VaultEntry | null } | { unreviewed: string[] }> {
    const pinned = snapshot?.entry ?? null;
    const usable = pinned !== null && !(pinned.expiresAt !== undefined && pinned.expiresAt.getTime() <= Date.now());
    const entry = usable ? pinned : await vault.get(getOpts);
    if (snapshot && entry) {
      const unreviewed = withStoredDerivedScopes(service, entry.scopes ?? [])
        .filter((scope) => !scopeCoveredBy(snapshot.held, scope));
      if (unreviewed.length > 0) return { unreviewed };
    }
    return { entry };
  }

  /**
   * What a live delegation may do now: its scopes, within the Permission that
   * authorized it and the agent's Permission as they stand. A Permission narrowed
   * after issuance takes effect at once, like a revocation. A row that has gone or
   * expired covers nothing, and a re-grant is a new row: a delegation under the
   * replaced one stops.
   */
  /**
   * The Permission rows that bound a delegation now: the row that authorized it
   * and the agent's current row for the service. Null when the authorizing row
   * is gone or either row has expired, which covers nothing; an empty list when
   * neither exists. One definition for exercise and for cold restore.
   */
  async function permissionLimitsNow(
    permissionId: string | undefined,
    agentDid: string | undefined,
    service: string,
  ): Promise<Permission[] | null> {
    const authorizing = permissionId ? await vault.getPermissionById(permissionId) : null;
    if (permissionId && !authorizing) return null;
    const current = agentDid
      ? await permissionForDidAgent(agentDid, await vault.getAgentByDid?.(agentDid) ?? null, service)
      : null;
    const limits = [authorizing, current].filter((limit): limit is Permission => limit !== null);
    if (limits.some((limit) => limit.expiresAt && limit.expiresAt.getTime() <= Date.now())) return null;
    return limits;
  }

  async function scopesAllowedNow(
    delegationId: string,
    delegation: BrokeredDelegation,
    connection?: ConnectionSnapshot,
  ): Promise<string[]> {
    const { service } = delegation;
    const permissionId = (await vault.getDelegation(delegationId))?.grant?.permissionId;
    const limits = await permissionLimitsNow(permissionId, delegation.agentDid, service);
    if (limits === null) return [];
    if (limits.length === 0) return allowAgentsWithoutPermission ? delegation.scopes : [];
    // One read of the row, through the same helper the issuance paths use, so
    // "what this connection covers" has a single definition. A handle restored
    // in this same request hands in the row its token came from, and this call
    // decides over that one rather than reading again.
    const row = connection ?? await connectionSnapshot(service, delegation.userId);
    // The authority of the credential this call forwards, which is NOT the row
    // as it stands now: a live handle forwards the provider token it was issued
    // (upstreamToken below is delegation.accessToken), and a row that replaced
    // the connection since describes a different token. A handle restored by
    // this request forwards the row it hands in, so there the row IS the
    // credential and the two reads are one.
    //
    // A handle cached before its issuance recorded this has no way to say what
    // it forwards: it fails closed rather than being judged over a row that may
    // no longer cover it.
    const credentialScopes = connection ? (connection.entry?.scopes ?? []) : delegation.credentialScopes;
    if (!credentialScopes) return [];
    // Over what the credential covers, not its bare list: an existing Notion
    // entry with no stored scopes is the whole connection, so a credential
    // issued over `read_content` never reaches `notion.read`.
    const credentialHeld = withStoredDerivedScopes(service, credentialScopes);
    // What the credential was issued over, named as the row named it: an empty
    // Notion list stands for the whole connection, and a derived read is not
    // credited to the credential unless the row it was issued over reached it.
    const credentialAuthority = credentialScopes.length > 0 ? credentialScopes : credentialHeld;
    // A row that no longer covers the forwarded credential cannot decide for it.
    // Narrowed from `repo` to `public_repo` under a handle that still holds the
    // `repo` token, the row's scopes would let that token's private reach
    // through as if it were public only, and the widened-token check below would
    // read the narrow row and report no wider token at all. A row reconnected to
    // a wider scope still covers the narrower credential, so that direction is
    // untouched. A removed row is not decided here: the route's own existence
    // check answers it (connection_revoked).
    if (row.entry && credentialAuthority.some((scope) => !connectionCovers(service, row.held, scope))) return [];
    // The widest of the two is what the Permission's derived reads are measured
    // over, so neither the credential behind the handle nor the connection as it
    // now stands can be read as narrower than it is.
    const held = [...new Set([...credentialHeld, ...row.held, ...delegation.scopes])];
    const storedScopes = row.entry?.scopes ?? [];
    return withoutRedundantDerivedScopes(service, withDerivedScopes(service, delegation.scopes)
      // A public-only grant is only honest over a token that reaches no further:
      // the credential this call forwards, and the connection as it now stands.
      .filter((scope) => !publicRepoOverWiderToken(service, scope, credentialScopes))
      .filter((scope) => !publicRepoOverWiderToken(service, scope, storedScopes))
      .filter((scope) => limits.every((limit) => permissionCovers(service, limit.allowedScopes, scope, held))));
  }

  /**
   * A token holding `repo` also reaches private repositories, so it can't honor a public_repo grant. A reconnect can widen the stored row after issuance too.
   */
  function publicRepoOverWiderToken(service: string, scope: string, stored: string[]): boolean {
    return service === 'github' && scope === 'public_repo' && stored.includes('repo');
  }

  /**
   * Provider scopes where the wider one already reaches the narrower: `repo`
   * includes public repositories, `content` includes `read_content`, `full`
   * includes `api`. A connection reconnected to the wider scope therefore still
   * covers a credential issued over the narrower one, while the reverse is what
   * /api/v1/use must refuse.
   *
   * This mirrors the `outgrown` pairs of the derived read table in
   * @credninja/protocol, which that package keeps internal. A service not listed
   * has no such pair, so there only an exact match covers.
   */
  const WIDER_SCOPE_COVERS: Readonly<Record<string, readonly [narrow: string, wide: string]>> = {
    github: ['public_repo', 'repo'],
    notion: ['read_content', 'content'],
    salesforce: ['api', 'full'],
  };

  /** Whether a connection holding `held` covers `scope`, the narrower half of a wider scope included. */
  function connectionCovers(service: string, held: readonly string[], scope: string): boolean {
    if (scopeCoveredBy(held, scope)) return true;
    const pair = Object.prototype.hasOwnProperty.call(WIDER_SCOPE_COVERS, service) ? WIDER_SCOPE_COVERS[service] : undefined;
    return pair !== undefined && scope === pair[0] && held.includes(pair[1]);
  }

  /** Two Permissions for one agent: neither can widen the other, so it gets the limits of both. */
  function tightestOf(service: string, a: Permission, b: Permission): Permission & { alsoLimitedBy?: Permission } {
    // The token is unknown here, so assume the widest: no row derives a read
    // through a narrower scope it names alone.
    const covered = (list: string[], scope: string) => permissionCovers(service, list, scope, widestDerivedReadSources());
    const rate = (limit: Permission['rateLimit']) => (limit ? limit.maxRequests / limit.windowMs : Infinity);
    // The rate limit counts against the row whose limit is tighter.
    const tighterRate = rate(a.rateLimit) <= rate(b.rateLimit) ? a : b;
    const earliest = [a.expiresAt, b.expiresAt].filter((d): d is Date => d instanceof Date).sort((x, y) => x.getTime() - y.getTime())[0];
    const ttls = [a.ttlOverride, b.ttlOverride].filter((t): t is number => typeof t === 'number');
    const approvers = [a, b].filter((p) => p.requiresApproval).map((p) => p.approver ?? 'subject');
    return {
      ...tighterRate,
      alsoLimitedBy: tighterRate === a ? b : a,
      allowedScopes: [...new Set([
        ...a.allowedScopes.filter((scope) => covered(b.allowedScopes, scope)),
        ...b.allowedScopes.filter((scope) => covered(a.allowedScopes, scope)),
      ])],
      requiresApproval: a.requiresApproval || b.requiresApproval,
      ...(approvers.length > 0 ? { approver: new Set(approvers).size > 1 ? 'both' as const : approvers[0]! } : {}),
      delegatable: a.delegatable && b.delegatable,
      maxDelegationDepth: Math.min(a.maxDelegationDepth, b.maxDelegationDepth),
      expiresAt: earliest,
      ttlOverride: ttls.length > 0 ? Math.min(...ttls) : undefined,
    };
  }

  /** Why a did:key agent holds no Permission, and what fixes it. */
  function permissionRequiredMessage(agentDid: string, service: string): string {
    return config.vaultStorage === 'sqlite'
      ? `Agent ${agentDid} holds no Permission for ${service}. An operator grants one at POST /admin/permissions (agentId, connectionId, allowedScopes).`
      : `Agent ${agentDid} holds no Permission for ${service}, and this vault cannot store one. Run with VAULT_STORAGE=sqlite and grant it at POST /admin/permissions, or set the deprecated CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true.`;
  }

  /**
   * Whether a revocation still holds this agent out of this user's service.
   * With the deprecated opt-out set it holds nothing, and `bypassed` says the
   * call is one the audit log must mark.
   */
  async function agentRevocationStatus(
    agentDid: string,
    service: string,
    userId: string,
  ): Promise<{ refused: true; cause: string } | { refused: false; bypassed: boolean }> {
    const revocation = await vault.getAgentRevocation(await agentIdsOf(agentDid), service, userId);
    if (!revocation) return { refused: false, bypassed: false };
    if (allowRedelegationAfterRevocation) return { refused: false, bypassed: true };
    return { refused: true, cause: revocation.cause };
  }

  const AGENT_ACCESS_REVOKED_MESSAGE = 'This agent\'s access to this service was revoked. An operator restores it at POST /admin/permissions/:id/restore, which keeps its limits, or grants it again at POST /admin/permissions.';

  /** Audit a refusal on revoked or absent standing, for the agent named. */
  function denyAgentStanding(agentDid: string, service: string, userId: string, error: string, correlationId: string, metadata?: Record<string, unknown>): void {
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: agentDid },
      action: 'deny',
      resource: { type: 'token', id: `${service}/${userId}` },
      outcome: 'denied',
      correlationId,
      errorMessage: error,
      ...(metadata ? { metadata } : {}),
    });
  }

  /**
   * The scopes a request asks for once Guard has decided, or null after
   * refusing. Guard was shown the scopes named, or for a request naming
   * none the stored scopes it would be granted; what Guard allowed is the
   * request. An empty request means every stored scope, so a decision that
   * allows none is refused, never read as "everything".
   */
  function guardedRequestedScopes(req: Request, res: Response, requested: string[] | undefined): string[] | undefined | null {
    const decision = (req as any).guardDecision as GuardDecision | undefined;
    if (!decision) return requested;
    const effective = decision.effectiveScopes ?? requested;
    if (!effective || effective.length === 0) {
      res.status(403).json({ error: 'invalid_scope', message: 'Guard policy allows none of the scopes this request would be granted' });
      return null;
    }
    return effective;
  }

  /** The roles an approver setting needs. */
  function approverRoles(approver: Permission['approver']): Array<'subject' | 'admin'> {
    return approver === 'both' ? ['subject', 'admin'] : [approver ?? 'subject'];
  }

  /** Whether an approval by `given` satisfies a Permission that now needs `needed`. */
  function approvalCovers(given: Permission['approver'], needed: Permission['approver']): boolean {
    const roles = approverRoles(given);
    return approverRoles(needed).every((role) => roles.includes(role));
  }

  function refusePermission(res: Response, code: string): void {
    const messages: Record<string, string> = {
      permission_expired: 'Permission has expired',
      approval_required: 'This permission requires approval: only a did:key agent\'s root delegation can be approved, by asking at /bc-authorize (CIBA)',
      rate_limited: 'Permission rate limit exceeded',
    };
    res.status(code === 'rate_limited' ? 429 : 403).json({ error: code, message: messages[code] ?? code });
  }

  async function getPermissionIfSupported(principalId: string, service: string) {
    if (!vault.getPermission) {
      return null;
    }
    try {
      return await vault.getPermission(principalId, service);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('not supported')) {
        return null;
      }
      throw err;
    }
  }

  /**
   * GET /api/token/:provider — Delegation endpoint (agent-facing)
   *
   * Returns a valid access token for the requested provider.
   * Auto-refreshes expired tokens using the stored refresh token.
   * When guard is configured, policies are evaluated before token retrieval.
   *
   * Auth: Bearer cred_at_<token>
   */
  const tokenRouteHandlers: Array<express.RequestHandler> = [tokenRateLimiter, requireAgentAuth, verifyWebBotAuth];
  if (guardMiddleware) {
    tokenRouteHandlers.push(exposeStoredScopesToGuard('user_id'), guardMiddleware);
  }

  // If you add guardMiddleware to a new agent-facing route here, also add its
  // MCP tool name to CLOUD_SERVER_GUARDED_TOOLS in
  // packages/mcp/src/guard-wiring.ts — that Set exists specifically to stop
  // packages/mcp from double-wrapping a route already guarded here with a
  // second, independently-configured CredGuard.
  /**
   * A call naming connection_id is a Cred Link call. With Link disabled the
   * server cannot check it, so it is refused before any vault access instead
   * of falling back to the legacy `default` user. Sub-delegation of a Link
   * connection is refused in Phase 1 either way.
   */
  const refuseUncheckableLinkCall = (always: boolean): express.RequestHandler => (req, res, next) => {
    const body = req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : null;
    if (body && body.connection_id !== undefined && (always || !linkService)) {
      res.status(400).json({
        error: 'invalid_request',
        message: always
          ? 'Sub-delegation of a Link connection is not supported'
          : 'connection_id names a Cred Link connection, and Cred Link is not enabled on this server',
      });
      return;
    }
    next();
  };

  // The agent a raw request names is the one whose Permission authorizes
  // issuance, though the output is a provider bearer token. When that agent
  // has a key (a did:key, or a record id whose record holds one), prove the
  // key before Guard's stored-scope lookup, token retrieval or refresh can
  // run. An agent with no key on record has nothing to prove: it is known
  // only by the name the caller gives.
  const requireRawAgentProof: express.RequestHandler = async (req, res, next) => {
    try {
      const named = req.body?.agent_did;
      const service = req.body?.service;
      if (!allowRawTokens || tokenFormatFromBody(req) !== 'raw' || req.body?.connection_id !== undefined
        || typeof named !== 'string' || typeof service !== 'string') {
        next();
        return;
      }
      // A TOFU principal has a key on record, but it is proved by its signed TOFU
      // payload, never by being named. Naming it here would issue a raw token
      // under its Permission to anyone holding the agent token.
      if (named.startsWith('tofu:')) {
        refuseDpop(res, 401, 'agent_key_required', 'A raw token for a TOFU agent is issued only to its signed TOFU request; name a did:key agent in agent_did instead');
        return;
      }
      let agentDid: string | undefined = named.startsWith('did:key:') ? named : undefined;
      if (agentDid === undefined && !named.startsWith('did:')) {
        const recordDid = (await vault.getAgent?.(named) ?? null)?.did;
        if (typeof recordDid === 'string' && recordDid.startsWith('did:key:')) agentDid = recordDid;
      }
      if (agentDid === undefined) {
        next();
        return;
      }
      const userId = requestUserId(req, res, { agent: true, source: 'body' });
      if (userId === null) return;
      if (!checkDpop(req, res, { agentDid, path: '/api/v1/delegate', resource: { type: 'connection', id: `${service}/${userId}` } })) return;
      provedRawAgentDid.set(req, agentDid);
      next();
    } catch (err) {
      next(err);
    }
  };
  const delegateRouteHandlers: Array<express.RequestHandler> = [delegateRateLimiter, requireAgentAuth, verifyWebBotAuth, refuseUncheckableLinkCall(false), requireRawAgentProof];
  if (linkService) {
    // Runs checkLinkAccess for calls naming connection_id, before Guard and
    // before any vault access, whether or not a Guard is configured.
    delegateRouteHandlers.push(linkService.delegatePrecheck);
  }
  if (guardMiddleware) {
    delegateRouteHandlers.push(assignProviderFromBody, exposeStoredScopesToGuard('user_id'), guardMiddleware);
  }

  const subdelegateRouteHandlers: Array<express.RequestHandler> = [subdelegateRateLimiter, requireAgentAuth, verifyWebBotAuth, refuseUncheckableLinkCall(true)];
  if (guardMiddleware) {
    subdelegateRouteHandlers.push(attachParentReceiptClaimsForGuard, assignProviderFromBody, guardMiddleware);
  }

  app.get('/api/token/:provider', ...tokenRouteHandlers, async (req: Request, res: Response) => {
    try {
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      if (!allowRawTokens) {
        refuseRawToken(res);
        return;
      }
      const userId = requestUserId(req, res, { agent: true });
      if (userId === null) return;
      if (rejectReservedUserId(res, userId)) return;
      if (!allowAgentsWithoutPermission) {
        refuseAnonymousRawToken(res);
        return;
      }
      const vaultEntry = await getVaultEntry(slug, userId);
      if ('status' in vaultEntry) {
        res.status(vaultEntry.status).json(vaultEntry.body);
        return;
      }
      const { entry } = vaultEntry;

      // Return the delegated token — never the refresh token
      const guardDecision = (req as any).guardDecision;
      const effectiveRequestedScopes = guardedRequestedScopes(req, res, normalizeRequestedScopes(req.query.scopes));
      if (effectiveRequestedScopes === null) return;
      const { grantedScopes, widenedScopes } = resolveGrantedScopes(slug, entry.scopes ?? [], effectiveRequestedScopes);

      if (widenedScopes.length > 0) {
        res.status(403).json({
          error: 'scope_escalation_denied',
          message: `Requested scopes exceed stored consent: ${widenedScopes.join(', ')}`,
        });
        return;
      }

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: 'server-agent' },
        action: 'access',
        resource: { type: 'connection', id: `${slug}/${userId}` },
        outcome: 'success',
        scopesRequested: effectiveRequestedScopes,
        scopesGranted: grantedScopes,
        correlationId: crypto.randomUUID(),
        metadata: { enforcementOptOuts: ['raw_tokens', 'agents_without_permission'] },
      });

      res.json({
        provider: slug,
        accessToken: entry.accessToken,
        expiresAt: entry.expiresAt?.toISOString() ?? null,
        scopes: grantedScopes,
        ...(guardDecision && {
          guard: {
            allowed: guardDecision.allowed,
            evaluationMs: guardDecision.evaluationMs,
            policies: guardDecision.results.map((r: any) => ({
              name: r.policy,
              decision: r.decision,
            })),
          },
        }),
      });
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/api/token/:provider] Error:', { provider: req.params.provider, err });
      res.status(500).json({ error: 'Failed to retrieve token' });
    }
  });

  /**
   * GET /api/v1/providers — agent-facing provider discovery.
   *
   * Distinct from the admin-only GET /providers above: agent-Bearer auth
   * instead of admin auth, and the response is stripped down to only
   * non-secret fields (slug, defaultScopes) an agent can use to discover
   * what's available before calling cred_delegate — never client
   * id/secret or any other admin-only configuration.
   */
  app.get('/api/v1/providers', tokenRateLimiter, requireAgentAuth, verifyWebBotAuth, async (_req: Request, res: Response) => {
    try {
      const providers = config.providers.map((p) => ({
        slug: p.slug,
        defaultScopes: p.defaultScopes,
      }));

      res.json({ providers });
    } catch (err) {
      console.error('[/api/v1/providers] Error:', err);
      res.status(500).json({ error: 'Failed to list providers' });
    }
  });

  app.get('/api/v1/connections', tokenRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const userId = requestUserId(req, res, { agent: true });
      if (userId === null) return;
      const entries = await vault.list({ userId });
      res.json({
        connections: entries.map((entry) => ({
          slug: entry.provider,
          scopesGranted: entry.scopes ?? [],
          consentedAt: entry.createdAt?.toISOString() ?? null,
          appClientId: null,
        })),
      });
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/api/v1/connections] Error:', err);
      res.status(500).json({ error: 'Failed to list connections' });
    }
  });

  /**
   * The Delegation Token on an exercise request (RFC 9449 Section 7.1:
   * `Authorization: DPoP <token>`), or null when the request carries none.
   */
  function presentedDelegationToken(req: Request): string | null {
    const header = req.headers.authorization;
    if (typeof header !== 'string') return null;
    const match = /^DPoP\s+([A-Za-z0-9_\-.]+)$/i.exec(header.trim());
    return match ? match[1]! : null;
  }

  // An exercise authenticates with the Delegation Token itself. A request
  // without one is authenticated as an agent call and then refused by the
  // route: an id alone authorizes nothing.
  function requireExerciseAuth(req: Request, res: Response, next: NextFunction): void {
    if (presentedDelegationToken(req) !== null) {
      next();
      return;
    }
    requireAgentAuth(req, res, next);
  }

  function refuseDelegationToken(res: Response, message: string, absent = false): void {
    // RFC 6750 Section 3.1: a request that presents no token gets the
    // challenge without an error code.
    res.set('WWW-Authenticate', absent
      ? `DPoP algs="${DPOP_ACCEPTED_ALGS.join(' ')}"`
      : `DPoP error="invalid_token", algs="${DPOP_ACCEPTED_ALGS.join(' ')}"`);
    res.status(401).json({ error: 'invalid_token', message });
  }

  /** A recorded Link binding, or null when it is not one. */
  function linkBindingFrom(value: Record<string, unknown>): LinkHandleBinding | null {
    const { connectionId, clientId, grantId, grantVersion, agentId } = value;
    if (typeof connectionId !== 'string' || typeof clientId !== 'string' || typeof grantId !== 'string'
      || typeof grantVersion !== 'number' || typeof agentId !== 'string') return null;
    return { connectionId, clientId, grantId, grantVersion, agentId };
  }

  /** Why a cold restore refused before loading the provider token. */
  type RestoreRefusal = {
    refused: 'agent_suspended' | 'permission_lapsed';
    agentDid: string;
    jkt: string | undefined;
    service: string;
    userId: string;
  };

  /**
   * The exercise state of a delegation whose token this process did not
   * issue (another replica, or before a restart): rebuilt from the recorded
   * grant, with the provider token loaded from the vault for this call (a
   * Cred Link delegation's is loaded through Link at exercise instead).
   */
  async function restoreTokenDelegation(
    delegationId: string,
    expiresAtSeconds: number,
    out?: { connection: ConnectionSnapshot | null },
  ): Promise<BrokeredDelegation | null | 'cumulative_unenforceable' | { revokedBy: string } | RestoreRefusal> {
    const record = await vault.getDelegation(delegationId);
    if (!record?.grant || !record.agentDid) return null;
    if (record.status === 'revoked') return { revokedBy: record.revokedAncestorId ?? record.id };
    const nowSeconds = Math.floor(Date.now() / 1000);
    const recordExpiresAt = record.expiresAt ? Math.floor(Date.parse(record.expiresAt) / 1000) : expiresAtSeconds;
    if (recordExpiresAt <= nowSeconds) return null;
    const grant = record.grant;
    // A running total lives in this process's ledger unless one is shared
    // (cumulativeLedgerPath). Registering the delegation afresh would reset
    // its budget, so a delegation under a cumulative bound this ledger does
    // not hold is refused, never restored with zero spent.
    if (cumulativeConstraints((grant.constraints ?? []) as DelegationConstraint[]).length > 0 && !cumulativeLedger.has(delegationId)) {
      return 'cumulative_unenforceable';
    }
    // A Cred Link delegation loads its provider token through Link at each
    // exercise; any other loads it from the vault here.
    const link = grant.link ? linkBindingFrom(grant.link) : null;
    if (grant.link && (!link || !linkService)) return null;
    let accessToken = '';
    let providerLifetime = Number.POSITIVE_INFINITY;
    // The stored scopes of the row the token above was read from. Recorded on
    // the handle with the token, so every later exercise decides over the
    // authority the handle forwards rather than over a row that replaced it.
    let credentialScopes: string[] | undefined;
    if (!link) {
      // Loading the token below reads the stored row and refreshes an expired
      // one at the provider. An agent that /api/v1/use would refuse anyway (a
      // suspended agent, or one whose Permission is gone or expired) is refused
      // here first, so it cannot make the server rotate the row.
      const refusedFor = { agentDid: record.agentDid, jkt: grant.jkt, service: record.service, userId: record.userId };
      if ((await vault.getAgentByDid?.(record.agentDid))?.status === 'suspended') {
        return { refused: 'agent_suspended', ...refusedFor };
      }
      const limits = await permissionLimitsNow(grant.permissionId, record.agentDid, record.service);
      if (limits === null || (limits.length === 0 && !allowAgentsWithoutPermission)) {
        return { refused: 'permission_lapsed', ...refusedFor };
      }
      const vaultEntry = await getVaultEntry(record.service, record.userId);
      if ('status' in vaultEntry) return null;
      accessToken = vaultEntry.entry.accessToken;
      providerLifetime = handleLifetimeSeconds(vaultEntry.entry.expiresAt);
      credentialScopes = vaultEntry.entry.scopes ?? [];
      // This row is the token this call will forward, so it is also the row the
      // call's checks are taken over: /api/v1/use decides from it rather than
      // reading the connection again, and a replacement that lands after this
      // read cannot make the decision and the credential disagree.
      if (out) {
        out.connection = {
          entry: vaultEntry.entry,
          held: withStoredDerivedScopes(record.service, vaultEntry.entry.scopes ?? []),
        };
      }
    }
    cumulativeLedger.register({
      id: delegationId,
      ...(record.parentId ? { parentId: record.parentId } : {}),
      constraints: (grant.constraints ?? []) as DelegationConstraint[],
    });
    storeBrokeredDelegation({
      delegationId,
      accessToken,
      service: record.service,
      userId: record.userId,
      scopes: grant.scopes,
      ...(link ? { link } : {}),
      ...(credentialScopes ? { credentialScopes } : {}),
      // Never cache the provider token past its own expiry, the token's, or
      // the recorded delegation's.
      expiresIn: Math.max(1, Math.min(
        expiresAtSeconds - nowSeconds,
        recordExpiresAt - nowSeconds,
        providerLifetime,
      )),
      ...(grant.constraints && grant.constraints.length > 0 ? { constraints: grant.constraints as DelegationConstraint[] } : {}),
      agentDid: record.agentDid,
      dpopJkt: grant.jkt,
      capabilities: grant.authorizationDetails as CredDelegationDetail[],
    });
    return getBrokeredDelegation(delegationId);
  }

  app.post('/api/v1/use', tokenRateLimiter, requireExerciseAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const {
        delegation_id: bodyDelegationId,
        url,
        method,
        body,
        extra_headers: extraHeaders,
      } = req.body as {
        delegation_id?: string;
        url?: string;
        method?: string;
        body?: unknown;
        extra_headers?: Record<string, string>;
      };

      const presentedToken = presentedDelegationToken(req);
      let tokenExpiresAt: number | undefined;
      let tokenBinding: { agentDid: string; jkt: string; credentialHandle: string } | undefined;
      let delegationId: string;
      if (presentedToken !== null) {
        const keys = getReceiptKeys();
        const verified = verifyDelegationToken(presentedToken, {
          issuer: config.redirectBaseUri,
          acceptedAlgs: keys.acceptedAlgs,
          resolveKey: keys.resolveKey,
          // This server minted it, on this clock: no skew allowance.
          clockSkewSeconds: 0,
        });
        if (!verified.ok) {
          refuseDelegationToken(res, `The Delegation Token is not valid (${verified.reason})`);
          return;
        }
        delegationId = verified.claims.jti;
        tokenExpiresAt = verified.claims.exp;
        tokenBinding = {
          agentDid: verified.claims.client_id,
          jkt: verified.claims.cnf.jkt,
          credentialHandle: verified.claims.credential_handle,
        };
        // A security event revokes consents (Section 8.3): no token issued
        // under a revoked consent is exercised again.
        // A delegation revoked by id reports that, as the draft requires, even
        // though revoking it also ends its consent.
        const consentRevoked = await vault.getConsentRevocation(verified.claims.consent_id);
        if (consentRevoked && await delegationRevokedBy(verified.claims.jti) === null) {
          res.status(401).json({ error: 'consent_revoked', message: 'The consent behind this delegation was revoked; ask again', reason: consentRevoked.reason });
          return;
        }
        // The caller identity guard policies key on (rate limits, audit):
        // the agent and key the token is bound to.
        (req as any).agentTokenHash = hashTokenValue(`dpop:${verified.claims.client_id}:${verified.claims.cnf.jkt}`);
        if (bodyDelegationId !== undefined && bodyDelegationId !== delegationId) {
          res.status(400).json({ error: 'invalid_request', message: 'delegation_id does not match the Delegation Token' });
          return;
        }
        // Workload identity on a brokered call (draft-ietf-wimse-http-signature-08):
        // checked in addition to the Delegation Token and its DPoP proof.
        if (externalIdentity && req.headers['workload-identity-token'] !== undefined) {
          if (await authenticateUseWorkload(req, res, verified.claims.client_id) === 'refused') return;
        }
      } else {
        // Every delegation, Cred Link's included, is exercised with its
        // Delegation Token: an id alone authorizes nothing.
        refuseDelegationToken(res, 'Present the Delegation Token as Authorization: DPoP <token>', true);
        return;
      }
      if (!url || typeof url !== 'string') {
        res.status(400).json({ error: 'url is required' });
        return;
      }
      const normalizedMethod = typeof method === 'string' ? method.toUpperCase() : '';
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(normalizedMethod)) {
        res.status(400).json({ error: 'method must be one of GET, POST, PUT, PATCH, DELETE' });
        return;
      }
      if (normalizedMethod === 'GET' && body !== undefined) {
        res.status(400).json({ error: 'GET requests cannot have a body' });
        return;
      }

      // A delegation this process has not cached is rebuilt from its record,
      // and rebuilding reads the provider token from the vault, which refreshes
      // an expired row at the provider. Prove the key the token is bound to
      // first, from the record's metadata alone, so a Delegation Token presented
      // without its key cannot make this server decrypt the row or rotate it.
      // The proof's jti is spent on verification, so it is checked once: here
      // for a restore, below for a cached handle.
      const cached = getBrokeredDelegation(delegationId);
      let proofChecked = false;
      if (!cached) {
        const record = await vault.getDelegation(delegationId);
        if (record?.grant && record.agentDid) {
          if (!tokenBinding || tokenBinding.agentDid !== record.agentDid || tokenBinding.jkt !== record.grant.jkt) {
            refuseDelegationToken(res, 'The Delegation Token does not match its delegation');
            return;
          }
          const requestHash = useRequestHashes.get(req) ?? null;
          if (requestHash === null) {
            res.status(400).json({ error: 'invalid_request', message: 'The request body has no canonical JSON form (RFC 8785)' });
            return;
          }
          if (!checkDpop(req, res, {
            agentDid: record.agentDid,
            path: '/api/v1/use',
            ath: delegationTokenAth(presentedToken),
            req: requestHash,
            resource: { type: 'token', id: `${record.service}/${record.userId}` },
          })) return;
          proofChecked = true;
        }
      }
      const restored: { connection: ConnectionSnapshot | null } = { connection: null };
      const found = cached ?? await restoreTokenDelegation(delegationId, tokenExpiresAt!, restored);
      if (found === 'cumulative_unenforceable') {
        res.status(403).json({
          error: CUMULATIVE_CONSTRAINT_UNENFORCEABLE,
          message: 'This delegation carries a cumulative constraint whose running total this server does not hold; set a shared cumulative ledger (cumulativeLedgerPath)',
        });
        return;
      }
      if (found !== null && typeof found === 'object' && 'refused' in found) {
        if (found.refused === 'agent_suspended') {
          res.status(403).json({ error: 'agent_suspended', message: 'Agent is suspended' });
          return;
        }
        refusals.record({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: found.agentDid, ...(found.jkt ? { fingerprint: found.jkt } : {}) },
          action: 'deny',
          resource: { type: 'token', id: `${found.service}/${found.userId}` },
          outcome: 'denied',
          correlationId: crypto.randomUUID(),
          errorMessage: 'scope_insufficient',
          metadata: { delegationId, method: normalizedMethod, reason: 'permission_narrowed' },
        });
        res.status(403).json({ error: 'scope_insufficient', message: 'The Permission behind this delegation no longer covers it: it was narrowed, replaced by a new grant, revoked or expired. Ask for a new delegation.' });
        return;
      }
      if (found !== null && typeof found === 'object' && 'revokedBy' in found) {
        res.status(401).json({ error: 'delegation_revoked', message: 'This delegation has been revoked', revoked_ancestor_id: found.revokedBy });
        return;
      }
      const delegation = found;
      if (!delegation) {
        refuseDelegationToken(res, 'The Delegation Token names no active delegation');
        return;
      }
      // A Link delegation's Guard identity is the Link agent it was issued
      // to, not the key: an agent minting tokens under fresh keys still
      // shares one rate-limit bucket.
      if (delegation.link) (req as any).agentTokenHash = hashTokenValue(`link:${delegation.link.agentId}`);
      // The token and the recorded delegation must name the same agent and key.
      if (!tokenBinding || tokenBinding.agentDid !== delegation.agentDid || tokenBinding.jkt !== delegation.dpopJkt) {
        refuseDelegationToken(res, 'The Delegation Token does not match its delegation');
        return;
      }
      // A token is usable only with a DPoP proof by the key it is bound to,
      // naming this token (ath) and this exact request: the proof's cred_req
      // covers the whole body (URL, method, upstream body and extra
      // headers), so it authorizes one upstream call.
      if (!proofChecked) {
        const requestHash = useRequestHashes.get(req) ?? null;
        if (requestHash === null) {
          res.status(400).json({ error: 'invalid_request', message: 'The request body has no canonical JSON form (RFC 8785)' });
          return;
        }
        if (!checkDpop(req, res, {
          agentDid: delegation.agentDid,
          path: '/api/v1/use',
          ath: delegationTokenAth(presentedToken),
          req: requestHash,
          resource: { type: 'token', id: `${delegation.service}/${delegation.userId}` },
        })) return;
      }
      const revokedBy = await delegationRevokedBy(delegationId, delegation);
      if (revokedBy !== null) {
        refuseRevokedDelegation(res, delegationId, revokedBy, delegation);
        return;
      }
      if (delegation.agentDid && (await vault.getAgentByDid?.(delegation.agentDid))?.status === 'suspended') {
        res.status(403).json({ error: 'agent_suspended', message: 'Agent is suspended' });
        return;
      }
      // Opaque restrictions survive delegation, but cannot authorize use.
      // Deny before token loading, accounting, or any upstream request.
      if (unknownConstraints(delegation.constraints ?? []).length > 0) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: brokeredActor(delegation),
          action: 'deny',
          resource: { type: 'token', id: `${delegation.service}/${delegation.userId}` },
          outcome: 'denied',
          correlationId: crypto.randomUUID(),
          errorMessage: UNKNOWN_CONSTRAINT,
          metadata: brokeredCallMetadata(delegationId, delegation, url),
        });
        res.status(403).json({ error: UNKNOWN_CONSTRAINT, message: 'This delegation carries an unimplemented constraint type' });
        return;
      }
      // Every constraint is decided from what this server measures itself
      // (Section 6.1, step 3): an agent never reports its own quantities. A
      // key with no meter cannot be decided, so the exercise is denied, as
      // under an unimplemented type. Cumulative bounds need a numeric meter.
      const allConstraints = delegation.constraints ?? [];
      const cumulative = cumulativeConstraints(allConstraints);
      const perExercise = allConstraints.filter((c) => !cumulative.includes(c));
      const unmetered = [
        ...perExercise.filter((c) => meterSide(c.key) === null),
        ...cumulative.filter((c) => meterSide(c.key) === null || c.key === 'method' || c.key === 'destination'),
      ].map((c) => c.key);
      if (unmetered.length > 0) {
        denyCumulative(delegationId, delegation, 'unmetered_constraint', unmetered, url);
        res.status(403).json({
          error: 'unmetered_constraint',
          message: 'This delegation carries a constraint on a quantity this server does not measure, so no exercise can be decided under it',
          constraints: [...new Set(unmetered)],
        });
        return;
      }
      // Link delegations: re-run the Link check (revoked, narrowed or
      // needs_reauth connections are refused at once) before anything else.
      let linkAccess: Awaited<ReturnType<LinkService['authorizeUse']>> = null;
      if (delegation.link) {
        if (!linkService) {
          res.status(404).json({ error: 'Delegation handle not found or expired' });
          return;
        }
        // The token and its DPoP proof were verified above.
        linkAccess = await linkService.authorizeUse(req, res, {
          service: delegation.service,
          scopes: delegation.scopes,
          link: delegation.link,
        }, true);
        if (!linkAccess) return;
        delegation.instanceOrigin = linkAccess.connection.instance_url
          ? new URL(linkAccess.connection.instance_url).origin
          : undefined;
      }
      // A Link delegation was just re-checked against its grant and Permission above.
      // A handle restored by this request hands in the row it loaded its token
      // from, so this check and the credential it guards are one read.
      const scopesNow = linkAccess
        ? linkAccess.effective_scopes
        : await scopesAllowedNow(delegationId, delegation, restored.connection ?? undefined);
      if (scopesNow.length === 0) {
        refuseBrokeredCall(delegationId, delegation, url, 'scope_insufficient', { method: normalizedMethod, reason: 'permission_narrowed' });
        res.status(403).json({ error: 'scope_insufficient', message: 'The Permission behind this delegation no longer covers it: it was narrowed, replaced by a new grant, revoked or expired. Ask for a new delegation.' });
        return;
      }
      const guardResult = await evaluateBrokerUseGuard(req, res, {
        delegationId,
        url,
        method: normalizedMethod,
        delegation,
        scopes: scopesNow,
        provenAgentDid: tokenBinding?.agentDid,
      });
      if (!guardResult.allowed) return;

      const upstreamUrl = resolveBrokerUrl(delegation.service, url, guardResult.effectiveScopes);
      // Every channel that could run a different method than the one classified
      // is refused rather than quietly dropped, so a caller learns it did not work.
      if (upstreamUrl && methodOverrideChannel({
        url: upstreamUrl,
        ...(classifyBrokerCalls ? { headers: extraHeaders && typeof extraHeaders === 'object' ? extraHeaders : {}, body } : {}),
      })) {
        refuseBrokeredCall(delegationId, delegation, url, 'method_override_refused', { method: normalizedMethod });
        res.status(400).json({ error: 'invalid_request', message: 'A method override is not allowed: the call runs the method it names' });
        return;
      }
      if (!upstreamUrl || (linkAccess && !linkService!.upstreamAllowed(linkAccess.connection, upstreamUrl))) {
        refuseBrokeredCall(delegationId, delegation, url, 'url_refused', { method: normalizedMethod });
        res.status(400).json({ error: `URL is not allowed for ${delegation.service} with the delegated scopes` });
        return;
      }
      // Any *.salesforce.com or *.force.com host passes the grammar above, and
      // anyone can have one, so a Salesforce token goes only to the instance
      // stored for its connection. This has no opt-out. (Link connections are
      // held to theirs by upstreamAllowed.)
      if (delegation.service === 'salesforce' && !delegation.link) {
        const stored = await vault.getStored({ provider: delegation.service, userId: delegation.userId });
        const storedOrigin = stored?.instanceUrl ? new URL(stored.instanceUrl).origin : undefined;
        // The handle holds the token of the org it was issued for: a reconnect to
        // another org must not send that token to the new host, or the new org's
        // token to anyone holding the old delegation.
        const issuedFor = (await vault.getDelegation(delegationId))?.grant?.instanceOrigin;
        delegation.instanceOrigin = issuedFor !== undefined && issuedFor === storedOrigin ? storedOrigin : undefined;
        if (!delegation.instanceOrigin || new URL(upstreamUrl).origin !== delegation.instanceOrigin) {
          const error = storedOrigin ? 'salesforce_instance_mismatch' : 'salesforce_instance_unknown';
          refuseBrokeredCall(delegationId, delegation, url, error, { method: normalizedMethod });
          res.status(400).json({
            error,
            message: storedOrigin
              ? 'This delegation is not for that Salesforce instance. Ask for a new delegation if the connection has moved.'
              : 'This Salesforce connection has no stored instance, so no host can be trusted with its token. Reconnect it.',
            ...(storedOrigin ? {} : { consent_url: buildConsentUrl({ service: delegation.service, userId: delegation.userId, scopes: delegation.scopes }) }),
          });
          return;
        }
      }
      // Classify the exact URL, method and body that will be forwarded.
      if (classifyBrokerCalls) {
        const verdict = contentTypeMismatch(extraHeaders && typeof extraHeaders === 'object' ? extraHeaders : {})
          ? { outcome: 'not_mapped' as const, reason: 'content_type' }
          : evaluateOperation({ service: delegation.service, method: normalizedMethod, url: upstreamUrl, body }, guardResult.effectiveScopes);
        if (verdict.outcome === 'not_mapped') {
          refuseBrokeredCall(delegationId, delegation, upstreamUrl, 'operation_not_mapped', { method: normalizedMethod, reason: verdict.reason });
          res.status(403).json({ error: 'operation_not_mapped', message: `This server does not map this ${delegation.service} call to a scope, so it is refused` });
          return;
        }
        if (verdict.outcome === 'insufficient') {
          refuseBrokeredCall(delegationId, delegation, upstreamUrl, 'scope_insufficient', { method: normalizedMethod, access: verdict.access });
          res.status(403).json({ error: 'scope_insufficient', message: `This delegation's scopes do not cover this ${verdict.access} call`, needs_one_of: verdict.needs });
          return;
        }
      }
      // The token's capabilities narrow the scopes further: a catalogue
      // operation allows one method and URL template, a resource one
      // repository or file (Section 5.2).
      if (delegation.capabilities && !capabilitiesAllow(
        delegation.capabilities,
        delegation.service,
        normalizedMethod,
        upstreamUrl,
        (ops) => {
          // The scope operations this token names, held to what it may do now.
          // Through coverage on both sides: `repo` operations under a Permission since
          // narrowed to github.read still reach reads, and github.read operations
          // under a `repo` token never reach more.
          const named = withDerivedScopes(delegation.service, guardResult.effectiveScopes)
            .filter((scope) => withDerivedScopes(delegation.service, ops).includes(scope));
          if (named.length === 0) return false;
          return classifyBrokerCalls
            ? evaluateOperation({ service: delegation.service, method: normalizedMethod, url: upstreamUrl, body }, named).outcome === 'allowed'
            : resolveBrokerUrl(delegation.service, url, named) !== null;
        },
      )) {
        // Written each time: which operation was tried outside the capability is the point of the record.
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: brokeredActor(delegation),
          action: 'deny',
          resource: { type: 'token', id: `${delegation.service}/${delegation.userId}` },
          outcome: 'denied',
          correlationId: crypto.randomUUID(),
          errorMessage: 'capability_denied',
          metadata: { ...brokeredCallMetadata(delegationId, delegation, upstreamUrl), method: normalizedMethod },
        });
        res.status(403).json({ error: 'capability_denied', message: 'This call is outside the delegation\'s capabilities' });
        return;
      }

      // A listing with a page-size parameter is capped up front at the
      // tightest per-exercise bound on its item count, so the provider never
      // returns more than the delegation allows.
      let meteredUrl = upstreamUrl;
      const itemCap = perExercise
        .filter((c) => ITEM_KEYS.includes(c.key) && typeof (c as { max?: unknown }).max === 'number')
        .reduce<number | null>((cap, c) => Math.min(cap ?? Infinity, (c as { max: number }).max), null);
      const page = itemCap !== null && delegation.capabilities
        ? matchedPageParam(delegation.capabilities, delegation.service, normalizedMethod, upstreamUrl)
        : null;
      if (page && itemCap !== null) {
        const capped = new URL(upstreamUrl);
        const asked = Number(capped.searchParams.get(page.param));
        const size = Math.max(1, Math.min(page.max, itemCap, Number.isFinite(asked) && asked > 0 ? asked : Infinity));
        capped.searchParams.set(page.param, String(size));
        meteredUrl = capped.toString();
      }
      const requestMeasure = {
        method: normalizedMethod,
        // The URL as asked for: the page cap only rewrites the query.
        destination: upstreamUrl,
        // Everything the call carries upstream: body, query and forwarded headers.
        requestBytes: (body === undefined ? 0 : Buffer.byteLength(JSON.stringify(body), 'utf8'))
          + Buffer.byteLength(new URL(meteredUrl).search, 'utf8')
          + Object.entries(extraHeaders && typeof extraHeaders === 'object' ? extraHeaders : {})
            .filter(([key, value]) => isForwardableBrokerHeader(key, value))
            .reduce((n, [key, value]) => n + Buffer.byteLength(`${key}: ${String(value)}`, 'utf8'), 0),
      };
      for (const c of perExercise.filter((x) => meterSide(x.key) === 'request')) {
        const measured = REQUEST_METERS[c.key]!(requestMeasure);
        // HTTP methods compare in upper case, whatever case the bound names them in.
        const constraint = c.key === 'method'
          ? Object.fromEntries(Object.entries(c).map(([k, v]) => [k, Array.isArray(v) ? v.map((m) => (typeof m === 'string' ? m.toUpperCase() : m)) : v])) as typeof c
          : c;
        // A destination prefix holds at a URL boundary, not mid-segment.
        const violation = c.key === 'destination' && typeof (c as { prefix?: unknown }).prefix === 'string'
          ? (destinationWithinPrefix(String(measured), (c as { prefix: string }).prefix) ? null : 'destination is outside the allowed prefix')
          : exerciseConstraintViolation(constraint, measured);
        if (violation) {
          denyCumulative(delegationId, delegation, 'ceiling_exceeded', [c.key], upstreamUrl);
          res.status(403).json({ error: 'ceiling_exceeded', message: violation, constraint: c.key });
          return;
        }
      }

      let upstreamToken = delegation.accessToken;
      if (linkAccess && delegation.link) {
        const loaded = await linkService!.loadUseToken(req, res, linkAccess, delegation.link.agentId);
        if (loaded === null) return;
        upstreamToken = loaded;
      }

      // The guard and Link checks above can wait on I/O. A revocation that
      // landed meanwhile must still stop this call before it goes upstream.
      const revokedInFlight = await delegationRevokedBy(delegationId, delegation);
      if (revokedInFlight !== null) {
        refuseRevokedDelegation(res, delegationId, revokedInFlight, delegation);
        return;
      }
      // A non-Link handle holds a copy of its connection's token. The
      // connection must still exist: this catches a revocation in another
      // process, or one that raced this handle's issuance.
      if (!delegation.link && !(await vault.getStored({ provider: delegation.service, userId: delegation.userId }))) {
        brokeredDelegations.delete(delegationId);
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: brokeredActor(delegation),
          action: 'deny',
          resource: { type: 'token', id: `${delegation.service}/${delegation.userId}` },
          outcome: 'denied',
          correlationId: crypto.randomUUID(),
          errorMessage: 'connection_revoked',
          metadata: brokeredCallMetadata(delegationId, delegation, upstreamUrl),
        });
        res.status(401).json({ error: 'connection_revoked', message: 'The connection behind this handle has been revoked' });
        return;
      }

      const requestQuantities: Record<string, number> = {};
      for (const c of cumulative.filter((x) => meterSide(x.key) === 'request')) {
        requestQuantities[c.key] = REQUEST_METERS[c.key]!(requestMeasure) as number;
      }
      let requestDebit: Extract<ReturnType<CumulativeLedger['debit']>, { ok: true }> | null = null;
      if (Object.keys(requestQuantities).length > 0) {
        const debit = cumulativeLedger.debit(delegationId, requestQuantities);
        if (debit.ok) requestDebit = debit;
        if (!debit.ok) {
          const error = debit.reason === 'exceeded' ? 'cumulative_constraint_exceeded' : CUMULATIVE_CONSTRAINT_UNENFORCEABLE;
          denyCumulative(delegationId, delegation, error, debit.key ? [debit.key] : cumulative.map((c) => c.key), upstreamUrl);
          res.status(403).json({ error, message: debit.message, ...(debit.key ? { constraint: debit.key, type: debit.type } : {}) });
          return;
        }
      }

      const hasBody = body !== undefined;
      const sanitizedExtraHeaders = extraHeaders && typeof extraHeaders === 'object'
        ? Object.fromEntries(
            Object.entries(extraHeaders).filter(([key, value]) => {
              // Checked above, and always JSON: the broker sets it itself.
              if (classifyBrokerCalls && key.trim().toLowerCase() === 'content-type') return false;
              return isForwardableBrokerHeader(key, value);
            }),
          )
        : {};

      // A call that never reaches its upstream gives its request-side debit back.
      const refundRequestDebit = () => {
        if (requestDebit) cumulativeLedger.refund(requestDebit.debited, requestQuantities);
        requestDebit = null;
      };
      let upstream: globalThis.Response;
      try {
        upstream = await fetch(meteredUrl, {
        method: normalizedMethod,
        redirect: 'manual',
        headers: {
          Authorization: `Bearer ${upstreamToken}`,
          Accept: 'application/json',
          'User-Agent': 'Cred-Server/1.0',
          ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
          ...sanitizedExtraHeaders,
        },
        body: hasBody ? JSON.stringify(body) : undefined,
        });
      } catch (err) {
        refundRequestDebit();
        // The error text can quote the URL, so it stays out of the log.
        refuseBrokeredCall(delegationId, delegation, upstreamUrl, 'upstream_unreachable', { method: normalizedMethod }, 'error');
        throw err;
      }

      const contentType = upstream.headers.get('content-type') ?? '';
      const raw = await upstream.text();
      const truncated = raw.length > MAX_BROKER_RESPONSE_BYTES;
      const responseBody = truncated ? raw.slice(0, MAX_BROKER_RESPONSE_BYTES) : raw;
      let parsedBody: unknown = responseBody;
      try {
        parsedBody = JSON.parse(responseBody);
      } catch {
        // Leave non-JSON responses as text.
      }

      // Response-side bounds are known only now, measured on the whole body
      // (not the part returned). Over a limit, the response is withheld.
      let fullParsed: unknown;
      let isJson = false;
      try {
        fullParsed = JSON.parse(raw);
        isJson = true;
      } catch {
        // Not JSON: record counts cannot be measured.
      }
      const responseMeasure = {
        responseBytes: Buffer.byteLength(raw, 'utf8'),
        items: countItems(fullParsed, isJson, raw.trim() === ''),
      };
      const withhold = (constraint: string, detail: string, error = 'ceiling_exceeded') => {
        // The call ran upstream (a write is done): audit it as performed and
        // tell the agent its status, so it does not retry a completed write.
        // The measurement stays in the audit log, not the response.
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: brokeredActor(delegation),
          action: 'access',
          resource: { type: 'connection', id: `${delegation.service}/${delegation.userId}` },
          outcome: 'denied',
          correlationId: crypto.randomUUID(),
          errorMessage: error,
          metadata: { ...brokeredCallMetadata(delegationId, delegation, upstreamUrl), withheld: true, constraint, detail, method: normalizedMethod, upstreamStatus: upstream.status },
        });
        res.status(403).json({
          error,
          message: 'The call ran upstream, but its response exceeds a ceiling of this delegation and was withheld',
          constraint,
          withheld: true,
          upstream_status: upstream.status,
        });
      };
      for (const c of perExercise.filter((x) => meterSide(x.key) === 'response')) {
        const measured = RESPONSE_METERS[c.key]!(responseMeasure);
        const violation = exerciseConstraintViolation(c, measured ?? undefined);
        if (violation) {
          if (measured === null) withhold(c.key, `${c.key} cannot be measured on a non-JSON response`, 'unmeasurable_response');
          else withhold(c.key, violation);
          return;
        }
      }
      const responseQuantities: Record<string, number> = {};
      for (const c of cumulative.filter((x) => meterSide(x.key) === 'response')) {
        const measured = RESPONSE_METERS[c.key]!(responseMeasure);
        if (measured === null) {
          withhold(c.key, `${c.key} cannot be measured on a non-JSON response`, 'unmeasurable_response');
          return;
        }
        responseQuantities[c.key] = measured;
      }
      if (Object.keys(responseQuantities).length > 0) {
        const debit = cumulativeLedger.debit(delegationId, responseQuantities);
        if (!debit.ok) {
          const error = debit.reason === 'exceeded' ? 'cumulative_constraint_exceeded' : CUMULATIVE_CONSTRAINT_UNENFORCEABLE;
          withhold(debit.key ?? Object.keys(responseQuantities)[0]!, debit.message, error);
          return;
        }
      }

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: brokeredActor(delegation),
        action: 'access',
        resource: { type: 'connection', id: `${delegation.service}/${delegation.userId}` },
        outcome: upstream.ok ? 'success' : 'error',
        scopesGranted: guardResult.effectiveScopes,
        correlationId: crypto.randomUUID(),
        metadata: {
          ...brokeredCallMetadata(delegationId, delegation, upstreamUrl),
          brokered: true,
          method: normalizedMethod,
          status: upstream.status,
          ...(guardResult.decision ? {
            guard: {
              allowed: guardResult.decision.allowed,
              evaluationMs: guardResult.decision.evaluationMs,
              policies: guardResult.decision.results.map((result) => ({
                name: result.policy,
                decision: result.decision,
              })),
            },
          } : {}),
        },
      });

      res.json({
        status: upstream.status,
        ok: upstream.ok,
        contentType: contentType.split(';')[0].trim(),
        body: parsedBody,
        ...(truncated ? { truncated: true, truncatedAt: MAX_BROKER_RESPONSE_BYTES } : {}),
      });
    } catch (err) {
      // The error's text and cause can quote the upstream URL and its query.
      console.error('[/api/v1/use] Error:', err instanceof Error ? err.name : 'unknown');
      res.status(502).json({ error: 'Brokered upstream request failed' });
    }
  });

  app.post('/api/v1/delegate', ...delegateRouteHandlers, async (req: Request, res: Response) => {
    const correlationId = crypto.randomUUID();

    try {
      // Link Delegation Tokens carry no ceilings yet, so a Link request that
      // sends some would get an unbounded token. Refuse rather than drop them.
      if (linkService && req.body?.connection_id !== undefined && req.body?.constraints !== undefined) {
        res.status(400).json({
          error: 'invalid_constraints',
          message: 'constraints are not supported on Cred Link delegation (connection_id)',
        });
        return;
      }
      // Capabilities live in a Delegation Token: a raw token or a Cred Link
      // handle could not be held to them, so refuse rather than drop them.
      if (req.body?.authorization_details !== undefined
        && (tokenFormatFromBody(req) === 'raw' || req.body?.connection_id !== undefined)) {
        res.status(400).json({
          error: 'invalid_authorization_details',
          message: 'authorization_details needs a Delegation Token: not supported with token_format "raw" or on Cred Link delegation (connection_id)',
        });
        return;
      }
      if (linkService && await linkService.handleDelegate(req, res)) return;

      const {
        service,
        appClientId = 'local',
        scopes,
        constraints: requestedConstraintsRaw,
        authorization_details: requestedCapabilities,
        agent_did: agentDid,
        tofu_fingerprint: tofuFingerprint,
        tofu_payload: tofuPayload,
        tofu_signature: tofuSignature,
      } = req.body as {
        service?: string;
        user_id?: string;
        appClientId?: string;
        scopes?: string[];
        /**
         * Optional ceilings the root receipt should carry, in the wire
         * shape of asor-01 section 4.2: [{key, max}] or [{key, rank}].
         * Every hop below must restate each at least as tight.
         */
        constraints?: unknown;
        /** RFC 9396 capabilities (type cred_delegation); default: the granted scopes. */
        authorization_details?: unknown;
        agent_did?: string;
        tofu_fingerprint?: string;
        tofu_payload?: string;
        tofu_signature?: string;
      };

      if (!service || typeof service !== 'string') {
        res.status(400).json({ error: 'service is required' });
        return;
      }
      if (tokenFormatFromBody(req) === 'raw' && !allowRawTokens) {
        refuseRawToken(res);
        return;
      }
      if (tokenFormatFromBody(req) === 'raw' && !agentDid && !allowAgentsWithoutPermission) {
        refuseAnonymousRawToken(res);
        return;
      }
      const chainProfile = chainProfileRequest(req.body, agentDid);
      if (!chainProfile.ok) {
        res.status(400).json(chainProfile.body);
        return;
      }

      if (invalidConstraintJson.has(req)) {
        res.status(400).json({ error: 'invalid_constraints', message: 'Constraint-bearing requests must use strict JSON' });
        return;
      }
      const rootConstraints = parseConstraints(requestedConstraintsRaw);
      if (!rootConstraints.ok) {
        res.status(400).json({ error: 'invalid_constraints', message: rootConstraints.message });
        return;
      }
      if (tokenFormatFromBody(req) === 'raw' && unknownConstraints(rootConstraints.constraints).length > 0) {
        res.status(403).json({ error: UNKNOWN_CONSTRAINT, message: 'A raw token cannot enforce an unimplemented constraint type' });
        return;
      }
      // A rank label with no registered ordering would parse, be minted, and
      // then fail every later hop's subsumption check. Refuse at issuance.
      const unresolvableRoot = unresolvableRankLabels(rootConstraints.constraints);
      if (unresolvableRoot.length > 0) {
        res.status(400).json({ error: 'invalid_constraints', message: `No rank ordering is registered for: ${unresolvableRoot.join(', ')}` });
        return;
      }
      // max is per action only (asor-02 section 4.2): refuse to mint a
      // running-count bound under it.
      const rootProducerViolations = producerConstraintViolations(rootConstraints.constraints);
      if (rootProducerViolations.length > 0) {
        res.status(400).json({ error: 'invalid_constraints', message: rootProducerViolations.join('; ') });
        return;
      }
      // Handles are the default format, but a service with no brokered-use
      // path could never redeem one. Such a service needs an explicit
      // token_format "raw" rather than a silent fallback to a raw token.
      // A Delegation Token is bound to the key of the agent it names
      // (cnf.jkt), so it can only be issued to a did:key agent.
      if (tokenFormatFromBody(req) === 'handle' && !dpopBindingFor(agentDid)) {
        res.status(400).json({
          error: 'agent_key_required',
          message: 'A Delegation Token is bound to the agent\'s key: send agent_did as a did:key and a DPoP proof by that key',
        });
        return;
      }
      if (tokenFormatFromBody(req) === 'handle' && !isBrokerableService(service)) {
        res.status(400).json({
          error: 'brokered_format_unsupported',
          message: `'${service}' has no brokered-use path; request token_format "raw" to receive the provider token`,
        });
        return;
      }
      // A raw provider token leaves the server, so nothing can hold it to a
      // running total. Under a cumulative constraint only a brokered handle
      // is issued, and /api/v1/use debits the running total on each
      // exercise (asor-02 section 6, step 8). Checked before any vault lookup.
      if (tokenFormatFromBody(req) === 'raw' && cumulativeConstraints(rootConstraints.constraints).length > 0) {
        res.status(400).json({
          error: CUMULATIVE_CONSTRAINT_UNENFORCEABLE,
          message: 'A raw token cannot be held to a cumulative constraint (max_lifetime, max_subtree); request token_format "handle"',
        });
        return;
      }

      const userId = requestUserId(req, res, { agent: true, source: 'body' });
      if (userId === null) return;
      // The handle is bound to the key of the agent it names. The agent
      // proves it holds that key before the handle exists, so a request
      // cannot bind a handle to a key it does not hold.
      if (tokenFormatFromBody(req) === 'handle'
        && !checkDpop(req, res, { agentDid, path: '/api/v1/delegate', resource: { type: 'connection', id: `${service}/${userId}` } })) {
        return;
      }
      const requestedScopes = normalizeRequestedScopes(scopes);
      const vaultEntry = await getVaultEntry(service, userId);
      if ('status' in vaultEntry) {
        if (vaultEntry.status === 404 && getProviderConfig(service)) {
          res.status(403).json({
            error: 'consent_required',
            message: `No credentials stored for '${service}/${userId}'. Connect the service before requesting delegation.`,
            consent_url: buildConsentUrl({
              service,
              userId,
              appClientId,
              scopes: requestedScopes,
            }),
          });
          return;
        }
        res.status(vaultEntry.status).json(vaultEntry.body);
        return;
      }
      const { entry } = vaultEntry;
      // A Salesforce connection made before instances were recorded has nowhere its
      // token can be sent. Connecting again records one.
      if (service === 'salesforce' && tokenFormatFromBody(req) === 'handle' && !entry.instanceUrl) {
        res.status(403).json({
          error: 'consent_required',
          message: 'This Salesforce connection has no stored instance. Connect it again.',
          consent_url: buildConsentUrl({ service, userId, appClientId, scopes: requestedScopes }),
        });
        return;
      }
      const webBotAuthIdentity = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;
      const effectiveRequestedScopes = guardedRequestedScopes(req, res, requestedScopes);
      if (effectiveRequestedScopes === null) return;
      const tokenFormat = tokenFormatFromBody(req);

      let principalId: string | null = null;
      let principalFingerprint: string | undefined;
      let allowedByPrincipal: string[] | undefined;
      let authorizingPermission: Permission | null = null;
      let didAgentRecord: AgentRecord | null = null;
      if (agentDid && vault.getAgentByDid) {
        // Named by DID or by record id, a revoked agent is a revoked agent.
        didAgentRecord = await vault.getAgentByDid(agentDid) ?? (agentDid.startsWith('did:') ? null : await vault.getAgent?.(agentDid) ?? null);
        if (didAgentRecord?.status === 'revoked') {
          writeAuditEventIfSupported({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: agentDid },
            action: 'deny',
            resource: { type: 'token', id: `${service}/${userId}` },
            outcome: 'denied',
            scopesRequested: effectiveRequestedScopes,
            correlationId,
            errorMessage: 'agent_revoked',
          });
          res.status(403).json({ error: 'agent_revoked', message: 'Agent has been revoked' });
          return;
        }
        if (didAgentRecord?.status === 'suspended') {
          res.status(403).json({ error: 'agent_suspended', message: 'Agent is suspended' });
          return;
        }
        if (didAgentRecord?.scopeCeiling.length && effectiveRequestedScopes?.length) {
          const unauthorizedScopes = effectiveRequestedScopes.filter((scope) => !ceilingCovers(service, didAgentRecord!.scopeCeiling, scope));
          if (unauthorizedScopes.length > 0) {
            res.status(403).json({
              error: 'scope_ceiling_exceeded',
              message: `Agent scope ceiling exceeded: ${unauthorizedScopes.join(', ')}`,
            });
            return;
          }
        }
      }
      if (tofuFingerprint || tofuPayload || tofuSignature) {
        if (!tofuFingerprint || !tofuPayload || !tofuSignature) {
          res.status(400).json({
            error: 'tofu_fingerprint, tofu_payload, and tofu_signature must all be provided together',
          });
          return;
        }

        let resolved;
        try {
          resolved = await resolveTofuPrincipal(
            tofu,
            {
              fingerprint: tofuFingerprint,
              payloadBase64: tofuPayload,
              signatureBase64: tofuSignature,
            },
            {
              service,
              userId,
              appClientId,
              requestedScopes: effectiveRequestedScopes,
            },
            new Date(),
            tofuProofSeen,
          );
        } catch (err) {
          res.status(403).json({ error: err instanceof Error ? err.message : 'Invalid TOFU proof' });
          return;
        }

        principalId = resolved.principal.principalId;
        principalFingerprint = resolved.principal.fingerprint;
        const permission = await getPermissionIfSupported(principalId, service);
        authorizingPermission = permission;
        const permissionDenied = permission ? await permissionRefusal(permission) : null;
        if (permissionDenied) {
          writeAuditEventIfSupported({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: principalId },
            action: 'deny',
            resource: { type: 'permission', id: permission!.id },
            outcome: 'denied',
            scopesRequested: effectiveRequestedScopes,
            correlationId,
            errorMessage: permissionDenied,
          });
          refusePermission(res, permissionDenied);
          return;
        }
        try {
          const authorization = computeTofuAuthorization(resolved.principal, permission);
          allowedByPrincipal = authorization.allowedScopes;
        } catch (err) {
          res.status(403).json({ error: err instanceof Error ? err.message : 'TOFU authorization denied' });
          return;
        }
      }

      // A did:key agent's Permission can require approval (Section 8.1): the
      // delegation is then issued only under a CIBA consent that still
      // covers it (unexpired, unrevoked, at least as wide), else the agent
      // asks at /bc-authorize.
      // Looked up whatever else the request carries: TOFU fields beside a
      // did:key must not step around the did's own Permission.
      let approvalRequired = false;
      let didPermission: Permission | null = null;
      const enforcementOptOuts: string[] = [];
      if (tokenFormat === 'raw') {
        enforcementOptOuts.push('raw_tokens');
        if (!agentDid) enforcementOptOuts.push('agents_without_permission');
      }
      if (agentDid) {
        const standing = await agentRevocationStatus(agentDid, service, userId);
        if (standing.refused) {
          denyAgentStanding(agentDid, service, userId, 'agent_access_revoked', correlationId, { cause: standing.cause });
          res.status(403).json({ error: 'agent_access_revoked', message: AGENT_ACCESS_REVOKED_MESSAGE });
          return;
        }
        if (standing.bypassed) enforcementOptOuts.push('redelegation_after_revocation');
        const agentPermission = await permissionForDidAgent(agentDid, didAgentRecord, service);
        if (agentPermission) {
          didPermission = agentPermission;
          authorizingPermission ??= agentPermission;
          const refusal = await permissionRefusal(agentPermission);
          if (refusal === 'approval_required') approvalRequired = true;
          else if (refusal) {
            refusePermission(res, refusal);
            return;
          }
        } else if (allowAgentsWithoutPermission) {
          // This opt-out is about agents nobody granted, not agents someone
          // revoked: a new key must not walk around a hold on this user's service.
          if (!allowRedelegationAfterRevocation && !didAgentRecord && (await vault.listAgentRevocations({ service, userId })).length > 0) {
            denyAgentStanding(agentDid, service, userId, 'agent_access_revoked', correlationId, { cause: 'hold_on_service' });
            res.status(403).json({ error: 'agent_access_revoked', message: AGENT_ACCESS_REVOKED_MESSAGE });
            return;
          }
          enforcementOptOuts.push('agents_without_permission');
        } else {
          denyAgentStanding(agentDid, service, userId, 'permission_required', correlationId);
          res.status(403).json({ error: 'permission_required', message: permissionRequiredMessage(agentDid, service) });
          return;
        }
      }
      if (approvalRequired && tokenFormat !== 'handle') {
        res.status(403).json({ error: 'approval_required', message: 'This permission requires approval, which only a Delegation Token can carry' });
        return;
      }

      // A request that names no agent (only a raw token can: see the
      // agent_key_required check) identifies nobody a Permission could be for.
      const principalScopes = (entry.scopes ?? []).filter((scope) => !principalId || !allowedByPrincipal || allowedByPrincipal.includes(scope));
      const { grantedScopes, widenedScopes } = resolveGrantedScopes(
        service,
        agentDid ? scopesForDidAgent(service, principalScopes, didAgentRecord, didPermission) : principalScopes,
        effectiveRequestedScopes,
      );

      if (widenedScopes.length > 0) {
        res.status(403).json({
          error: 'scope_escalation_denied',
          message: `Requested scopes exceed stored consent: ${widenedScopes.join(', ')}`,
        });
        return;
      }

      // A raw token is the whole connection, whatever its label: never hand one to
      // an agent whose Permission reaches nothing on it.
      if (tokenFormat === 'raw' && didPermission && grantedScopes.length === 0) {
        res.status(403).json({ error: 'no_scopes_granted', message: 'This agent\'s Permission covers none of this connection\'s scopes' });
        return;
      }
      // A provider token has the connection's whole scope, and a derived scope
      // holds only at the broker: a raw token cannot be what it describes.
      if (tokenFormat === 'raw' && grantedScopes.some((scope) => isBrokerOnlyScope(service, scope))) {
        res.status(400).json({
          error: 'invalid_scope',
          message: 'A read scope Cred derives holds only at the broker, so it cannot be issued as a raw token; request token_format "handle"',
        });
        return;
      }

      // Nor to one whose Permission covers only part of it: the token would do the rest.
      if (tokenFormat === 'raw' && didPermission) {
        const uncovered = (entry.scopes ?? []).filter((scope) => !grantedScopes.some((granted) => scopeEquivalent(granted, scope)));
        if (uncovered.length > 0) {
          res.status(403).json({ error: 'raw_token_wider_than_grant', message: 'A raw token carries every scope on the connection, and this agent\'s Permission does not cover them all. Use token_format "handle"' });
          return;
        }
      }

      const delegationId = `del_${crypto.randomUUID().replace(/-/g, '')}`;
      const expiresIn = handleLifetimeSeconds(entry.expiresAt);

      // The receipt comes first: the Delegation Token's prf names it. It is
      // released only once the delegation is recorded below.
      const receipt = agentDid
        ? createReceipt({
            agentDid,
            service,
            userId,
            appClientId,
            scopes: grantedScopes,
            delegationId,
            chainDepth: 0,
            receiptClaims: extractTrustedReceiptClaims(req),
            constraints: rootConstraints.constraints,
            ...(chainProfile.wanted ? { chainProfile: { format: 'agent_delegation' as const, jti: delegationId, scopeMapping: 'identity' as const } } : {}),
          })
        : undefined;

      let grant: DelegationGrant | undefined;
      if (tokenFormat === 'handle') {
        if (grantedScopes.length === 0) {
          res.status(400).json({ error: 'invalid_scope', message: 'A Delegation Token needs at least one granted scope' });
          return;
        }
        let capabilities: CredDelegationDetail[] | undefined;
        if (requestedCapabilities !== undefined) {
          const checked = validateCapabilities(requestedCapabilities, service, grantedScopes);
          if (!checked.ok) {
            res.status(400).json({ error: 'invalid_authorization_details', message: checked.message });
            return;
          }
          capabilities = checked.details;
        }
        let reusedConsentId: string | null = null;
        if (approvalRequired) {
          reusedConsentId = await reusableConsent({
            subject: userId,
            agentDid: agentDid!,
            service,
            capabilities: capabilities ?? capabilitiesFor(service, grantedScopes),
            constraints: rootConstraints.constraints,
            appClientId,
            approver: didPermission?.approver,
          });
          if (!reusedConsentId) {
            res.status(403).json({
              error: 'approval_required',
              message: 'This permission requires approval: ask at /bc-authorize (CIBA) and poll the token endpoint',
              backchannel_authentication_endpoint: `${publicBaseUri()}/bc-authorize`,
            });
            return;
          }
        }
        const consentId = reusedConsentId ?? await recordRootConsent({
          userId, agentDid: agentDid!, service, scopes: grantedScopes, permission: authorizingPermission, delegationId,
          ...(capabilities ? { capabilities } : {}),
        });
        grant = newDelegationGrant({
          ...(entry.instanceUrl ? { instanceUrl: entry.instanceUrl } : {}),
          ...(authorizingPermission ? { permissionId: authorizingPermission.id } : {}),
          agentDid,
          service,
          scopes: grantedScopes,
          appClientId,
          constraints: rootConstraints.constraints,
          consentId,
          prf: [receiptContentId(receipt!)],
          ...(capabilities ? { capabilities } : {}),
        })!;
      }

      const recorded = await recordIssuedDelegation(res, {
        id: delegationId,
        parentId: null,
        agentDid: agentDid ?? null,
        service,
        userId,
        chainDepth: 0,
        expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
        ...(grant ? { grant } : {}),
      }, correlationId);
      if (!recorded) return;
      let agentDelegationToken: string | undefined;
      if (chainProfile.wanted && receipt && agentDid) {
        const minted = mintChainProfileToken({
          receipt,
          agentDid,
          userId,
          scopes: grantedScopes,
          constraints: rootConstraints.constraints,
          delegationId,
          audience: chainProfile.audience,
          delMaxDepth: chainProfile.delMaxDepth,
        });
        if (!minted.ok) {
          res.status(400).json(minted.body);
          return;
        }
        agentDelegationToken = minted.token;
      }

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: {
          type: 'agent',
          id: principalId ?? webBotAuthIdentity?.agentId ?? agentDid ?? 'server-agent',
          fingerprint: principalFingerprint ?? webBotAuthIdentity?.fingerprint ?? agentDid,
        },
        action: 'delegate',
        resource: { type: 'token', id: delegationId },
        outcome: 'success',
        scopesRequested: effectiveRequestedScopes,
        scopesGranted: grantedScopes,
        correlationId,
        metadata: {
          identitySource: tofuFingerprint
            ? 'tofu'
            : (webBotAuthIdentity ? 'web-bot-auth' : (agentDid ? 'did' : 'agent-token')),
          tofuFingerprint,
          agentDid,
          webBotAuthKeyId: webBotAuthIdentity?.keyId,
          signatureAgent: webBotAuthIdentity?.signatureAgent,
          receiptClaims: extractTrustedReceiptClaims(req),
          ...(enforcementOptOuts.length > 0 ? { enforcementOptOuts } : {}),
        },
      });

      res.json(buildDelegationResponse({
        tokenFormat,
        ...(grant ? { grant } : {}),
        accessToken: entry.accessToken,
        expiresIn,
        service,
        userId,
        scopes: grantedScopes,
        delegationId,
        receipt,
        constraints: rootConstraints.constraints,
        ...(agentDelegationToken ? { agentDelegationToken } : {}),
        ...(agentDid ? { agentDid } : {}),
        // The row this token was read from: the handle decides over its scopes
        // at each exercise, never over a row that replaced it later.
        credentialScopes: entry.scopes ?? [],
      }));
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[/api/v1/delegate] Error:', err);
      res.status(500).json({ error: 'Delegation failed' });
    }
  });

  app.post('/api/v1/tofu/register', tofuRegisterRateLimiter, requireAgentAuth, async (req: Request, res: Response) => {
    try {
      const {
        public_key: publicKeyBase64,
        initial_scopes: initialScopes,
        metadata,
      } = req.body as {
        public_key?: string;
        initial_scopes?: string[];
        metadata?: Record<string, unknown>;
      };

      if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
        res.status(400).json({ error: 'public_key is required' });
        return;
      }

      const publicKey = decodeWebBotAuthPublicKey(publicKeyBase64);
      if (!publicKey) {
        res.status(400).json({ error: 'public_key must be a base64-encoded 32-byte Ed25519 public key' });
        return;
      }

      const registered = await tofu.registerAgent({
        publicKey,
        initialScopes: normalizeRequestedScopes(initialScopes) ?? [],
        metadata: metadata ?? {},
      });
      const identity = await tofu.getAgent(registered.fingerprint);

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: toTofuPrincipalId(registered.agentId), fingerprint: registered.fingerprint },
        action: 'create',
        resource: { type: 'agent', id: registered.agentId },
        outcome: 'success',
        scopesGranted: identity?.initialScopes ?? [],
        correlationId: crypto.randomUUID(),
        metadata: {
          identitySource: 'web-bot-auth',
          webBotAuthKeyId: identity?.keyId ?? registered.fingerprint,
          signatureAgent: getSignatureAgentUrl(),
        },
      });

      res.status(201).json({
        agent_id: registered.agentId,
        fingerprint: registered.fingerprint,
        key_id: identity?.keyId ?? registered.fingerprint,
        signature_agent: getSignatureAgentUrl(),
        status: identity?.status ?? 'unclaimed',
        initial_scopes: identity?.initialScopes ?? [],
      });
    } catch (err) {
      console.error('[/api/v1/tofu/register] Error:', err);
      res.status(500).json({ error: 'TOFU registration failed' });
    }
  });

  app.get('/api/v1/web-bot-auth/keys', tokenRateLimiter, requireAgentAuth, verifyWebBotAuth, async (_req: Request, res: Response) => {
    try {
      const agents = await tofu.listAgents();
      res.json({
        keys: agents.map((agent) => mapAgentToWebBotAuthKey(agent)),
      });
    } catch (err) {
      console.error('[/api/v1/web-bot-auth/keys] Error:', err);
      res.status(500).json({ error: 'Failed to list Web Bot Auth keys' });
    }
  });

  app.post('/api/v1/web-bot-auth/keys', tokenRateLimiter, requireAgentAuth, async (req: Request, res: Response) => {
    try {
      const {
        public_key: publicKeyBase64,
        initial_scopes: initialScopes,
        metadata,
      } = req.body as {
        public_key?: string;
        initial_scopes?: string[];
        metadata?: Record<string, unknown>;
      };

      if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
        res.status(400).json({ error: 'public_key is required' });
        return;
      }

      const publicKey = decodeWebBotAuthPublicKey(publicKeyBase64);
      if (!publicKey) {
        res.status(400).json({ error: 'public_key must be a base64-encoded 32-byte Ed25519 public key' });
        return;
      }

      const registered = await tofu.registerAgent({
        publicKey,
        initialScopes: normalizeRequestedScopes(initialScopes) ?? [],
        metadata: metadata ?? {},
      });
      const identity = (await tofu.listAgents()).find((agent) => agent.agentId === registered.agentId);
      if (!identity) {
        res.status(500).json({ error: 'Registered key not found after insert' });
        return;
      }

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: toTofuPrincipalId(registered.agentId), fingerprint: registered.fingerprint },
        action: 'create',
        resource: { type: 'agent', id: registered.agentId },
        outcome: 'success',
        scopesGranted: identity.initialScopes,
        correlationId: crypto.randomUUID(),
        metadata: {
          identitySource: 'web-bot-auth',
          webBotAuthKeyId: identity.keyId,
          signatureAgent: getSignatureAgentUrl(),
        },
      });

      res.status(201).json(mapAgentToWebBotAuthKey(identity));
    } catch (err) {
      console.error('[/api/v1/web-bot-auth/keys] Error:', err);
      res.status(500).json({ error: 'Failed to create Web Bot Auth key' });
    }
  });

  app.post('/api/v1/web-bot-auth/keys/:agentId/rotate', tokenRateLimiter, requireAgentAuth, requireVerifiedIdentityRegardlessOfMode, async (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      if (typeof agentId !== 'string') {
        res.status(400).json({ error: 'agentId must be a string' });
        return;
      }
      const {
        public_key: publicKeyBase64,
        grace_period_hours: gracePeriodHours,
      } = req.body as {
        public_key?: string;
        grace_period_hours?: number;
      };

      if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
        res.status(400).json({ error: 'public_key is required' });
        return;
      }

      const existing = (await tofu.listAgents()).find((agent) => agent.agentId === agentId);
      if (!existing) {
        res.status(404).json({ error: 'Web Bot Auth key not found' });
        return;
      }

      const ownership = assertOwnsAgentId(req, agentId, 'tofu');
      if (!ownership.ok) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: {
            type: 'agent',
            id: verifiedPrincipalId(req) ?? (req as any).webBotAuthIdentity?.agentId ?? 'unverified',
            fingerprint: (req as any).webBotAuthIdentity?.fingerprint,
          },
          action: 'deny',
          resource: { type: 'agent', id: agentId },
          outcome: 'denied',
          errorMessage: ownership.error,
          correlationId: crypto.randomUUID(),
        });
        res.status(ownership.status).json({ error: ownership.error });
        return;
      }

      let publicKey: Uint8Array;
      try {
        publicKey = new Uint8Array(Buffer.from(publicKeyBase64, 'base64'));
      } catch {
        res.status(400).json({ error: 'public_key must be base64-encoded' });
        return;
      }

      const rotation = await tofu.rotateKey({
        fingerprint: existing.fingerprint,
        newPublicKey: publicKey,
        gracePeriodHours: typeof gracePeriodHours === 'number' ? gracePeriodHours : undefined,
      });

      const updated = (await tofu.listAgents()).find((agent) => agent.agentId === agentId);
      if (!updated) {
        res.status(500).json({ error: 'Rotated key not found after update' });
        return;
      }

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: toTofuPrincipalId(updated.agentId), fingerprint: updated.fingerprint },
        action: 'rotate',
        resource: { type: 'agent', id: updated.agentId },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
        metadata: {
          identitySource: 'web-bot-auth',
          webBotAuthKeyId: updated.keyId,
          previousFingerprint: rotation.previousFingerprint,
          signatureAgent: getSignatureAgentUrl(),
          graceExpiresAt: rotation.graceExpiresAt.toISOString(),
        },
      });

      res.json({
        ...mapAgentToWebBotAuthKey(updated),
        previous_fingerprint: rotation.previousFingerprint,
        grace_expires_at: rotation.graceExpiresAt.toISOString(),
      });
    } catch (err) {
      console.error('[/api/v1/web-bot-auth/keys/:agentId/rotate] Error:', err);
      res.status(500).json({ error: 'Failed to rotate Web Bot Auth key' });
    }
  });

  app.post('/api/v1/agents/:agentId/revoke-all', revokeRateLimiter, requireAgentAuth, requireVerifiedIdentityRegardlessOfMode, async (req: Request, res: Response) => {
    try {
      const agentIdParam = req.params.agentId;
      if (typeof agentIdParam !== 'string') {
        res.status(400).json({ error: 'agentId must be a string' });
        return;
      }
      const agentId = agentIdParam;
      const agent = await vault.getAgent(agentId);
      if (!agent) {
        res.status(404).json({ error: 'Agent not found' });
        return;
      }

      const ownership = assertOwnsAgentId(req, agentId, 'vault', agent);
      if (!ownership.ok) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: {
            type: 'agent',
            id: verifiedPrincipalId(req) ?? (req as any).webBotAuthIdentity?.agentId ?? 'unverified',
            fingerprint: (req as any).webBotAuthIdentity?.fingerprint,
          },
          action: 'deny',
          resource: { type: 'agent', id: agentId },
          outcome: 'denied',
          errorMessage: ownership.error,
          correlationId: crypto.randomUUID(),
        });
        res.status(ownership.status).json({ error: ownership.error });
        return;
      }

      const started = performance.now();
      const correlationId = crypto.randomUUID();
      const actor: AuditActor = { type: 'agent', id: agent.id, fingerprint: agent.fingerprint };
      const cascade = await applyRevocation(await vault.revokeAgentCascade(agentId, { hold: { cause: `agent:${agent.id}` } }), started, {
        actor,
        correlationId,
        cause: `agent:${agent.id}`,
      });

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor,
        action: 'revoke',
        resource: { type: 'agent', id: agent.id },
        outcome: 'success',
        correlationId,
        metadata: {
          agentDid: agent.did,
          revokedCount: cascade.count,
          elapsedMs: cascade.elapsedMs,
        },
      });

      res.status(204).send();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('not supported')) {
        res.status(501).json({ error: 'Agent storage not supported by this vault backend' });
        return;
      }
      console.error('[/api/v1/agents/:agentId/revoke-all] Error:', err);
      res.status(500).json({ error: 'Failed to revoke agent' });
    }
  });

  /**
   * Shared by `GET /api/v1/audit` and `GET /api/v1/audit/stream` — decides
   * whether an audit event is visible to a caller scoped to `userId`
   * (optionally further narrowed by `service`). Agent-identity events
   * (register/rotate/revoke) carry no `userId` in their resource id, so —
   * matching the pre-existing behavior of `GET /api/v1/audit` — they are
   * only visible to the `default` logical user and never alongside a
   * `service` filter.
   */
  function isAuditEventVisibleToCaller(event: AuditEvent, userId: string, service: string | undefined): boolean {
    if (event.resource.type === 'agent') {
      return userId === 'default' && !service;
    }
    // The user id may itself hold a slash, so only the first one separates.
    const separator = event.resource.id.indexOf('/');
    const eventService = event.resource.id.slice(0, separator);
    if (separator === -1 || event.resource.id.slice(separator + 1) !== userId) return false;
    if (service && eventService !== service) return false;
    return true;
  }

  /** Shapes a raw `AuditEvent` into the response entry used by both audit routes above. */
  /**
   * The `metadata` sub-object is identical across every audit-entry mapper
   * in this file (the agent-facing GET /api/v1/audit route, the admin GET
   * /admin/audit route, and auditEventToEntry's two branches below) — factored
   * out once so a future field addition doesn't need to be applied in 3+ places.
   */
  function buildAuditEntryMetadata(event: AuditEvent) {
    const stored = event.metadata ?? {};
    const isWebBotAuth = WEB_BOT_AUTH_SIGNS.some((key) => stored[key] !== undefined);
    const signed = isWebBotAuth ? Object.fromEntries(Object.entries(stored).filter(([key]) => WEB_BOT_AUTH_FIELDS.includes(key))) : {};
    const details = Object.fromEntries(Object.entries(stored).filter(([key]) => !(key in signed)));
    return {
      outcome: event.outcome,
      scopesRequested: event.scopesRequested,
      scopesGranted: event.scopesGranted,
      correlationId: event.correlationId,
      errorMessage: event.errorMessage,
      ...(Object.keys(details).length > 0 ? { details } : {}),
      // Deprecated, kept for 2.x readers: 2.0.0 filed every stored field here, signed
      // or not, so it still holds them all. Read an event's own fields from `details`;
      // a Web Bot Auth signature was checked only when `webBotAuthKeyId` is present.
      ...(event.metadata ? { webBotAuth: stored } : {}),
    };
  }

  /**
   * Who an entry names, for a caller holding only the agent token. A failed proof
   * came from someone who could not prove the key, so naming the agent would tell
   * them who a token they do not hold is bound to. /admin/audit shows it.
   */
  function auditEntryActor(event: AuditEvent): AuditActor {
    return event.errorMessage === 'invalid_dpop_proof' ? { type: event.actor.type, id: 'unverified' } : event.actor;
  }

  /** Shapes a raw `AuditEvent` into the response entry used by both audit routes above. */
  function auditEventToEntry(event: AuditEvent, userId: string) {
    if (event.resource.type === 'agent') {
      return {
        id: event.id,
        action: event.action,
        service: 'agent',
        userId,
        actor: auditEntryActor(event),
        timestamp: event.timestamp.toISOString(),
        metadata: buildAuditEntryMetadata(event),
      };
    }
    const separator = event.resource.id.indexOf('/');
    const eventService = separator === -1 ? event.resource.id : event.resource.id.slice(0, separator);
    const eventUserId = separator === -1 ? undefined : event.resource.id.slice(separator + 1);
    return {
      id: event.id,
      action: event.action,
      service: eventService ?? '',
      userId: eventUserId ?? 'default',
      actor: auditEntryActor(event),
      timestamp: event.timestamp.toISOString(),
      metadata: buildAuditEntryMetadata(event),
    };
  }

  /**
   * GET /api/v1/audit — query audit events when the vault backend supports audit.
   *
   * Requires Bearer auth. Events are filtered by logical `user_id` and optional
   * service when the backend supports audit queries.
   *
   * Accepts an optional `since` query parameter — an ISO-8601 timestamp cursor.
   * When provided, only events with a timestamp strictly after `since` are
   * returned (in place of the default "most recent `limit` events" behavior),
   * letting a poller re-fetch just the events it hasn't seen instead of
   * re-fetching and diffing the last N rows. Omitting `since` preserves
   * today's behavior exactly.
   */
  app.get('/api/v1/audit', auditRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const userId = requestUserId(req, res, { agent: true });
      if (userId === null) return;
      const service = typeof req.query.service === 'string' ? req.query.service : undefined;
      const limitRaw = typeof req.query.limit === 'string' ? req.query.limit : undefined;
      const limit = limitRaw ? Number.parseInt(limitRaw, 10) : 50;

      if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
        res.status(400).json({ error: 'Invalid limit: must be between 1 and 200' });
        return;
      }

      const sinceRaw = typeof req.query.since === 'string' ? req.query.since : undefined;
      let since: Date | undefined;
      if (sinceRaw) {
        const parsedSince = new Date(sinceRaw);
        if (Number.isNaN(parsedSince.getTime())) {
          res.status(400).json({ error: 'Invalid since: must be an ISO-8601 timestamp' });
          return;
        }
        since = parsedSince;
      }

      let events;
      try {
        events = vault.queryAuditEvents({ limit, ...(since ? { since } : {}) });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('not supported')) {
          res.status(501).json({ error: 'Audit query not supported by this vault backend' });
          return;
        }
        throw err;
      }

      const entries = events
        .filter((event) => isAuditEventVisibleToCaller(event, userId, service))
        .map((event) => auditEventToEntry(event, userId));

      res.json({ entries });
    } catch (err) {
      console.error('[/api/v1/audit] Error:', err);
      res.status(500).json({ error: 'Failed to fetch audit log' });
    }
  });

  /**
   * GET /api/v1/audit/stream — Server-Sent Events stream of the connecting
   * caller's own `revoke`-action audit events, delivered as they happen.
   *
   * Deliberately minimal, per docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md
   * (U9): scoped to `revoke` only — delegate/use/subdelegate events are not
   * streamed by this route, and this is not a general pub/sub mechanism.
   *
   * Auth is the same header-based Bearer `requireAgentAuth`/`verifyWebBotAuth`
   * used by `GET /api/v1/audit`, established once at connection time. This is
   * not designed for browser `EventSource` clients (which cannot set an
   * `Authorization` header) — a token-in-query-string workaround for browser
   * compatibility is explicitly out of scope.
   *
   * No event-emitter/pub-sub hook exists anywhere in this codebase to attach
   * to, so this is implemented as a short internal poll against
   * `vault.queryAuditEvents` (every 1.5s) rather than a push from the audit
   * write path — intentionally simple, not a production-grade event bus.
   * Visibility uses the exact same `isAuditEventVisibleToCaller` scoping as
   * `GET /api/v1/audit`, so a connecting caller only ever sees revoke events
   * visible to its own logical `userId` (see that function's docs above).
   *
   * Operational note: SSE is new long-lived-connection surface for this
   * codebase. Any reverse proxy fronting this service — not just the
   * documented Caddy setup in packages/server/README.md — needs verified
   * idle/read timeouts (and disabled response buffering) for this connection
   * to survive; see the plan's System-Wide Impact section.
   *
   * Rate limiting: `auditRateLimiter` gates new *connection attempts* (a
   * per-IP window, same as `GET /api/v1/audit`) rather than capping
   * concurrent open streams — express-rate-limit counts at request start,
   * so it does nothing once a stream is already open. A connection-count
   * limit would be the more precise protection for a long-lived route, but
   * is deliberately left out of this minimal unit; the connect-rate limit
   * plus required auth is the accepted protection level for now.
   */
  app.get('/api/v1/audit/stream', auditRateLimiter, requireAgentAuth, verifyWebBotAuth, (req: Request, res: Response) => {
    const userId = requestUserId(req, res, { agent: true });
    if (userId === null) return;

    // Fail fast with the same 501 GET /api/v1/audit would give, rather than
    // opening a stream that can never emit anything.
    try {
      vault.queryAuditEvents({ limit: 1 });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('not supported')) {
        res.status(501).json({ error: 'Audit query not supported by this vault backend' });
        return;
      }
      console.error('[/api/v1/audit/stream] Error:', err);
      res.status(500).json({ error: 'Failed to open audit stream' });
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.flushHeaders();

    // Cursor starts just before connection time (1ms back) — this stream
    // delivers revocations going forward, not a historical backlog (use
    // GET /api/v1/audit for that). The 1ms backdate matters because the
    // query below is a strict `timestamp > since` (see audit.ts) and Date
    // has only millisecond resolution: without it, a revoke whose audit
    // write lands in the same millisecond as this connection would never
    // satisfy the comparison and would be silently dropped for the life of
    // the stream, not just delayed.
    let cursor = new Date(Date.now() - 1);

    const poll = () => {
      let events: AuditEvent[];
      try {
        events = vault.queryAuditEvents({ action: 'revoke', since: cursor });
      } catch {
        // Backend became unavailable mid-stream — skip this tick rather
        // than crashing the poll loop; the client can reconnect.
        return;
      }
      if (events.length === 0) return;

      // queryAuditEvents orders newest-first; replay oldest-first so the
      // cursor advances monotonically and events arrive in chronological order.
      const chronological = [...events].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
      for (const event of chronological) {
        if (!isAuditEventVisibleToCaller(event, userId, undefined)) continue;
        const entry = auditEventToEntry(event, userId);
        res.write(`data: ${JSON.stringify(entry)}\n\n`);
      }
      cursor = chronological[chronological.length - 1]!.timestamp;
    };

    const interval = setInterval(poll, 1500);

    req.on('close', () => {
      clearInterval(interval);
    });
  });

  /**
   * POST /api/v1/subdelegate — Sub-delegate from a verified parent receipt
   *
   * Verifies the parent receipt signature, validates delegation chain constraints
   * (scope attenuation, depth limits, service/user/app matching), retrieves a
   * fresh token from the vault, and issues a signed child receipt.
   *
   * Responses are always returned as brokered handles (never a raw provider
   * access token), regardless of the requested `token_format` — scope
   * attenuation on a raw provider token can't be enforced once it has left
   * the server, so every hop past the root delegation is broker-only. If the
   * caller asked for `token_format: 'raw'`, the response is still brokered
   * and carries `token_format_enforced: 'brokered'` to flag the downgrade.
   * If the service has no brokered-use path at all, the request is rejected
   * with 400 rather than minting an unusable handle.
   *
   * Ancestor revocation: every receipt carries a signed `lineage` of its
   * ancestors' DIDs (root first), extended at each hop. Before minting a
   * child receipt, every DID in `[...parent.lineage, parent.sub]` is
   * checked against the vault's agent records — a revoked or suspended
   * agent anywhere in the chain (not just the immediate parent) blocks the
   * sub-delegation. Receipts minted before this claim existed carry no
   * lineage and degrade to a parent-only check until they age out under the
   * receipt TTL.
   *
   * Request body:
   *   parent_receipt  — signed parent delegation receipt (JWS)
   *   agent_did       — DID of the child agent
   *   service         — provider slug (must match parent)
   *   user_id         — logical user (must match parent)
   *   appClientId     — app context (must match parent)
   *   scopes          — optional subset of parent scopes
   *
   * Auth: Bearer cred_at_<token>
   */
  app.post('/api/v1/subdelegate', ...subdelegateRouteHandlers, async (req: Request, res: Response) => {
    const correlationId = crypto.randomUUID();
    try {
      const webBotAuthIdentity = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;
      const {
        parent_receipt: parentReceipt,
        agent_did: agentDid,
        service,
        appClientId = 'local',
        scopes: requestedScopes,
        constraints: requestedConstraintsRaw,
        authorization_details: requestedCapabilities,
        ancestor_receipts: ancestorReceipts,
        exchange,
        agent_delegation_chain: parentAgentDelegationChain,
      } = req.body as {
        /**
         * "grant": run the Sub-Delegation Exchange instead of issuing the
         * child here. The response carries a single-use delegation grant
         * the receiving agent redeems at POST /api/v1/token.
         */
        exchange?: string;
        authorization_details?: unknown;
        /**
         * With token_profile "agent_delegation": the parent's
         * agent_delegation token chain, root first, so the child token can
         * commit to its parent.
         */
        agent_delegation_chain?: unknown;
        parent_receipt?: string;
        agent_did?: string;
        service?: string;
        user_id?: string;
        appClientId?: string;
        scopes?: string[];
        /**
         * Optional ceilings for the child receipt (asor-01 section 4.2
         * shape). Absent inherits the parent's ceilings unchanged; present
         * must restate every parent ceiling at least as tight, and may add
         * new ones. Loosening is 'constraint_escalation_denied'.
         */
        constraints?: unknown;
        /**
         * Optional. Every receipt above parent_receipt, root first. When
         * present the whole chain is verified offline (signatures, linkage
         * through parentReceiptHash, depth, scope subsumption, expiry
         * ordering) before the parent is used. Absent means the existing
         * parent-only behavior.
         */
        ancestor_receipts?: string[];
      };
      // Sub-delegation of a Cred Link connection is refused in Phase 1, and
      // no caller-supplied user id may reach the reserved Link vault rows.
      if (req.body?.connection_id !== undefined) {
        res.status(400).json({ error: 'invalid_request', message: 'Sub-delegation of a Link connection is not supported' });
        return;
      }
      const userId = requestUserId(req, res, { agent: true, source: 'body' });
      if (userId === null) return;
      // Sub-delegation always returns a brokered handle — see route doc
      // comment above. `requestedTokenFormat` is only used to detect (and
      // flag) a caller asking for the raw provider token.
      const requestedTokenFormat = tokenFormatFromBody(req);

      // ── Input validation ──────────────────────────────────────────────────

      if (!parentReceipt || typeof parentReceipt !== 'string') {
        res.status(400).json({ error: 'parent_receipt is required' });
        return;
      }
      if (!agentDid || typeof agentDid !== 'string') {
        res.status(400).json({ error: 'agent_did is required' });
        return;
      }
      // The child handle is bound to the receiving agent's key, which only a
      // did:key carries. That agent proves the key each time it uses the handle.
      if (!dpopBindingFor(agentDid)) {
        refuseDpop(res, 400, 'agent_key_required', 'A child Delegation Token is issued only to a did:key agent; its key binds the token');
        return;
      }
      if (!service || typeof service !== 'string') {
        res.status(400).json({ error: 'service is required' });
        return;
      }
      if (!isBrokerableService(service)) {
        res.status(400).json({
          error: 'brokered_format_unsupported',
          message: `Sub-delegation requires a brokered handle for '${service}', which has no brokered-use path.`,
        });
        return;
      }
      if (exchange !== undefined && exchange !== 'grant') {
        res.status(400).json({ error: 'invalid_request', message: "exchange must be 'grant'" });
        return;
      }
      const chainProfile = chainProfileRequest(req.body, agentDid);
      if (!chainProfile.ok) {
        res.status(400).json(chainProfile.body);
        return;
      }

      if (invalidConstraintJson.has(req)) {
        res.status(400).json({ error: 'invalid_constraints', message: 'Constraint-bearing requests must use strict JSON' });
        return;
      }
      const childConstraints = parseConstraints(requestedConstraintsRaw);
      if (!childConstraints.ok) {
        res.status(400).json({ error: 'invalid_constraints', message: childConstraints.message });
        return;
      }
      const unresolvableChild = unresolvableRankLabels(childConstraints.constraints);
      if (unresolvableChild.length > 0) {
        res.status(400).json({ error: 'invalid_constraints', message: `No rank ordering is registered for: ${unresolvableChild.join(', ')}` });
        return;
      }

      // ── Verify parent receipt ─────────────────────────────────────────────

      let parent = (req as any).verifiedParentReceipt as ReturnType<typeof parseAndVerifyReceipt> | undefined;
      try {
        parent = parent ?? parseAndVerifyReceipt(parentReceipt);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Invalid receipt';
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: message,
          correlationId,
        });
        res.status(403).json({ error: message });
        return;
      }

      // ── Caller is the delegating agent ───────────────────────────────────
      // A valid receipt is not authority by itself: the caller must prove it
      // is the agent the receipt names (act.sub / client_id) by signing an
      // RFC 7523 actor_token with that agent's did:key, the key the
      // receipt's cnf binds. CRED_REQUIRE_AGENT_IDENTITY=false keeps the
      // legacy behaviour (any Bearer caller holding the receipt) and logs a
      // deprecation warning at startup. Under DPoP-bound handles the check
      // always runs: without it, a leaked receipt plus the Bearer credential
      // could mint a child handle bound to a key the caller chose.
      // Always: every child is a Delegation Token bound to the receiving
      // agent's key, so a leaked receipt alone must never mint one.
      {
        const actorToken = (req.body as { actor_token?: unknown }).actor_token;
        const denyIdentity = (status: number, error: string, message: string) => {
          writeAuditEventIfSupported({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: agentDid },
            action: 'deny',
            resource: { type: 'token', id: `${service}/${userId}` },
            outcome: 'denied',
            errorMessage: error,
            correlationId,
          });
          res.status(status).json({ error, message });
        };
        if (actorToken === undefined) {
          denyIdentity(401, 'agent_identity_required', 'Sub-delegation needs an actor_token signed by the agent the parent receipt names');
          return;
        }
        if (!publicKeyFromDidKey(parent.sub)) {
          denyIdentity(403, 'agent_identity_unverifiable', 'The parent receipt names an agent that is not a did:key, so the caller cannot prove it is that agent');
          return;
        }
        const proof = verifyActorToken(actorToken, parent.sub, `${publicBaseUri()}/api/v1/subdelegate`, actorTokenJtiSeen);
        if (!proof.ok) {
          denyIdentity(403, 'agent_identity_mismatch', proof.message);
          return;
        }
      }

      // ── Context matching (service, user, app) ────────────────────────────

      if (parent.service !== service) {
        res.status(403).json({ error: 'Service does not match parent receipt' });
        return;
      }
      if (parent.userId !== userId) {
        res.status(403).json({ error: 'User does not match parent receipt' });
        return;
      }
      if (rejectReservedUserId(res, parent.userId)) return;
      if (parent.appClientId !== appClientId) {
        res.status(403).json({ error: 'App does not match parent receipt' });
        return;
      }

      // ── Optional full-chain verification ─────────────────────────────────
      // If the caller presents the ancestors, the parent must be provably the
      // leaf of that chain: each receipt's parentReceiptHash has to equal the
      // hash of the receipt before it. This is the offline check that
      // parentReceiptHash exists for; it was written on every hop but never
      // read before this.

      if (ancestorReceipts !== undefined) {
        if (!Array.isArray(ancestorReceipts) || ancestorReceipts.some((r) => typeof r !== 'string' || r.trim() === '')) {
          res.status(400).json({ error: 'ancestor_receipts must be an array of receipt strings' });
          return;
        }
        if (ancestorReceipts.length > 0) {
          const chain = verifyReceiptChain([...ancestorReceipts, parentReceipt], getReceiptKeys(), {
            clockSkewSeconds: RECEIPT_CLOCK_SKEW_SECONDS,
          });
          if (!chain.ok) {
            writeAuditEventIfSupported({
              id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
              timestamp: new Date(),
              actor: { type: 'agent', id: agentDid },
              action: 'deny',
              resource: { type: 'token', id: `${service}/${userId}` },
              outcome: 'denied',
              errorMessage: `chain_invalid:${chain.reason}`,
              correlationId,
            });
            res.status(403).json({
              error: 'chain_invalid',
              reason: chain.reason,
              hop: chain.hop,
              message: chain.message,
            });
            return;
          }
        }
      }

      // ── Parent delegation status ─────────────────────────────────────────
      // A revoked parent (revoked directly, or reached by a cascade from any
      // of its ancestors) can anchor no new child. Recording the child below
      // re-checks this atomically with the insert.

      const parentRecord = await vault.getDelegation(parent.delegationId);
      if (parentRecord?.status === 'revoked') {
        const revokedAncestorId = parentRecord.revokedAncestorId ?? parentRecord.id;
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: 'delegation_revoked',
          correlationId,
          metadata: { parentDelegationId: parent.delegationId, revokedAncestorId },
        });
        res.status(401).json({
          error: 'delegation_revoked',
          message: 'The parent delegation has been revoked',
          revoked_ancestor_id: revokedAncestorId,
        });
        return;
      }

      // ── Ancestor status check (if vault supports agents) ─────────────────
      // A revoked/suspended ancestor anywhere in the chain — not just the
      // immediate parent — must not be able to anchor a fresh sub-delegation
      // to a still-active descendant DID. Delegation records (checked above)
      // cover revoked delegations; a suspended agent revokes nothing, and a
      // receipt may predate the records, so this also walks the chain
      // embedded in the signed receipt itself: every receipt carries a
      // `lineage` of its ancestors' DIDs (oldest/root first), appended to
      // and re-signed at each hop by this same trusted issuer, so a
      // requesting agent cannot forge or truncate it. Checking
      // `[...parent.lineage, parent.sub]` therefore checks every ancestor
      // back to the root, not just the presenter.
      //
      // Legacy receipts minted before the `lineage` claim existed carry an
      // empty lineage, so this degrades to a parent-only check for those —
      // that gap self-heals as those receipts age out under the receipt TTL
      // (see parseAndVerifyReceipt).
      //
      // If the vault has no agent record for a given ancestor DID, that
      // ancestor is treated as allowed (matches the existing unknown-agent
      // behavior for the child check below).

      const ancestorDids = Array.from(new Set([...parent.lineage, parent.sub]));
      for (const ancestorDid of ancestorDids) {
        let ancestorAgentRecord: AgentRecord | null = null;
        if (vault.getAgentByDid) {
          ancestorAgentRecord = await vault.getAgentByDid(ancestorDid);
        }
        if (ancestorAgentRecord?.status === 'revoked' || ancestorAgentRecord?.status === 'suspended') {
          const errorCode = ancestorAgentRecord.status === 'revoked' ? 'ancestor_agent_revoked' : 'ancestor_agent_suspended';
          writeAuditEventIfSupported({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: agentDid },
            action: 'deny',
            resource: { type: 'token', id: `${service}/${userId}` },
            outcome: 'denied',
            errorMessage: errorCode,
            correlationId,
          });
          res.status(403).json({
            error: errorCode,
            message: `Ancestor agent ${ancestorDid} has been ${ancestorAgentRecord.status}`,
          });
          return;
        }
      }

      // ── Agent status check (if vault supports agents) ────────────────────

      let agentRecord: { id: string; status: string; scopeCeiling: string[] } | null = null;
      if (vault.getAgentByDid) {
        agentRecord = await vault.getAgentByDid(agentDid);
      }
      if (agentRecord?.status === 'revoked') {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: 'Agent is revoked',
          correlationId,
        });
        res.status(403).json({ error: 'Agent has been revoked' });
        return;
      }
      if (agentRecord?.status === 'suspended') {
        res.status(403).json({ error: 'Agent is suspended' });
        return;
      }

      // ── Permission lookup ────────────────────────────────────────────────

      // A revocation holds the agent out however it asks, and an ancestor
      // cut off the same way cannot hand its access on either.
      const subdelegationOptOuts: string[] = [];
      for (const did of [...ancestorDids, agentDid]) {
        const standing = await agentRevocationStatus(did, service, userId);
        if (standing.refused) {
          denyAgentStanding(agentDid, service, userId, 'agent_access_revoked', correlationId, { cause: standing.cause, revokedAgent: did });
          res.status(403).json({ error: 'agent_access_revoked', message: AGENT_ACCESS_REVOKED_MESSAGE });
          return;
        }
        if (standing.bypassed && subdelegationOptOuts.length === 0) subdelegationOptOuts.push('redelegation_after_revocation');
      }

      const permission = await permissionForDidAgent(agentDid, agentRecord as AgentRecord | null, service);
      // The agent handing off needs leave to hand off, as well as the agent receiving.
      const parentPermission = parent.sub.startsWith('did:')
        ? await permissionForDidAgent(parent.sub, await vault.getAgentByDid?.(parent.sub) ?? null, service)
        : null;
      if (parentPermission && !parentPermission.delegatable) {
        res.status(403).json({ error: 'Permission is not delegatable', code: 'delegation_not_allowed' });
        return;
      }
      // The grantor's own row also caps how deep it may pass access on: what a
      // Permission holder may hand off depends on the depth it already sits at,
      // not only on the receiving agent's row. A grantor with no row keeps the
      // pre-existing recipient-only behaviour.
      if (parentPermission && (parent.chainDepth ?? 0) + 1 > parentPermission.maxDelegationDepth) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'permission', id: parentPermission.id },
          outcome: 'denied',
          errorMessage: 'grantor_depth_exceeded',
          correlationId,
        });
        res.status(403).json({
          error: "Sub-delegation exceeds the delegating agent's max delegation depth",
          code: 'depth_exceeded',
        });
        return;
      }
      // A Permission is a clock and a scope list, not only a boolean. A receipt
      // names what was granted when it was minted; what its holder may pass on
      // now is bounded by the row it holds now, exactly as /api/v1/use bounds
      // what the holder may reach now. A row that has expired hands nothing on,
      // and a row narrowed since issuance hands on only what it still covers:
      // the child gets the intersection, never a scope the grantor has lost.
      //
      // One metadata read of the stored row decides every stored-scope question
      // on this hop: what the grantor may still pass on, and what the receiving
      // Permission's derived read would reach. It is taken once, so a refusal
      // costs a single read and no two checks can see different rows — and the
      // entry that read returned is the credential this hop issues against
      // (hopCredential), so no later read exists to disagree with the decision.
      let hopSnapshot: Promise<ConnectionSnapshot> | undefined;
      const tokenScopesForHop = async (): Promise<string[]> => {
        if (!hasDerivedReadScope(service)) return [];
        hopSnapshot ??= connectionSnapshot(service, userId);
        return (await hopSnapshot).held;
      };
      if (parentPermission) {
        if (parentPermission.expiresAt && parentPermission.expiresAt.getTime() <= Date.now()) {
          writeAuditEventIfSupported({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: agentDid },
            action: 'deny',
            resource: { type: 'permission', id: parentPermission.id },
            outcome: 'denied',
            scopesRequested: requestedScopes,
            errorMessage: 'grantor_permission_expired',
            correlationId,
          });
          refusePermission(res, 'permission_expired');
          return;
        }
        const handoffScopes = Array.isArray(requestedScopes) && requestedScopes.length > 0 ? requestedScopes : parent.scopes;
        // Only scopes the receipt itself covers are the grantor's to lose: a
        // scope outside the receipt is the parent's business, and stays
        // 'scope_escalation_denied' below exactly as it was.
        const receiptScopes = withDerivedScopes(service, parent.scopes);
        // A derived read scope is Cred's name for access the raw token already
        // carries, so it means what the stored connection can reach, never what
        // the receipt happens to name. getStored is the narrowest accessor that
        // reports those scopes: it decrypts the row at rest, never refreshes it
        // and never calls the provider. Only the scope list is used, and it is
        // neither logged nor returned; the read leaves no other trace. An
        // existing Notion entry with no stored scopes covers the whole
        // connection, so a grantor narrowed to `read_content` cannot hand on
        // `notion.read` from a receipt minted while its row was wider.
        const tokenScopes = await tokenScopesForHop();
        const uncoveredScopes = [...new Set(handoffScopes.filter((scope) =>
          scopeCoveredBy(receiptScopes, scope)
          && !permissionCovers(service, parentPermission.allowedScopes, scope, tokenScopes),
        ))];
        if (uncoveredScopes.length > 0) {
          writeAuditEventIfSupported({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: agentDid },
            action: 'deny',
            resource: { type: 'permission', id: parentPermission.id },
            outcome: 'denied',
            scopesRequested: requestedScopes,
            errorMessage: 'grantor_scope_insufficient',
            correlationId,
          });
          res.status(403).json({
            error: 'scope_insufficient',
            code: 'scope_insufficient',
            message: "The delegating agent's Permission no longer covers every scope this handoff would grant. Ask for a new delegation.",
            scopes: uncoveredScopes,
          });
          return;
        }
      }
      if (!permission) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: `No permission for ${service}`,
          correlationId,
        });
        res.status(403).json({ error: `Agent has no permission for ${service}` });
        return;
      }
      const permissionDenied = await permissionRefusal(permission);
      if (permissionDenied) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'permission', id: permission.id },
          outcome: 'denied',
          correlationId,
          errorMessage: permissionDenied,
        });
        refusePermission(res, permissionDenied);
        return;
      }

      // ── Validate delegation chain ────────────────────────────────────────

      // The receiving Permission is read over what the stored connection
      // actually covers, not over the parent receipt's list. A derived read
      // means access the raw token carries, so a recipient row naming only the
      // narrower source of one — `public_repo` over a `repo` token, or
      // `read_content` over a Notion connection with no stored scopes — must not
      // be issued that read. The live use check already reads the stored row;
      // this is the issuance-time equivalent, so a receipt never names more than
      // the recipient's Permission states.
      const hopTokenScopes = await tokenScopesForHop();
      let validation;
      try {
        validation = validateSubDelegation({
          parent: {
            delegationId: parent.delegationId,
            agentDid: parent.sub,
            service: parent.service,
            userId: parent.userId,
            appClientId: parent.appClientId,
            // A parent's wider scope covers the read scope derived from it, and
            // never the other way round.
            scopesGranted: withDerivedScopes(parent.service, parent.scopes),
            chainDepth: parent.chainDepth,
            constraints: parent.constraints,
          },
          childAgentDid: agentDid,
          service,
          userId,
          appClientId,
          requestedScopes,
          // `constraints` absent from the request body means inherit the
          // parent's ceilings; an explicit list is checked for subsumption.
          ...(requestedConstraintsRaw !== undefined
            ? { requestedConstraints: childConstraints.constraints }
            : {}),
          permission: {
            allowedScopes: withDerivedScopesUnder(service, permission.allowedScopes, hopTokenScopes),
            delegatable: permission.delegatable,
            maxDelegationDepth: permission.maxDelegationDepth,
          },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Delegation chain validation failed';
        const code = err instanceof DelegationChainError ? err.code : 'validation_failed';
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${service}/${userId}` },
          outcome: 'denied',
          scopesRequested: requestedScopes,
          errorMessage: message,
          correlationId,
        });
        res.status(403).json({ error: message, code });
        return;
      }
      validation.grantedScopes = withoutRedundantDerivedScopes(service, validation.grantedScopes);

      // ── Enforce the child agent's scope ceiling ──────────────────────────
      // Mirror the direct-delegation path (a non-empty scopeCeiling is a hard
      // per-agent cap; empty means unbounded). Without this, sub-delegation
      // could grant an agent scopes above the ceiling that the same agent is
      // capped to on direct delegation. The ceiling is read over what the stored
      // connection covers for the same reason as the recipient Permission above:
      // a `public_repo` ceiling does not reach `github.read` over a `repo` token.
      if (agentRecord?.scopeCeiling.length) {
        const withinCeiling = validation.grantedScopes.filter((scope) =>
          ceilingCovers(service, agentRecord!.scopeCeiling, scope, hopTokenScopes),
        );
        if (withinCeiling.length === 0) {
          writeAuditEventIfSupported({
            id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
            timestamp: new Date(),
            actor: { type: 'agent', id: agentDid },
            action: 'deny',
            resource: { type: 'token', id: `${service}/${userId}` },
            outcome: 'denied',
            scopesRequested: requestedScopes,
            errorMessage: 'Requested scopes exceed agent scope ceiling',
            correlationId,
          });
          res.status(403).json({
            error: 'Requested scopes exceed agent scope ceiling',
            code: 'scope_ceiling_exceeded',
          });
          return;
        }
        validation.grantedScopes = withinCeiling;
      }

      // max is per action only (asor-02 section 4.2). Judge only what this
      // hop mints: a ceiling carried unchanged from the parent is inherited,
      // so chains under receipts minted before this rule keep working. Checked before the vault read, which can refresh a
      // stored credential.
      const childProducerViolations = producerConstraintViolations(validation.grantedConstraints, { inherited: parent.constraints });
      if (childProducerViolations.length > 0) {
        res.status(400).json({ error: 'invalid_constraints', message: childProducerViolations.join('; ') });
        return;
      }

      // ── Retrieve token from vault ────────────────────────────────────────

      const providerConfig = getProviderConfig(service);
      const getOpts: Parameters<typeof vault.get>[0] = {
        provider: service,
        userId,
      };
      if (providerConfig) {
        const adapter = createAdapter(providerConfig.slug as BuiltinAdapterSlug);
        getOpts.adapter = toVaultRefreshAdapter(adapter);
        getOpts.clientId = providerConfig.clientId;
        getOpts.clientSecret = providerConfig.clientSecret;
      }

      // The decision's own entry, not a second read of the same connection: see
      // hopCredential(). A hop that re-read here could authorize against one row
      // and issue against another replaced in between.
      const selected = await hopCredential(service, hopSnapshot ? await hopSnapshot : undefined, getOpts);
      if ('unreviewed' in selected) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${service}/${userId}` },
          outcome: 'denied',
          scopesRequested: requestedScopes,
          errorMessage: 'connection_changed_during_hop',
          correlationId,
        });
        res.status(403).json({
          error: 'scope_insufficient',
          code: 'scope_insufficient',
          message: 'The stored connection changed while this hop was being decided and now covers scopes this hop was not authorized over. Ask for a new delegation.',
          scopes: selected.unreviewed,
        });
        return;
      }
      const { entry } = selected;
      if (!entry) {
        res.status(404).json({
          error: `No credentials stored for '${service}/${userId}'. Connect it first: an operator opens /connect?user_id=${encodeURIComponent(userId)} and clicks Connect for ${service}.`,
        });
        return;
      }

      // ── Monotonic expiry ─────────────────────────────────────────────────
      // A child receipt must not outlive its parent. parseAndVerifyReceipt()
      // tolerates a small clock skew past `exp`, so a parent can verify while
      // having nothing left to hand down; that case is rejected here rather
      // than minting a receipt that is already expired.

      const parentExpiryBound = receiptExpiryBound(parent);
      const nowSecondsForChild = Math.floor(Date.now() / 1000);
      if (parentExpiryBound !== undefined && parentExpiryBound <= nowSecondsForChild) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${service}/${userId}` },
          outcome: 'denied',
          errorMessage: 'parent_expiring',
          correlationId,
        });
        res.status(403).json({
          error: 'parent_expiring',
          message: 'Parent receipt expires before a child receipt could be issued',
        });
        return;
      }

      let parentChainToken: string | undefined;
      let parentChainDepthBound: number | undefined;
      if (chainProfile.wanted) {
        const parentChain = verifyParentChainProfile(parentAgentDelegationChain, parent);
        if (!parentChain.ok) {
          res.status(400).json(parentChain.body);
          return;
        }
        parentChainToken = parentChain.parentToken;
        parentChainDepthBound = parentChain.depthBound;
      }

      // ── Issue child receipt ──────────────────────────────────────────────

      // The child's handle, like its receipt, ends no later than the parent.
      const entryExpiresIn = handleLifetimeSeconds(entry.expiresAt);
      const expiresIn = parentExpiryBound !== undefined
        ? Math.max(1, Math.min(entryExpiresIn, parentExpiryBound - nowSecondsForChild))
        : entryExpiresIn;

      const delegationId = `del_${crypto.randomUUID().replace(/-/g, '')}`;
      const parentReceiptHash = crypto.createHash('sha256').update(parentReceipt).digest('hex');

      // The receipt comes first: the child's Delegation Token names it in
      // prf. It is released only once the delegation is recorded below.
      const receipt = createReceipt({
        expiresAtSecondsCeiling: parentExpiryBound,
        agentDid,
        service,
        userId,
        appClientId,
        scopes: validation.grantedScopes,
        delegationId,
        chainDepth: validation.chainDepth,
        parentDelegationId: validation.parentDelegationId,
        parentReceiptHash,
        receiptClaims: parent.receiptClaims,
        lineage: ancestorDids,
        constraints: validation.grantedConstraints,
        ...(chainProfile.wanted ? { chainProfile: { format: 'agent_delegation' as const, jti: delegationId, scopeMapping: 'identity' as const } } : {}),
      });
      let agentDelegationToken: string | undefined;
      if (chainProfile.wanted) {
        const minted = mintChainProfileToken({
          receipt,
          agentDid,
          userId,
          scopes: validation.grantedScopes,
          constraints: validation.grantedConstraints,
          delegationId,
          audience: chainProfile.audience,
          delMaxDepth: chainProfile.delMaxDepth,
          parentToken: parentChainToken,
          chainDepthBound: parentChainDepthBound,
        });
        if (!minted.ok) {
          res.status(400).json(minted.body);
          return;
        }
        agentDelegationToken = minted.token;
      }

      // The child's token keeps the consent its chain traces to and extends
      // the parent's prf with the new receipt. A parent issued without a
      // token (a receipt-only root) starts the list at its own receipt.
      const parentGrant = (await vault.getDelegation(parent.delegationId))?.grant;
      // This server holds a destination prefix to a URL boundary at exercise,
      // so a child's must sit at such a boundary under its parent's too: a
      // parent's `files/a` never grants `files/abc`.
      const destinationPrefix = (list: readonly DelegationConstraint[]) => list
        .filter((c) => c.key === 'destination' && typeof (c as { prefix?: unknown }).prefix === 'string')
        .map((c) => (c as { prefix: string }).prefix);
      const parentDestinations = destinationPrefix(parent.constraints ?? []);
      const childDestinations = destinationPrefix(validation.grantedConstraints ?? []);
      if (parentDestinations.some((p) => childDestinations.some((c) => !destinationWithinPrefix(c, p)))) {
        res.status(403).json({ error: 'constraint_escalation_denied', message: 'A destination prefix must narrow its parent\'s at a URL boundary' });
        return;
      }
      // The child's capabilities must be within the parent's (Section 5.2):
      // what it asks for, or by default its granted scopes as operations.
      const parentCapabilities = (parentGrant?.authorizationDetails as CredDelegationDetail[] | undefined)
        ?? capabilitiesFor(service, parent.scopes);
      let childCapabilities = capabilitiesFor(service, validation.grantedScopes);
      if (requestedCapabilities !== undefined) {
        const checked = validateCapabilities(requestedCapabilities, service, validation.grantedScopes);
        if (!checked.ok) {
          res.status(400).json({ error: 'invalid_authorization_details', message: checked.message });
          return;
        }
        childCapabilities = checked.details;
      } else if (!capabilitiesSubsumed(parentCapabilities, childCapabilities)) {
        // A parent narrowed to catalogue operations passes them down
        // unchanged, provided the child's own scopes still grant them.
        const inherited = validateCapabilities(parentCapabilities, service, validation.grantedScopes);
        if (!inherited.ok) {
          res.status(403).json({ error: 'capability_escalation_denied', message: `The child's scopes do not cover the parent's capabilities: ${inherited.message}` });
          return;
        }
        childCapabilities = inherited.details;
      }
      if (!capabilitiesSubsumed(parentCapabilities, childCapabilities)) {
        res.status(403).json({ error: 'capability_escalation_denied', message: 'The requested capabilities are wider than the parent delegation\'s' });
        return;
      }
      // Recorded only once the hop's checks pass. A receipt-only parent has
      // no recorded consent: the delegating agent's hop is the consent event.
      const consentId = parentGrant?.consentId ?? (await vault.recordConsent({
        id: `consent_${crypto.randomBytes(16).toString('hex')}`,
        subject: userId,
        agentDid,
        service,
        capabilities: childCapabilities,
        source: 'delegation',
        approvedBy: parent.sub,
        expiresAt: null,
        chainContext: { delegationId, parentDelegationId: parent.delegationId, chainDepth: validation.chainDepth },
      })).id;
      const grantState = newDelegationGrant({
        ...(entry.instanceUrl ? { instanceUrl: entry.instanceUrl } : {}),
        permissionId: permission.id,
        agentDid,
        service,
        scopes: validation.grantedScopes,
        appClientId,
        constraints: validation.grantedConstraints,
        consentId,
        prf: [...(parentGrant?.prf ?? [receiptContentId(parentReceipt)]), receiptContentId(receipt)],
        capabilities: childCapabilities,
      });
      if (!grantState || validation.grantedScopes.length === 0) {
        res.status(400).json({
          error: 'agent_key_required',
          message: 'A Delegation Token is bound to the receiving agent\'s key: agent_did must be a did:key, with at least one granted scope',
        });
        return;
      }

      const recorded = await recordIssuedDelegation(res, {
        id: delegationId,
        parentId: parent.delegationId,
        agentDid,
        service,
        userId,
        chainDepth: validation.chainDepth,
        expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
        grant: grantState,
      }, correlationId);
      if (!recorded) return;

      // ── Sub-Delegation Exchange, step 1: authorization ───────────────────
      // The checks above are the hop's checks; the child is issued only when
      // the agent it names redeems the grant at POST /api/v1/token.
      if (exchange === 'grant') {
        const ttlSeconds = config.delegationGrantTtlSeconds ?? DEFAULT_DELEGATION_GRANT_TTL_SECONDS;
        const expiresAt = Math.min(
          Date.now() + ttlSeconds * 1000,
          parentExpiryBound !== undefined ? parentExpiryBound * 1000 : Number.POSITIVE_INFINITY,
        );
        const grant = delegationGrants.issue({
          agentDid,
          delegatorDid: parent.sub,
          service,
          userId,
          appClientId,
          scopes: validation.grantedScopes,
          constraints: validation.grantedConstraints,
          delegationId,
          parentDelegationId: validation.parentDelegationId,
          chainDepth: validation.chainDepth,
          receipt,
          lineage: ancestorDids,
          ...(agentDelegationToken ? { agentDelegationToken } : {}),
          expiresAt,
        });
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: parent.sub },
          action: 'delegate',
          resource: { type: 'token', id: delegationId },
          outcome: 'success',
          scopesRequested: requestedScopes,
          scopesGranted: validation.grantedScopes,
          delegationChain: [
            { delegatorId: parent.sub, delegateeId: agentDid, scopes: validation.grantedScopes },
          ],
          correlationId,
          metadata: { stage: 'delegation_grant', receivingAgent: agentDid, ...(subdelegationOptOuts.length > 0 ? { enforcementOptOuts: subdelegationOptOuts } : {}) },
        });
        res.json({
          delegation_grant: grant,
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token_type: DELEGATION_GRANT_TOKEN_TYPE,
          expires_in: Math.max(1, Math.floor((expiresAt - Date.now()) / 1000)),
          agent_did: agentDid,
          delegation_id: delegationId,
          // The signed child receipt is a credential in its own right (it
          // anchors further hops), so it is released only to the agent that
          // redeems the grant at /api/v1/token, never to the delegator.
          chain_depth: validation.chainDepth,
          parent_delegation_id: validation.parentDelegationId,
          scopes: validation.grantedScopes,
        });
        return;
      }

      // ── Audit event ──────────────────────────────────────────────────────

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: agentDid },
        action: 'delegate',
        resource: { type: 'token', id: delegationId },
        outcome: 'success',
        scopesRequested: requestedScopes,
        scopesGranted: validation.grantedScopes,
        delegationChain: [
          { delegatorId: parent.sub, delegateeId: agentDid, scopes: validation.grantedScopes },
        ],
        correlationId,
        ...((webBotAuthIdentity || subdelegationOptOuts.length > 0) && {
          metadata: {
            ...(webBotAuthIdentity ? {
              identitySource: 'web-bot-auth',
              webBotAuthKeyId: webBotAuthIdentity.keyId,
              signatureAgent: webBotAuthIdentity.signatureAgent,
              receiptClaims: parent.receiptClaims,
            } : {}),
            ...(subdelegationOptOuts.length > 0 ? { enforcementOptOuts: subdelegationOptOuts } : {}),
          },
        }),
      });

      // ── Response ─────────────────────────────────────────────────────────

      // Sub-delegated responses are always brokered handles — chainDepth is
      // always >= 1 here — regardless of the requested token_format, since
      // scope attenuation on a raw provider token can't be enforced once
      // it's left the server. `isBrokerableService` above already rejected
      // services with no brokered-use path, so 'handle' is always safe here.
      res.json({
        ...buildDelegationResponse({
          tokenFormat: 'handle',
          accessToken: entry.accessToken,
          expiresIn,
          service,
          userId,
          scopes: validation.grantedScopes,
          delegationId,
          receipt,
          chainDepth: validation.chainDepth,
          parentDelegationId: validation.parentDelegationId,
          constraints: validation.grantedConstraints,
          ...(agentDelegationToken ? { agentDelegationToken } : {}),
          agentDid,
          grant: grantState,
          lineage: ancestorDids,
          // The row this hop issued against: the child handle decides over its
          // scopes at each exercise, exactly as the hop's own decision did.
          credentialScopes: entry?.scopes ?? [],
        }),
        // Always present: sub-delegation is broker-only at every depth, so
        // this both confirms the format and flags any downgrade from a
        // caller-requested 'raw' token_format.
        token_format_enforced: 'brokered',
        ...(requestedTokenFormat !== 'handle' ? { requested_token_format: requestedTokenFormat } : {}),
      });
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[POST /api/v1/subdelegate] Error:', err);
      res.status(500).json({ error: 'Sub-delegation failed' });
    }
  });

  /**
   * POST /api/v1/token — Sub-Delegation Exchange, step 2: issuance (RFC 8693)
   *
   * The receiving agent redeems the single-use grant from
   * `POST /api/v1/subdelegate` with `exchange: "grant"`:
   *
   *   grant_type          urn:ietf:params:oauth:grant-type:token-exchange
   *   subject_token       the delegation grant
   *   subject_token_type  urn:credninja:params:oauth:token-type:delegation-grant
   *   actor_token         an RFC 7523 JWT signed with the receiving agent's
   *                       did:key: iss = sub = that DID, aud = this endpoint's
   *                       URL, exp at most iat + 300, a fresh jti
   *   actor_token_type    urn:ietf:params:oauth:token-type:jwt
   *
   * The server checks the actor token names the DID the grant names, then
   * consumes the grant (a second redemption is `invalid_grant`), re-checks
   * the status of every agent in the chain, and issues the child as a
   * brokered handle with the receipt signed at authorization.
   *
   * Auth: Bearer cred_at_<token> (the deployment's agent auth), plus the
   * actor token above as proof of the receiving agent's key.
   */
  // ── CIBA approvals (Section 8.1) ─────────────────────────────────────────

  const approvals = new ApprovalStore();
  const cibaConsentTtlSeconds = config.cibaConsentTtlSeconds ?? 86_400;

  /**
   * The id of a CIBA consent that still covers this request: same subject,
   * agent, service and app client, unexpired, unrevoked, given by every
   * role the Permission now names, with capabilities at least as wide and
   * ceilings at least as loose. A broader request, looser ceilings, a
   * stricter approver, an expired grant or a security event all mean
   * asking again (Section 8.3).
   */
  async function reusableConsent(input: {
    subject: string;
    agentDid: string;
    service: string;
    capabilities: CredDelegationDetail[];
    constraints: DelegationConstraint[];
    appClientId: string;
    approver: Permission['approver'];
  }): Promise<string | null> {
    const now = new Date().toISOString();
    for (const consent of await vault.findConsents({ subject: input.subject, agentDid: input.agentDid, service: input.service })) {
      if (consent.source !== 'ciba') continue;
      if (consent.expiresAt && consent.expiresAt <= now) continue;
      const approved = consent.chainContext as { appClientId?: unknown; constraints?: unknown; approver?: unknown };
      if (approved.appClientId !== input.appClientId) continue;
      if (approved.approver !== 'subject' && approved.approver !== 'admin' && approved.approver !== 'both') continue;
      if (!approvalCovers(approved.approver, input.approver)) continue;
      const approvedConstraints = parseConstraints(approved.constraints ?? []);
      if (!approvedConstraints.ok || !constraintsSubsume(approvedConstraints.constraints, input.constraints).ok) continue;
      if (!capabilitiesSubsumed(consent.capabilities as CredDelegationDetail[], input.capabilities)) continue;
      if (await vault.getConsentRevocation(consent.id)) continue;
      return consent.id;
    }
    return null;
  }

  /** Tell the subject's channel about a request needing their approval. */
  async function askSubject(request: ApprovalRequest): Promise<void> {
    if (config.cibaProvider) {
      void askExternalProvider(config.cibaProvider, request).then((decision) => {
        if (decision !== 'expired') approvals.decide(request.authReqId, 'subject', decision, `oidc:${request.subject}`);
      }).catch((err) => {
        // The subject could not be asked: end the request, not leave it pending.
        approvals.decide(request.authReqId, 'subject', 'deny', 'channel_failure');
        console.error('[ciba] external provider failed:', err instanceof Error ? err.message : err);
      });
      return;
    }
    const approveUrl = `${publicBaseUri()}/approve/${encodeURIComponent(request.authReqId)}?sig=${approvals.linkSignature(request.authReqId)}`;
    const delivered = await fetch(config.approvalWebhookUrl!, {
      method: 'POST',
      signal: AbortSignal.timeout(10_000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'cred.approval_requested',
        auth_req_id: request.authReqId,
        subject: request.subject,
        agent_did: request.agentDid,
        service: request.service,
        capabilities: request.capabilities ?? capabilitiesFor(request.service, request.scopes),
        ...(request.bindingMessage ? { binding_message: request.bindingMessage } : {}),
        approve_url: approveUrl,
        expires_at: new Date(request.expiresAt).toISOString(),
      }),
      redirect: 'manual',
    });
    // A refusal or a redirect means nobody was asked.
    if (!delivered.ok) throw new Error(`approval webhook answered ${delivered.status}`);
  }

  /**
   * POST /bc-authorize — CIBA backchannel authentication request (CIBA
   * Section 7.1) for a delegation that needs approval. The agent proves its
   * did:key with a DPoP proof; the approval is bound to that key.
   */
  // Guard policy decides here as on /api/v1/delegate: an approval never
  // covers more than a direct delegation would be allowed.
  const bcAuthorizeHandlers: Array<express.RequestHandler> = [subdelegateRateLimiter, requireAgentAuth, verifyWebBotAuth];
  if (guardMiddleware) bcAuthorizeHandlers.push(assignProviderFromBody, exposeStoredScopesToGuard('login_hint'), guardMiddleware);
  app.post('/bc-authorize', ...bcAuthorizeHandlers, async (req: Request, res: Response) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const loginHint = body.login_hint;
      const service = body.service;
      const agentDid = body.agent_did;
      if (typeof loginHint !== 'string' || !loginHint || typeof service !== 'string' || !service || typeof agentDid !== 'string') {
        res.status(400).json({ error: 'invalid_request', error_description: 'login_hint, service and agent_did are required' });
        return;
      }
      if (body.connection_id !== undefined) {
        res.status(400).json({ error: 'invalid_request', error_description: 'Cred Link connections are not approved through CIBA' });
        return;
      }
      if (body.user_id !== undefined && body.user_id !== loginHint) {
        res.status(400).json({ error: 'invalid_request', error_description: 'user_id and login_hint name different users' });
        return;
      }
      const jkt = dpopBindingFor(agentDid);
      if (!jkt) {
        res.status(400).json({ error: 'invalid_request', error_description: 'agent_did must be a did:key' });
        return;
      }
      // The same request checks /api/v1/delegate makes: the approval is for
      // a Delegation Token, so the service needs a brokered-use path and the
      // ceilings must be ones a later hop can restate.
      if (!isBrokerableService(service)) {
        res.status(400).json({ error: 'brokered_format_unsupported', error_description: `'${service}' has no brokered-use path` });
        return;
      }
      if (invalidConstraintJson.has(req)) {
        res.status(400).json({ error: 'invalid_constraints', error_description: 'Constraint-bearing requests must use strict JSON' });
        return;
      }
      const constraints = parseConstraints(body.constraints);
      if (!constraints.ok) {
        res.status(400).json({ error: 'invalid_constraints', error_description: constraints.message });
        return;
      }
      const unresolvable = unresolvableRankLabels(constraints.constraints);
      if (unresolvable.length > 0) {
        res.status(400).json({ error: 'invalid_constraints', error_description: `No rank ordering is registered for: ${unresolvable.join(', ')}` });
        return;
      }
      const producerViolations = producerConstraintViolations(constraints.constraints);
      if (producerViolations.length > 0) {
        res.status(400).json({ error: 'invalid_constraints', error_description: producerViolations.join('; ') });
        return;
      }
      // login_hint names the subject the same way user_id does on
      // /api/v1/delegate: an agent bound to one user cannot ask for another.
      (req.body as Record<string, unknown>).user_id = loginHint;
      const subject = requestUserId(req, res, { agent: true, source: 'body' });
      if (subject === null) return;
      if (!checkDpop(req, res, { agentDid, path: '/bc-authorize', resource: { type: 'connection', id: `${service}/${subject}` } })) return;
      if (body.binding_message !== undefined && (typeof body.binding_message !== 'string' || body.binding_message.length > 100)) {
        res.status(400).json({ error: 'invalid_binding_message', error_description: 'binding_message must be a string of at most 100 characters' });
        return;
      }
      const requestedScopes = guardedRequestedScopes(req, res, normalizeRequestedScopes(body.scopes));
      if (requestedScopes === null) return;
      const agentCheck = await didAgentCheck(agentDid, service, requestedScopes);
      if (!agentCheck.ok) {
        res.status(403).json({ error: agentCheck.error, error_description: agentCheck.message });
        return;
      }
      const standing = await agentRevocationStatus(agentDid, service, subject);
      if (standing.refused) {
        denyAgentStanding(agentDid, service, subject, 'agent_access_revoked', crypto.randomUUID(), { cause: standing.cause });
        res.status(403).json({ error: 'agent_access_revoked', error_description: AGENT_ACCESS_REVOKED_MESSAGE });
        return;
      }
      const approvalOptOuts = standing.bypassed ? ['redelegation_after_revocation'] : [];
      const permission = await permissionForDidAgent(agentDid, agentCheck.record, service);
      if (!permission && !allowAgentsWithoutPermission) {
        denyAgentStanding(agentDid, service, subject, 'permission_required', crypto.randomUUID());
        res.status(403).json({ error: 'permission_required', error_description: permissionRequiredMessage(agentDid, service) });
        return;
      }
      if (!permission?.requiresApproval) {
        res.status(400).json({ error: 'invalid_request', error_description: 'This delegation needs no approval: request it at /api/v1/delegate' });
        return;
      }
      const refusal = await permissionRefusal(permission);
      if (refusal && refusal !== 'approval_required') {
        refusePermission(res, refusal);
        return;
      }
      const approver = permission.approver ?? 'subject';
      if (approver !== 'admin' && !config.cibaProvider && !config.approvalWebhookUrl) {
        res.status(503).json({ error: 'approval_unavailable', error_description: 'No channel is configured to ask the subject (CRED_APPROVAL_WEBHOOK_URL or an external CIBA provider)' });
        return;
      }
      if (!approvals.hasCapacity({ agentDid, subject })) {
        res.status(503).json({ error: 'approval_unavailable', error_description: 'Too many approval requests are pending; try again later' });
        return;
      }
      const vaultEntry = await getVaultEntry(service, subject);
      if ('status' in vaultEntry) {
        res.status(vaultEntry.status === 404 ? 403 : vaultEntry.status).json(vaultEntry.status === 404 ? { error: 'consent_required' } : vaultEntry.body);
        return;
      }
      const { grantedScopes, widenedScopes } = resolveGrantedScopes(
        service,
        scopesForDidAgent(service, vaultEntry.entry.scopes ?? [], agentCheck.record, permission),
        requestedScopes,
      );
      if (widenedScopes.length > 0 || grantedScopes.length === 0) {
        res.status(403).json({ error: 'scope_escalation_denied', error_description: 'Requested scopes exceed the stored connection or the Permission' });
        return;
      }
      let capabilities: CredDelegationDetail[] | undefined;
      if (body.authorization_details !== undefined) {
        const checked = validateCapabilities(body.authorization_details, service, grantedScopes);
        if (!checked.ok) {
          res.status(400).json({ error: 'invalid_authorization_details', error_description: checked.message });
          return;
        }
        capabilities = checked.details;
      }
      let request: ApprovalRequest;
      try {
        request = approvals.create({
          subject,
          agentDid,
          jkt,
          service,
          appClientId: typeof body.appClientId === 'string' ? body.appClientId : 'local',
          scopes: grantedScopes,
          ...(capabilities ? { capabilities } : {}),
          constraints: constraints.constraints,
          ...(typeof body.binding_message === 'string' ? { bindingMessage: body.binding_message } : {}),
          approver,
        });
      } catch (err) {
        if (!(err instanceof ApprovalCapacityError)) throw err;
        res.status(503).json({ error: 'approval_unavailable', error_description: 'Too many approval requests are pending; try again later' });
        return;
      }
      if (approver !== 'admin') {
        try {
          await askSubject(request);
        } catch (err) {
          // Nobody was asked: end the request rather than leave it pending.
          approvals.decide(request.authReqId, 'subject', 'deny', 'channel_failure');
          console.error('[POST /bc-authorize] approval channel failed:', err instanceof Error ? err.message : err);
          res.status(502).json({ error: 'approval_unavailable', error_description: 'The approval channel could not be reached' });
          return;
        }
      }
      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: agentDid },
        action: 'create',
        resource: { type: 'token', id: `${service}/${subject}` },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
        metadata: { stage: 'approval_requested', authReqId: request.authReqId, approver, ...(approvalOptOuts.length > 0 ? { enforcementOptOuts: approvalOptOuts } : {}) },
      });
      res.json({
        auth_req_id: request.authReqId,
        expires_in: Math.floor((request.expiresAt - Date.now()) / 1000),
        interval: request.intervalSeconds,
      });
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[POST /bc-authorize] Error:', err);
      res.status(500).json({ error: 'server_error' });
    }
  });

  /**
   * Issue the Delegation Token for an approved CIBA request, recording its
   * consent. What was approved is checked again against the state now: the
   * agent, its Permission and the connection may have changed while the
   * request waited, and an approval never outlasts them.
   */
  async function issueApprovedDelegation(request: ApprovalRequest, res: Response): Promise<void> {
    const refuse = (description: string) => res.status(400).json({ error: 'invalid_grant', error_description: description });
    const agentCheck = await didAgentCheck(request.agentDid, request.service, request.scopes);
    if (!agentCheck.ok) {
      refuse(`The agent can no longer be delegated to (${agentCheck.error})`);
      return;
    }
    const standing = await agentRevocationStatus(request.agentDid, request.service, request.subject);
    if (standing.refused) {
      refuse('The agent\'s access to this service was revoked; it needs a new Permission');
      return;
    }
    const permission = await permissionForDidAgent(request.agentDid, agentCheck.record, request.service);
    if (!permission?.requiresApproval
      || (permission.expiresAt && permission.expiresAt.getTime() <= Date.now())
      || !approvalCovers(request.approver, permission.approver)) {
      refuse('The Permission behind this approval changed; ask again');
      return;
    }
    const vaultEntry = await getVaultEntry(request.service, request.subject);
    if ('status' in vaultEntry) {
      refuse('The connection behind this approval is gone');
      return;
    }
    const stillAllowed = resolveGrantedScopes(request.service, scopesForDidAgent(request.service, vaultEntry.entry.scopes ?? [], agentCheck.record, permission), request.scopes);
    if (stillAllowed.widenedScopes.length > 0) {
      refuse('The approved scopes are no longer all allowed; ask again');
      return;
    }
    const delegationId = `del_${crypto.randomUUID().replace(/-/g, '')}`;
    const expiresIn = handleLifetimeSeconds(vaultEntry.entry.expiresAt);
    const capabilities = (request.capabilities as CredDelegationDetail[] | undefined) ?? capabilitiesFor(request.service, request.scopes);
    const constraints = request.constraints as DelegationConstraint[];
    const receipt = createReceipt({
      agentDid: request.agentDid,
      service: request.service,
      userId: request.subject,
      appClientId: request.appClientId,
      scopes: request.scopes,
      delegationId,
      chainDepth: 0,
      constraints,
    });
    const consentId = `consent_${crypto.randomBytes(16).toString('hex')}`;
    const grant = newDelegationGrant({
      ...(vaultEntry.entry.instanceUrl ? { instanceUrl: vaultEntry.entry.instanceUrl } : {}),
      permissionId: permission.id,
      agentDid: request.agentDid,
      service: request.service,
      scopes: request.scopes,
      appClientId: request.appClientId,
      constraints,
      consentId,
      prf: [receiptContentId(receipt)],
      capabilities,
    })!;
    const recorded = await recordIssuedDelegation(res, {
      id: delegationId,
      parentId: null,
      agentDid: request.agentDid,
      service: request.service,
      userId: request.subject,
      chainDepth: 0,
      expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
      grant,
    }, crypto.randomUUID());
    if (!recorded) return;
    // Recorded once the delegation is, so a failed issue leaves no reusable
    // consent behind. What reuse must match is kept with it.
    await vault.recordConsent({
      id: consentId,
      subject: request.subject,
      agentDid: request.agentDid,
      service: request.service,
      capabilities,
      source: 'ciba',
      approvedBy: [request.approvals.subject, request.approvals.admin].filter(Boolean).join(', '),
      expiresAt: new Date(Date.now() + cibaConsentTtlSeconds * 1000).toISOString(),
      chainContext: {
        delegationId,
        chainDepth: 0,
        authReqId: request.authReqId,
        appClientId: request.appClientId,
        constraints,
        approver: request.approver,
      },
    });
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: request.agentDid },
      action: 'delegate',
      resource: { type: 'token', id: delegationId },
      outcome: 'success',
      scopesGranted: request.scopes,
      correlationId: crypto.randomUUID(),
      metadata: { stage: 'ciba_redemption', authReqId: request.authReqId, ...(standing.bypassed ? { enforcementOptOuts: ['redelegation_after_revocation'] } : {}) },
    });
    res.json(buildDelegationResponse({
      tokenFormat: 'handle',
      grant,
      accessToken: vaultEntry.entry.accessToken,
      expiresIn,
      service: request.service,
      userId: request.subject,
      scopes: request.scopes,
      delegationId,
      receipt,
      constraints,
      agentDid: request.agentDid,
      // The row this token was read from: the handle decides over its scopes at
      // each exercise, never over a row that replaced it later.
      credentialScopes: vaultEntry.entry.scopes ?? [],
    }));
  }

  /** The built-in approval page: the signed link the subject's webhook carries. */
  app.get('/approve/:authReqId', connectUiRateLimiter, (req: Request, res: Response) => {
    const authReqId = routeParam(req.params.authReqId) ?? '';
    const request = approvals.get(authReqId);
    if (!request || !approvals.verifyLink(authReqId, req.query.sig) || request.status !== 'pending' || request.approver === 'admin') {
      res.status(404).send('This approval link is not valid or has already been used.');
      return;
    }
    const caps = JSON.stringify(request.capabilities ?? capabilitiesFor(request.service, request.scopes), null, 2);
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
    res.set('X-Frame-Options', 'DENY');
    res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Approve delegation</title>
<style>body{font:16px system-ui;max-width:40rem;margin:2rem auto;padding:0 1rem}pre{background:#f4f4f4;padding:1rem;overflow:auto}button{font:inherit;padding:.5rem 1rem;margin-right:.5rem}</style></head>
<body><h1>Approve access for an agent?</h1>
<p>Agent <code>${escapeHtml(request.agentDid)}</code> asks to act for <strong>${escapeHtml(request.subject)}</strong> on <strong>${escapeHtml(request.service)}</strong>.</p>
${request.bindingMessage ? `<p>Code shown by the agent: <strong>${escapeHtml(request.bindingMessage)}</strong></p>` : ''}
<p>It would be allowed:</p><pre>${escapeHtml(caps)}</pre>
<form method="post" action="/approve/${encodeURIComponent(authReqId)}"><input type="hidden" name="sig" value="${escapeHtml(String(req.query.sig))}">
<button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></form></body></html>`);
  });

  app.post('/approve/:authReqId', connectUiRateLimiter, (req: Request, res: Response) => {
    const authReqId = routeParam(req.params.authReqId) ?? '';
    const decision = req.body?.decision;
    if (!approvals.verifyLink(authReqId, req.body?.sig) || (decision !== 'approve' && decision !== 'deny')) {
      res.status(404).send('This approval link is not valid or has already been used.');
      return;
    }
    // Whoever holds the signed link decides: recorded as the link, not as
    // the subject's own sign-in.
    const request = approvals.decide(authReqId, 'subject', decision, `link:${approvals.get(authReqId)?.subject ?? 'unknown'}`);
    if (!request) {
      res.status(404).send('This approval link is not valid or has already been used.');
      return;
    }
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'user', id: request.subject },
      action: decision === 'approve' ? 'update' : 'deny',
      resource: { type: 'token', id: `${request.service}/${request.subject}` },
      outcome: decision === 'approve' ? 'success' : 'denied',
      correlationId: crypto.randomUUID(),
      metadata: { stage: 'approval_decided', authReqId, role: 'subject' },
    });
    res.send(decision === 'approve' ? 'Approved. You can close this page.' : 'Denied. You can close this page.');
  });

  app.get('/admin/approvals', adminAuditRateLimiter, requireAdminAuth, (_req: Request, res: Response) => {
    res.json({
      approvals: approvals.pending().filter((r) => r.approver !== 'subject').map((r) => ({
        auth_req_id: r.authReqId, subject: r.subject, agent_did: r.agentDid, service: r.service,
        capabilities: r.capabilities ?? capabilitiesFor(r.service, r.scopes), approver: r.approver,
        approvals: r.approvals, expires_at: new Date(r.expiresAt).toISOString(),
      })),
    });
  });

  app.post('/admin/approvals/:authReqId', adminAuditRateLimiter, requireAdminAuth, (req: Request, res: Response) => {
    const decision = req.body?.decision;
    if (decision !== 'approve' && decision !== 'deny') {
      res.status(400).json({ error: 'invalid_request', message: "decision must be 'approve' or 'deny'" });
      return;
    }
    const request = approvals.decide(routeParam(req.params.authReqId) ?? '', 'admin', decision, 'admin');
    if (!request) {
      res.status(404).json({ error: 'not_found', message: 'No pending approval with this id needs an admin' });
      return;
    }
    res.json({ auth_req_id: request.authReqId, status: request.status });
  });

  /**
   * POST /admin/consents/revoke — a security event (Section 8.3, trigger
   * 4): revoke the matching consents. Tokens issued under them are refused
   * at exercise, and the next request asks again.
   */
  app.post('/admin/consents/revoke', adminAuditRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    const body = (req.body ?? {}) as { consent_ids?: unknown; subject?: unknown; agent_did?: unknown; reason?: unknown };
    const filter = {
      ...(Array.isArray(body.consent_ids) ? { consentIds: body.consent_ids.filter((x): x is string => typeof x === 'string') } : {}),
      ...(typeof body.subject === 'string' ? { subject: body.subject } : {}),
      ...(typeof body.agent_did === 'string' ? { agentDid: body.agent_did } : {}),
    };
    if (!filter.consentIds?.length && !filter.subject && !filter.agentDid) {
      res.status(400).json({ error: 'invalid_request', message: 'Name consent_ids, a subject or an agent_did' });
      return;
    }
    const reason = typeof body.reason === 'string' && body.reason ? body.reason.slice(0, 200) : 'security_event';
    const revoked = await vault.revokeConsents(filter, reason);
    // An approval given but not yet redeemed would otherwise issue after the event.
    const cancelled = filter.subject || filter.agentDid
      ? approvals.cancel({ ...(filter.subject ? { subject: filter.subject } : {}), ...(filter.agentDid ? { agentDid: filter.agentDid } : {}) }, `security_event:${reason}`)
      : [];
    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'system', id: 'admin' },
      action: 'revoke',
      resource: { type: 'permission', id: 'consents' },
      outcome: 'success',
      correlationId: crypto.randomUUID(),
      metadata: { stage: 'consent_revoked', count: revoked.length, cancelledApprovals: cancelled.length, reason },
    });
    res.json({ revoked_count: revoked.length, revoked_ids: revoked, cancelled_approvals: cancelled });
  });

  app.post('/api/v1/token', subdelegateRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    const correlationId = crypto.randomUUID();
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      // CIBA poll mode (CIBA Section 10.1): the agent that asked, proving
      // the same key, redeems an approved request for its Delegation Token.
      if (body.grant_type === CIBA_GRANT_TYPE) {
        const pending = typeof body.auth_req_id === 'string' ? approvals.get(body.auth_req_id) : null;
        if (!pending) {
          res.status(400).json({ error: 'invalid_grant', error_description: 'Unknown auth_req_id' });
          return;
        }
        // As on the grant redemption below: a caller bound to a user may only
        // redeem that user's approvals, even when it shares the agent's key.
        const boundCibaUser = principalBoundUserId(req);
        if (boundCibaUser !== undefined && boundCibaUser !== pending.subject) {
          res.status(403).json({ error: 'user_id_mismatch' });
          return;
        }
        if (!checkDpop(req, res, { agentDid: pending.agentDid, path: '/api/v1/token', resource: { type: 'token', id: `${pending.service}/${pending.subject}` } })) return;
        const polled = approvals.poll(pending.authReqId, pending.jkt);
        if (!polled.ok) {
          res.status(400).json({ error: polled.error, error_description: polled.description });
          return;
        }
        await issueApprovedDelegation(polled.request, res);
        return;
      }
      if (body.grant_type !== TOKEN_EXCHANGE_GRANT_TYPE) {
        res.status(400).json({ error: 'unsupported_grant_type' });
        return;
      }
      if (body.subject_token_type !== DELEGATION_GRANT_TOKEN_TYPE || typeof body.subject_token !== 'string') {
        res.status(400).json({ error: 'invalid_request', error_description: `subject_token must be a delegation grant (${DELEGATION_GRANT_TOKEN_TYPE})` });
        return;
      }
      if (body.actor_token_type !== JWT_TOKEN_TYPE || typeof body.actor_token !== 'string') {
        res.status(400).json({ error: 'invalid_request', error_description: `actor_token must be a JWT (${JWT_TOKEN_TYPE}) signed by the receiving agent` });
        return;
      }
      const pending = delegationGrants.peek(body.subject_token);
      if (!pending) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'The delegation grant is unknown, expired, or already redeemed' });
        return;
      }
      const tokenEndpoint = `${publicBaseUri()}/api/v1/token`;
      const actor = verifyActorToken(body.actor_token, pending.agentDid, tokenEndpoint, actorTokenJtiSeen);
      if (!actor.ok) {
        writeAuditEventIfSupported({
          id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
          timestamp: new Date(),
          actor: { type: 'agent', id: pending.agentDid },
          action: 'deny',
          resource: { type: 'token', id: `${pending.service}/${pending.userId}` },
          outcome: 'denied',
          errorMessage: 'actor_token_rejected',
          correlationId,
        });
        res.status(401).json({ error: 'invalid_client', error_description: actor.message });
        return;
      }
      // A custom agentRequestVerifier that binds this caller to a user may
      // only redeem that user's grants (as on every legacy route).
      const boundUserId = principalBoundUserId(req);
      if (boundUserId !== undefined && boundUserId !== pending.userId) {
        res.status(403).json({ error: 'user_id_mismatch' });
        return;
      }
      // Single use: consumed only once the redeemer is shown to be the agent it names.
      const grant = delegationGrants.redeem(body.subject_token);
      if (!grant) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'The delegation grant is unknown, expired, or already redeemed' });
        return;
      }

      // The child was recorded at authorization; a revocation of it or an
      // ancestor since then refuses the redemption.
      const revokedBy = await delegationRevokedBy(grant.delegationId);
      if (revokedBy !== null) {
        res.status(401).json({ error: 'delegation_revoked', message: 'This delegation has been revoked', revoked_ancestor_id: revokedBy });
        return;
      }

      let redemptionBypassedHold = false;
      for (const did of [...grant.lineage, grant.agentDid]) {
        const record = vault.getAgentByDid ? await vault.getAgentByDid(did) : null;
        if (record?.status === 'revoked' || record?.status === 'suspended') {
          res.status(403).json({ error: did === grant.agentDid ? `agent_${record.status}` : `ancestor_agent_${record.status}`, message: `Agent ${did} has been ${record.status}` });
          return;
        }
        const standing = await agentRevocationStatus(did, grant.service, grant.userId);
        if (standing.refused) {
          denyAgentStanding(grant.agentDid, grant.service, grant.userId, 'agent_access_revoked', correlationId, { cause: standing.cause, revokedAgent: did });
          res.status(403).json({ error: 'agent_access_revoked', message: AGENT_ACCESS_REVOKED_MESSAGE });
          return;
        }
        if (standing.bypassed) redemptionBypassedHold = true;
      }

      const vaultEntry = await getVaultEntry(grant.service, grant.userId);
      if ('status' in vaultEntry) {
        res.status(vaultEntry.status).json(vaultEntry.body);
        return;
      }
      const entry = vaultEntry.entry;
      // The child was bounded by its parent at authorization (the recorded
      // expiry); redemption can only shorten that, never extend it.
      const childRecord = await vault.getDelegation(grant.delegationId);
      const recordedExpiresIn = childRecord?.expiresAt
        ? Math.floor((Date.parse(childRecord.expiresAt) - Date.now()) / 1000)
        : Number.POSITIVE_INFINITY;
      const expiresIn = Math.min(handleLifetimeSeconds(entry.expiresAt), recordedExpiresIn);
      if (expiresIn <= 0) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'The delegation behind this grant has expired' });
        return;
      }

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: grant.agentDid },
        action: 'delegate',
        resource: { type: 'token', id: grant.delegationId },
        outcome: 'success',
        scopesGranted: grant.scopes,
        delegationChain: [
          { delegatorId: grant.delegatorDid, delegateeId: grant.agentDid, scopes: grant.scopes },
        ],
        correlationId,
        metadata: { stage: 'token_exchange', actorTokenJti: actor.jti, ...(redemptionBypassedHold ? { enforcementOptOuts: ['redelegation_after_revocation'] } : {}) },
      });

      const recordedGrant = childRecord?.grant;
      if (!recordedGrant) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'The delegation behind this grant has no Delegation Token state' });
        return;
      }
      res.json({
        ...buildDelegationResponse({
          tokenFormat: 'handle',
          grant: recordedGrant,
          lineage: grant.lineage,
          accessToken: entry.accessToken,
          expiresIn,
          service: grant.service,
          userId: grant.userId,
          scopes: grant.scopes,
          delegationId: grant.delegationId,
          receipt: grant.receipt,
          chainDepth: grant.chainDepth,
          parentDelegationId: grant.parentDelegationId,
          constraints: grant.constraints,
          agentDid: grant.agentDid,
          // The row the exchanged token was read from: the handle decides over
          // its scopes at each exercise, never over a row that replaced it.
          credentialScopes: entry.scopes ?? [],
          ...(grant.agentDelegationToken ? { agentDelegationToken: grant.agentDelegationToken } : {}),
        }),
        // RFC 8693 Section 2.2.1: the issued token is the DPoP-bound
        // Delegation Token, an access token (token_type DPoP).
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        token_format_enforced: 'brokered',
      });
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[POST /api/v1/token] Error:', err);
      res.status(500).json({ error: 'server_error' });
    }
  });

  /**
   * DELETE /api/v1/delegations/:delegationId: revoke a delegation and every
   * delegation derived from it (draft-sweeney-wimse-credential-delegation,
   * "Revocation"). The vault walks the recorded parent linkage and revokes
   * the whole subtree in one transaction; brokered handles in the subtree
   * are refused by /api/v1/use from then on, including calls already in
   * flight that have not yet gone upstream. Raw provider tokens already
   * handed out cannot be recalled and live until they expire.
   *
   * Scoped like the other agent routes: the delegation must belong to the
   * resolved user, otherwise 404. Idempotent: revoking again reports
   * revoked_count 0.
   */
  // DELETE /delegation/{jti} is the path draft-sweeney-wimse-credential-delegation
  // Section 7 names; the id is the receipt jti. Same handler, same checks.
  app.delete(['/api/v1/delegations/:delegationId', '/delegation/:delegationId'], revokeRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const delegationId = routeParam(req.params.delegationId);
      if (!delegationId) {
        res.status(400).json({ error: 'Missing delegationId parameter' });
        return;
      }
      const userId = requestUserId(req, res, { agent: true });
      if (userId === null) return;

      const started = performance.now();
      const record = await vault.getDelegation(delegationId);
      if (!record || record.userId !== userId) {
        res.status(404).json({ error: 'delegation_not_found' });
        return;
      }

      const principal = (req as any).agentPrincipal as RequestAgentPrincipal | undefined;
      const result = await applyRevocation(await vault.revokeDelegations({ delegationIds: [delegationId] }, { hold: { cause: `delegation:${delegationId}` } }), started, {
        actor: { type: 'agent', id: (req as any).webBotAuthIdentity?.agentId ?? principal?.principalId ?? 'server-agent' },
        correlationId: crypto.randomUUID(),
        cause: `delegation:${delegationId}`,
      });

      res.json({
        delegation_id: delegationId,
        revoked_count: result.count,
        revoked_ids: result.revokedIds,
        elapsed_ms: Math.round(result.elapsedMs * 1000) / 1000,
        truncated: result.truncated,
      });
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[DELETE /api/v1/delegations/:delegationId] Error:', err);
      res.status(500).json({ error: 'Failed to revoke delegation' });
    }
  });

  /**
   * DELETE /api/token/:provider — Revoke stored credentials
   *
   * Deletes the provider's tokens from the vault.
   * Auth: Bearer cred_at_<token>
   */
  app.delete('/api/token/:provider', revokeRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      const userId = requestUserId(req, res, { agent: true });
      if (userId === null) return;
      await revokeStoredProvider(slug, userId);

      res.status(204).send();
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[DELETE /api/token/:provider] Error:', { provider: req.params.provider, err });
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  app.delete('/api/v1/connections/:provider', revokeRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const userId = requestUserId(req, res, { agent: true });
      if (userId === null) return;
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      await revokeStoredProvider(slug, userId);
      res.status(204).send();
    } catch (err) {
      if (sendReservedUserIdError(res, err)) return;
      console.error('[DELETE /api/v1/connections/:provider] Error:', { provider: req.params.provider, err });
      res.status(500).json({ error: 'Failed to revoke connection' });
    }
  });

  /**
   * Delete consent records whose retention ended (Section 8.2): kept at
   * least consentRetentionDays after the later of their grant and expiry.
   * The purge is itself audited, in the tamper-evident log.
   */
  async function purgeExpiredConsents(now = Date.now()): Promise<number> {
    const purged = await vault.purgeConsents(new Date(now - consentRetentionDays * 86_400_000));
    if (purged > 0) {
      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(now),
        actor: { type: 'system', id: 'server' },
        action: 'delete',
        resource: { type: 'permission', id: 'consents' },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
        metadata: { stage: 'consent_retention_purge', count: purged, retentionDays: consentRetentionDays },
      });
    }
    return purged;
  }
  // Daily, starting a minute after startup (never racing the vault's first init).
  const runPurge = () => void purgeExpiredConsents().catch((err) => console.error('[consent] retention purge failed:', err instanceof Error ? err.message : err));
  const firstPurge = setTimeout(() => {
    runPurge();
    const daily = setInterval(runPurge, 86_400_000);
    if (daily.unref) daily.unref();
  }, 60_000);
  if (firstPurge.unref) firstPurge.unref();

  return { app, vault, tofu, link: linkService, purgeExpiredConsents, flushAuditAggregates: () => refusals.flush() };
}
