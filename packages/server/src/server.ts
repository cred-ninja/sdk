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
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import { CredVault, validateSubDelegation, DelegationChainError, scopeCoveredBy } from '@credninja/vault';
import type { AgentRecord } from '@credninja/vault';
import { AgentVault, agentIdentityToDirectoryJwks, publicKeyToJwkWithKid } from '@credninja/tofu';
import { OAuthClient, createAdapter } from '@credninja/oauth';
import type { BuiltinAdapterSlug } from '@credninja/oauth';
import type { ServerConfig, ProviderConfig, RequestAgentPrincipal } from './config.js';
import { createExpressMiddleware, type GuardContext, type GuardDecision } from '@credninja/guard';
import { computeTofuAuthorization, resolveTofuPrincipal, toTofuPrincipalId } from './tofu-bridge.js';
import { createWebBotAuthNonceStore } from './nonce-store.js';
import {
  CRED_PROTOCOL_SUPPORTED_VERSIONS,
  CRED_PROTOCOL_VERSION,
  CRED_PROTOCOL_VERSION_HEADER,
  CRED_PROTOCOL_VERSION_MINIMUM,
  CRED_PROTOCOL_VERSION_UNSUPPORTED_ERROR,
  isCredProtocolVersionSupported,
} from '@credninja/protocol';
import { verifyReceiptChain } from './receipt-chain.js';

// ── Types ────────────────────────────────────────────────────────────────────

interface PendingOAuth {
  provider: string;
  userId: string;
  scopes: string[];
  state: string;
  codeVerifier?: string;
  createdAt: number;
}

interface BrokeredDelegation {
  accessToken: string;
  service: string;
  userId: string;
  scopes: string[];
  expiresAt: number;
  createdAt: number;
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
const DEFAULT_DELEGATION_TTL_SECONDS = 900;
const DEFAULT_RECEIPT_TTL_SECONDS = 3600;
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
};

const GOOGLE_SCOPE_ENDPOINTS: Array<{ scopes: string[]; bases: string[] }> = [
  {
    scopes: ['calendar', 'calendar.readonly', 'calendar.events'],
    bases: ['https://www.googleapis.com/calendar/', 'https://calendar.googleapis.com/'],
  },
  {
    scopes: ['gmail.readonly', 'gmail.send', 'gmail.compose', 'gmail.modify', 'mail.google.com'],
    bases: ['https://gmail.googleapis.com/', 'https://www.googleapis.com/gmail/'],
  },
  {
    scopes: ['drive', 'drive.readonly', 'drive.file', 'drive.metadata.readonly'],
    bases: ['https://www.googleapis.com/drive/', 'https://www.googleapis.com/upload/drive/', 'https://drive.googleapis.com/'],
  },
  {
    scopes: ['spreadsheets', 'spreadsheets.readonly'],
    bases: ['https://sheets.googleapis.com/'],
  },
  {
    scopes: ['documents', 'documents.readonly'],
    bases: ['https://docs.googleapis.com/'],
  },
  {
    scopes: ['admin', 'admin.directory.user.readonly', 'admin.directory.group.readonly'],
    bases: ['https://admin.googleapis.com/'],
  },
  {
    scopes: ['openid', 'email', 'profile', 'userinfo.email', 'userinfo.profile'],
    bases: ['https://www.googleapis.com/oauth2/', 'https://openidconnect.googleapis.com/'],
  },
  {
    scopes: ['contacts', 'contacts.readonly'],
    bases: ['https://people.googleapis.com/'],
  },
];

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
  if (!config.agentToken && !config.agentRequestVerifier) {
    throw new Error('Either agentToken or agentRequestVerifier is required');
  }

  const app = express();
  app.use(express.json());
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
  const brokeredDelegations = new Map<string, BrokeredDelegation>();
  const webBotAuthDirectoryCache = new Map<string, { expiresAt: number; directory: WebBotAuthDirectoryResponse }>();
  const webBotAuthNonceStore = createWebBotAuthNonceStore({
    store: config.webBotAuthNonceStore ?? 'memory',
    path: config.webBotAuthNoncePath,
  });

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

  function safeRelativePath(rawPath: string | undefined, fallback = '/connect'): string {
    if (!rawPath || !rawPath.startsWith('/') || rawPath.startsWith('//') || rawPath.includes('\\')) {
      return fallback;
    }
    return rawPath;
  }

  function requestUserId(req: Request): string {
    const queryUserId = queryStringValue(req.query.user_id);
    const bodyUserId = typeof req.body?.user_id === 'string' ? req.body.user_id : undefined;
    const userId = (bodyUserId ?? queryUserId ?? 'default').trim();
    return userId || 'default';
  }

  function buildConsentUrl(input: {
    service: string;
    userId: string;
    appClientId?: string;
    scopes?: string[];
  }): string {
    const url = new URL(`/connect/${encodeURIComponent(input.service)}`, config.redirectBaseUri);
    url.searchParams.set('user_id', input.userId);
    if (input.appClientId) {
      url.searchParams.set('app_client_id', input.appClientId);
    }
    if (input.scopes && input.scopes.length > 0) {
      url.searchParams.set('scopes', input.scopes.join(','));
    }
    return url.toString();
  }

  function tokenFormatFromBody(req: Request): 'raw' | 'handle' {
    return req.body?.token_format === 'handle' ? 'handle' : 'raw';
  }

  function scopeMatches(grantedScope: string, requiredScope: string): boolean {
    const normalized = grantedScope.toLowerCase().replace(/\/$/, '');
    const required = requiredScope.toLowerCase();
    return scopeEquivalent(grantedScope, requiredScope) ||
      normalized.endsWith(`/${required}`) ||
      normalized.endsWith(`auth/${required}`) ||
      normalized.includes(`//${required}`);
  }

  function canonicalScope(scope: string): string {
    const trimmed = scope.trim().replace(/\/$/, '');
    const normalized = trimmed.toLowerCase();
    const googleAuthPrefix = 'https://www.googleapis.com/auth/';
    if (normalized.startsWith(googleAuthPrefix)) {
      return normalized.slice(googleAuthPrefix.length);
    }
    return trimmed;
  }

  function scopeEquivalent(left: string, right: string): boolean {
    return canonicalScope(left) === canonicalScope(right);
  }

  function isAllowedGoogleScopeEndpoint(normalizedUrl: string, scopes?: string[]): boolean {
    if (!scopes || scopes.length === 0) return false;
    return GOOGLE_SCOPE_ENDPOINTS.some(({ scopes: requiredScopes, bases }) => (
      bases.some((base) => normalizedUrl.startsWith(base)) &&
      requiredScopes.some((requiredScope) => scopes.some((scope) => scopeMatches(scope, requiredScope)))
    ));
  }

  function isAllowedBrokerUrl(service: string, url: string, scopes?: string[]): boolean {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return false;
    }

    if (parsed.protocol !== 'https:') return false;
    if (parsed.username || parsed.password) return false;
    if (parsed.port !== '' && parsed.port !== '443') return false;

    const hostname = parsed.hostname.toLowerCase();
    if (service === 'salesforce') {
      const isPrivateIpSubdomain = /^(\d{1,3}\.){3}\d{1,3}\./.test(hostname);
      if (isPrivateIpSubdomain) return false;
      return hostname.endsWith('.salesforce.com') || hostname.endsWith('.force.com');
    }

    const allowed = SERVICE_ALLOWLIST[service];
    if (!allowed) return false;
    const normalizedUrl = `https://${hostname}${parsed.pathname}`;
    if (!allowed.some((base) => normalizedUrl.startsWith(base))) return false;
    if (service === 'google') {
      return isAllowedGoogleScopeEndpoint(normalizedUrl, scopes);
    }
    return true;
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

  function validateAdminRequest(req: Request): boolean {
    const token = extractBearerToken(req);
    if (token && tokenMatchesHash(token, adminTokenHash)) {
      return true;
    }
    const cookies = parseCookies(req);
    return validateAdminSessionValue(cookies[ADMIN_SESSION_COOKIE]);
  }

  /**
   * Admin auth middleware for provider-management browser routes.
   *
   * Browser login posts the admin token to `/admin/login`, then stores an
   * HttpOnly same-site cookie. API callers may also use Bearer admin auth.
   */
  function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
    if (!validateAdminRequest(req)) {
      res.status(401).json({ error: 'Unauthorized. Provide a valid admin Bearer token or sign in at /admin/login.' });
      return;
    }

    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  }

  function hashAgentPrincipal(principal: RequestAgentPrincipal): string {
    const stableId = principal.principalId ?? 'anonymous';
    return crypto.createHash('sha256').update(`${principal.type}:${stableId}`).digest('hex');
  }

  /**
   * Agent auth middleware for /api/* routes.
   */
  async function requireAgentAuth(req: Request, res: Response, next: NextFunction) {
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

  async function verifyWebBotAuth(req: Request, res: Response, next: NextFunction) {
    const mode = config.webBotAuthMode ?? 'off';
    if (mode === 'off') {
      next();
      return;
    }

    const hasHeaders = Boolean(req.get('Signature') || req.get('Signature-Input') || req.get('Signature-Agent'));
    if (!hasHeaders) {
      if (mode === 'require') {
        res.status(401).json({ error: 'Web Bot Auth signature required' });
        return;
      }
      next();
      return;
    }

    try {
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

      next();
    } catch (err) {
      res.status(401).json({
        error: 'invalid_web_bot_auth',
        message: err instanceof Error ? err.message : 'Web Bot Auth verification failed',
      });
    }
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
    webBotAuthNonceStore.remember({
      signatureAgent,
      keyId: parsed.params.keyid,
      nonce: parsed.params.nonce,
      expiresAtSeconds: expires,
    });
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

  function getReceiptPublicKey() {
    const publicKey = createPublicKey(getReceiptSigningKey());
    return publicKey;
  }

  function getReceiptTtlSeconds(): number {
    return config.receiptTtlSeconds ?? DEFAULT_RECEIPT_TTL_SECONDS;
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
     * Upper bound on this receipt's `exp`, in Unix seconds. Sub-delegation
     * passes the parent's expiry here so a child receipt can never outlive
     * the receipt it was derived from (monotonic expiry down the chain).
     */
    expiresAtSecondsCeiling?: number;
  }): string {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const nowSeconds = Math.floor(Date.now() / 1000);
    const aud = getReceiptAudience();
    const ttlExp = nowSeconds + getReceiptTtlSeconds();
    const exp = typeof input.expiresAtSecondsCeiling === 'number'
      ? Math.min(ttlExp, input.expiresAtSecondsCeiling)
      : ttlExp;
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:key:local-cred',
      sub: input.agentDid,
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
    })).toString('base64url');

    const signatureInput = Buffer.from(`${header}.${payload}`, 'utf8');
    const signature = sign(null, signatureInput, getReceiptSigningKey()).toString('base64url');
    return `${header}.${payload}.${signature}`;
  }

  function parseAndVerifyReceipt(receipt: string): {
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
    /** Unix seconds. Absent only on legacy receipts minted before these claims existed. */
    iat?: number;
    exp?: number;
  } {
    const parts = receipt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid receipt format');
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Verify signature
    const signatureInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
    const signatureBuffer = Buffer.from(signatureB64, 'base64url');
    const valid = verify(null, signatureInput, getReceiptPublicKey(), signatureBuffer);
    if (!valid) {
      throw new Error('Invalid receipt signature');
    }

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (!payload.delegationId) {
      throw new Error('Receipt is missing delegationId');
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
      sub: payload.sub,
      service: payload.service,
      scopes: payload.scopes ?? [],
      userId: payload.userId ?? 'default',
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
      const userId = requestUserId(req);
      const entries = await vault.list({ userId });
      const connected = new Set(entries.map((e) => e.provider));

      const providers = config.providers.map((p) => ({
        slug: p.slug,
        connected: connected.has(p.slug),
      }));

      res.json({ providers });
    } catch (err) {
      console.error('[/providers] Error:', err);
      res.status(500).json({ error: 'Failed to list providers' });
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
      const userId = requestUserId(req);
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
          { label: 'Read content', value: 'read_content' },
          { label: 'Update content', value: 'update_content' },
          { label: 'Insert content', value: 'insert_content' },
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
            <form class="scope-form" action="/connect/${encodedSlug}?user_id=${encodedUserId}" method="GET" data-provider="${safeSlug}" data-user-id="${safeUserId}">
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
function buildScopes(e, provider) {
  e.preventDefault();
  const form = e.target;
  const checked = [...form.querySelectorAll('input[name="scope"]:checked')].map(i => i.value);
  const custom = form.querySelector('input[name="customScopes"]').value;
  if (custom) checked.push(...custom.split(',').map(s => s.trim()).filter(Boolean));
  if (checked.length === 0) {
    alert('Select at least one scope');
    return;
  }
  window.location.href = '/connect/' + provider + '?user_id=' + encodeURIComponent(currentUserId) + '&scopes=' + encodeURIComponent(checked.join(','));
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

      const userId = requestUserId(req);
      await revokeStoredProvider(slug, userId);
      res.status(204).send();
    } catch (err) {
      console.error('[/connect/:provider DELETE] Error:', err);
      res.status(500).json({ error: 'Failed to revoke provider connection' });
    }
  });

  /**
   * GET /connect/:provider — start OAuth flow
   *
   * Opens in a browser. Redirects to the provider's authorization page.
   * Scopes can be specified via ?scopes=calendar.readonly,gmail.readonly
   */
  app.get('/connect/:provider', connectRateLimiter, requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      const userId = requestUserId(req);
      const providerConfig = getProviderConfig(slug);
      if (!providerConfig) {
        res.status(404).json({ error: `Provider '${slug}' not configured. Available: ${config.providers.map((p) => p.slug).join(', ')}` });
        return;
      }

      const client = makeOAuthClient(providerConfig);

      // Parse scopes from query string, fall back to provider's default scopes from config
      const scopeValues = Array.isArray(req.query.scopes)
        ? req.query.scopes.filter((scope): scope is string => typeof scope === 'string')
        : (typeof req.query.scopes === 'string' ? [req.query.scopes] : []);
      const scopes = scopeValues.length > 0
        ? scopeValues.flatMap((value) => value.split(',').map((scope) => scope.trim()).filter(Boolean))
        : providerConfig.defaultScopes;

      const { url, state, codeVerifier } = await client.getAuthorizationUrl({ scopes });

      // Store pending session
      cleanPendingOAuth();
      pendingOAuth.set(state, {
        provider: slug,
        userId,
        scopes,
        state,
        codeVerifier,
        createdAt: Date.now(),
      });

      res.redirect(url);
    } catch (err) {
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
        const safeOauthError = escapeHtml(oauthError);
        res.status(400).send(`<h2>OAuth Error</h2><p>${safeOauthError}</p><p><a href="/providers">Back</a></p>`);
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

      await vault.store({
        provider: slug,
        userId: pending.userId,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt,
        scopes,
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
      console.error('[/callback] Error:', err);
      const safeMessage = err instanceof Error
        ? escapeHtml(err.message)
        : 'Unknown error';
      res.status(500).send(`<h2>Connection Failed</h2><p>${safeMessage}</p><p><a href="/providers">Try again</a></p>`);
    }
  });

  // ── Guard middleware (optional) ─────────────────────────────────────────

  /**
   * If a CredGuard instance is provided in config, mount its express middleware
   * on the token delegation route. Guard runs after agent auth, before token
   * retrieval. Denied requests get 403 with policy details.
   */
  const guardMiddleware = config.guard
    ? createExpressMiddleware(config.guard, {
        onDeny: (_req, res, decision) => {
          // Log guard denials for audit
          console.warn('[guard] DENIED', {
            policy: decision.deniedBy?.policy,
            reason: decision.deniedBy?.reason,
          });
          res.status(403).json({
            error: 'Request denied by guard policy',
            policy: decision.deniedBy?.policy,
            reason: decision.deniedBy?.reason,
          });
        },
      })
    : null;

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
      adapter: {
        refreshAccessToken: async (refreshToken, clientId, clientSecret) => {
          const client = new OAuthClient({
            adapter,
            clientId,
            clientSecret,
            redirectUri: `${config.redirectBaseUri}/connect/${service}/callback`,
          });
          const result = await client.refreshToken(refreshToken);
          return {
            accessToken: result.access_token,
            refreshToken: result.refresh_token,
            expiresIn: result.expires_in,
          };
        },
      },
      clientId: providerConfig.clientId,
      clientSecret: providerConfig.clientSecret,
    });

    if (!entry) {
      return {
        status: 404,
        body: {
          error: `No credentials stored for '${service}/${userId}'. Connect first: GET /connect/${service}?user_id=${encodeURIComponent(userId)}`,
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

  async function revokeStoredProvider(slug: string, userId: string): Promise<void> {
    await vault.delete({ provider: slug, userId });

    writeAuditEventIfSupported({
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(),
      actor: { type: 'agent', id: 'server-agent' },
      action: 'revoke',
      resource: { type: 'connection', id: `${slug}/${userId}` },
      outcome: 'success',
      correlationId: crypto.randomUUID(),
    });
  }

  function storeBrokeredDelegation(input: {
    delegationId: string;
    accessToken: string;
    service: string;
    userId: string;
    scopes: string[];
    expiresIn: number;
  }): void {
    const expiresAt = Date.now() + Math.max(1, input.expiresIn) * 1000;
    brokeredDelegations.set(input.delegationId, {
      accessToken: input.accessToken,
      service: input.service,
      userId: input.userId,
      scopes: input.scopes,
      expiresAt,
      createdAt: Date.now(),
    });
    const timeout = setTimeout(() => brokeredDelegations.delete(input.delegationId), Math.max(1, input.expiresIn) * 1000);
    if (timeout.unref) timeout.unref();
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
  }): Record<string, unknown> {
    if (input.tokenFormat === 'handle') {
      storeBrokeredDelegation({
        delegationId: input.delegationId,
        accessToken: input.accessToken,
        service: input.service,
        userId: input.userId,
        scopes: input.scopes,
        expiresIn: input.expiresIn,
      });
    }

    return {
      ...(input.tokenFormat === 'raw'
        ? { access_token: input.accessToken, token_type: input.tokenType ?? 'Bearer' }
        : { token_type: 'Delegation' }),
      expires_in: input.expiresIn,
      service: input.service,
      user_id: input.userId,
      scopes: input.scopes,
      delegation_id: input.delegationId,
      ...(input.receipt ? { receipt: input.receipt } : {}),
      ...(input.chainDepth !== undefined ? { chain_depth: input.chainDepth } : {}),
      ...(input.parentDelegationId ? { parent_delegation_id: input.parentDelegationId } : {}),
      ...(input.guard ? { guard: input.guard } : {}),
    };
  }

  // Stored provider consent is compared exact-match on purpose (scopeEquivalent,
  // not scopeCovers): these are provider-defined identifiers, not Cred
  // delegation scopes, and are not expected to use the ".*" wildcard form.
  // Delegation-chain narrowing is wildcard-aware separately, in
  // validateSubDelegation and the per-agent scopeCeiling checks.
  function resolveGrantedScopes(storedScopes: string[], requestedScopes?: string[]) {
    if (!requestedScopes || requestedScopes.length === 0) {
      return { grantedScopes: storedScopes, widenedScopes: [] as string[] };
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
    },
  ): Promise<{ allowed: true; effectiveScopes: string[]; decision?: GuardDecision } | { allowed: false }> {
    if (!config.guard) {
      return { allowed: true, effectiveScopes: input.delegation.scopes };
    }

    try {
      const webBotAuthIdentity = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;
      const principal = (req as any).agentPrincipal as RequestAgentPrincipal | undefined;
      const ctx: GuardContext = {
        provider: input.delegation.service,
        agentTokenHash: (req as any).agentTokenHash ?? hashAgentPrincipal(principal ?? { type: 'unknown' }),
        requestedScopes: input.delegation.scopes,
        consentedScopes: input.delegation.scopes,
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
        webBotAuthKeyId: webBotAuthIdentity?.keyId,
        signatureAgent: webBotAuthIdentity?.signatureAgent,
      };

      const decision = await config.guard.evaluate(ctx);
      (req as any).guardDecision = decision;
      (req as any).guardContext = ctx;

      if (!decision.allowed) {
        res.status(403).json({
          error: 'Request denied by guard policy',
          policy: decision.deniedBy?.policy,
          reason: decision.deniedBy?.reason,
        });
        return { allowed: false };
      }

      return {
        allowed: true,
        effectiveScopes: decision.effectiveScopes,
        decision,
      };
    } catch (err) {
      res.status(500).json({
        error: 'Guard evaluation failed',
        message: err instanceof Error ? err.message : String(err),
      });
      return { allowed: false };
    }
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
    tokenRouteHandlers.push(guardMiddleware);
  }

  const delegateRouteHandlers: Array<express.RequestHandler> = [delegateRateLimiter, requireAgentAuth, verifyWebBotAuth];
  if (guardMiddleware) {
    delegateRouteHandlers.push(assignProviderFromBody, guardMiddleware);
  }

  const subdelegateRouteHandlers: Array<express.RequestHandler> = [subdelegateRateLimiter, requireAgentAuth, verifyWebBotAuth];
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
      const userId = requestUserId(req);
      const vaultEntry = await getVaultEntry(slug, userId);
      if ('status' in vaultEntry) {
        res.status(vaultEntry.status).json(vaultEntry.body);
        return;
      }
      const { entry } = vaultEntry;

      // Return the delegated token — never the refresh token
      const guardDecision = (req as any).guardDecision;
      const requestedScopes = normalizeRequestedScopes(req.query.scopes);
      const effectiveRequestedScopes = guardDecision?.effectiveScopes ?? requestedScopes;
      const { grantedScopes, widenedScopes } = resolveGrantedScopes(entry.scopes ?? [], effectiveRequestedScopes);

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
      console.error('[/api/token/:provider] Error:', { provider: req.params.provider, err });
      res.status(500).json({ error: 'Failed to retrieve token' });
    }
  });

  app.get('/api/v1/connections', tokenRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const userId = requestUserId(req);
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
      console.error('[/api/v1/connections] Error:', err);
      res.status(500).json({ error: 'Failed to list connections' });
    }
  });

  app.post('/api/v1/use', tokenRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const {
        delegation_id: delegationId,
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

      if (!delegationId || typeof delegationId !== 'string') {
        res.status(400).json({ error: 'delegation_id is required' });
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

      const delegation = getBrokeredDelegation(delegationId);
      if (!delegation) {
        res.status(404).json({ error: 'Delegation handle not found or expired' });
        return;
      }
      const guardResult = await evaluateBrokerUseGuard(req, res, {
        delegationId,
        url,
        method: normalizedMethod,
        delegation,
      });
      if (!guardResult.allowed) return;

      if (!isAllowedBrokerUrl(delegation.service, url, guardResult.effectiveScopes)) {
        res.status(400).json({ error: `URL is not allowed for ${delegation.service} with the delegated scopes` });
        return;
      }

      const hasBody = body !== undefined;
      const sanitizedExtraHeaders = extraHeaders && typeof extraHeaders === 'object'
        ? Object.fromEntries(
            Object.entries(extraHeaders).filter(([key, value]) => {
              return isForwardableBrokerHeader(key, value);
            }),
          )
        : {};

      const upstream = await fetch(url, {
        method: normalizedMethod,
        redirect: 'manual',
        headers: {
          Authorization: `Bearer ${delegation.accessToken}`,
          Accept: 'application/json',
          'User-Agent': 'Cred-Server/1.0',
          ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
          ...sanitizedExtraHeaders,
        },
        body: hasBody ? JSON.stringify(body) : undefined,
      });

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

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: 'server-agent' },
        action: 'access',
        resource: { type: 'connection', id: `${delegation.service}/${delegation.userId}` },
        outcome: upstream.ok ? 'success' : 'error',
        scopesGranted: guardResult.effectiveScopes,
        correlationId: crypto.randomUUID(),
        metadata: {
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
      console.error('[/api/v1/use] Error:', err);
      res.status(502).json({ error: 'Brokered upstream request failed' });
    }
  });

  app.post('/api/v1/delegate', ...delegateRouteHandlers, async (req: Request, res: Response) => {
    const correlationId = crypto.randomUUID();

    try {
      const {
        service,
        user_id: requestedUserId,
        appClientId = 'local',
        scopes,
        agent_did: agentDid,
        tofu_fingerprint: tofuFingerprint,
        tofu_payload: tofuPayload,
        tofu_signature: tofuSignature,
      } = req.body as {
        service?: string;
        user_id?: string;
        appClientId?: string;
        scopes?: string[];
        agent_did?: string;
        tofu_fingerprint?: string;
        tofu_payload?: string;
        tofu_signature?: string;
      };

      if (!service || typeof service !== 'string') {
        res.status(400).json({ error: 'service is required' });
        return;
      }

      const userId = typeof requestedUserId === 'string' && requestedUserId.trim() ? requestedUserId.trim() : 'default';
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
      const guardDecision = (req as any).guardDecision as GuardDecision | undefined;
      const webBotAuthIdentity = (req as any).webBotAuthIdentity as VerifiedWebBotAuthIdentity | undefined;
      const effectiveRequestedScopes: string[] | undefined = guardDecision?.effectiveScopes ?? requestedScopes;
      const tokenFormat = tokenFormatFromBody(req);

      let principalId: string | null = null;
      let principalFingerprint: string | undefined;
      let allowedByPrincipal: string[] | undefined;
      let didAgentRecord: AgentRecord | null = null;
      if (agentDid && vault.getAgentByDid) {
        didAgentRecord = await vault.getAgentByDid(agentDid);
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
          const unauthorizedScopes = effectiveRequestedScopes.filter((scope) => !scopeCoveredBy(didAgentRecord!.scopeCeiling, scope));
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
          );
        } catch (err) {
          res.status(403).json({ error: err instanceof Error ? err.message : 'Invalid TOFU proof' });
          return;
        }

        principalId = resolved.principal.principalId;
        principalFingerprint = resolved.principal.fingerprint;
        const permission = await getPermissionIfSupported(principalId, service);
        try {
          const authorization = computeTofuAuthorization(resolved.principal, permission);
          allowedByPrincipal = authorization.allowedScopes;
        } catch (err) {
          res.status(403).json({ error: err instanceof Error ? err.message : 'TOFU authorization denied' });
          return;
        }
      }

      const { grantedScopes, widenedScopes } = resolveGrantedScopes(
        (entry.scopes ?? [])
          .filter((scope) => !principalId || !allowedByPrincipal || allowedByPrincipal.includes(scope))
          .filter((scope) => !didAgentRecord?.scopeCeiling.length || scopeCoveredBy(didAgentRecord.scopeCeiling, scope)),
        effectiveRequestedScopes,
      );

      if (widenedScopes.length > 0) {
        res.status(403).json({
          error: 'scope_escalation_denied',
          message: `Requested scopes exceed stored consent: ${widenedScopes.join(', ')}`,
        });
        return;
      }

      const delegationId = `del_${crypto.randomUUID().replace(/-/g, '')}`;
      const expiresIn = entry.expiresAt
        ? Math.max(1, Math.floor((entry.expiresAt.getTime() - Date.now()) / 1000))
        : DEFAULT_DELEGATION_TTL_SECONDS;

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
          })
        : undefined;

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
        },
      });

      res.json(buildDelegationResponse({
        tokenFormat,
        accessToken: entry.accessToken,
        expiresIn,
        service,
        userId,
        scopes: grantedScopes,
        delegationId,
        receipt,
      }));
    } catch (err) {
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

  app.post('/api/v1/web-bot-auth/keys/:agentId/rotate', tokenRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
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

  app.post('/api/v1/agents/:agentId/revoke-all', revokeRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
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

      await vault.revokeAgent(agentId);

      writeAuditEventIfSupported({
        id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
        timestamp: new Date(),
        actor: { type: 'agent', id: agent.id, fingerprint: agent.fingerprint },
        action: 'revoke',
        resource: { type: 'agent', id: agent.id },
        outcome: 'success',
        correlationId: crypto.randomUUID(),
        metadata: {
          agentDid: agent.did,
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
   * GET /api/v1/audit — query audit events when the vault backend supports audit.
   *
   * Requires Bearer auth. Events are filtered by logical `user_id` and optional
   * service when the backend supports audit queries.
   */
  app.get('/api/v1/audit', auditRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const userId = requestUserId(req);
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
          if (event.resource.type === 'agent') {
            return userId === 'default' && !service;
          }
          const [eventService, eventUserId] = event.resource.id.split('/');
          if (eventUserId !== userId) return false;
          if (service && eventService !== service) return false;
          return true;
        })
        .map((event) => {
          if (event.resource.type === 'agent') {
            return {
              id: event.id,
              action: event.action,
              service: 'agent',
              userId,
              timestamp: event.timestamp.toISOString(),
              metadata: {
                outcome: event.outcome,
                scopesRequested: event.scopesRequested,
                scopesGranted: event.scopesGranted,
                correlationId: event.correlationId,
                errorMessage: event.errorMessage,
                ...(event.metadata ? { webBotAuth: event.metadata } : {}),
              },
            };
          }
          const [eventService, eventUserId] = event.resource.id.split('/');
          return {
            id: event.id,
            action: event.action,
            service: eventService ?? '',
            userId: eventUserId ?? 'default',
            timestamp: event.timestamp.toISOString(),
            metadata: {
              outcome: event.outcome,
              scopesRequested: event.scopesRequested,
              scopesGranted: event.scopesGranted,
              correlationId: event.correlationId,
              errorMessage: event.errorMessage,
              ...(event.metadata ? { webBotAuth: event.metadata } : {}),
            },
          };
        });

      res.json({ entries });
    } catch (err) {
      console.error('[/api/v1/audit] Error:', err);
      res.status(500).json({ error: 'Failed to fetch audit log' });
    }
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
        user_id: requestedUserId,
        appClientId = 'local',
        scopes: requestedScopes,
        ancestor_receipts: ancestorReceipts,
      } = req.body as {
        parent_receipt?: string;
        agent_did?: string;
        service?: string;
        user_id?: string;
        appClientId?: string;
        scopes?: string[];
        /**
         * Optional. Every receipt above parent_receipt, root first. When
         * present the whole chain is verified offline (signatures, linkage
         * through parentReceiptHash, depth, scope subsumption, expiry
         * ordering) before the parent is used. Absent means the existing
         * parent-only behavior.
         */
        ancestor_receipts?: string[];
      };
      const userId = typeof requestedUserId === 'string' && requestedUserId.trim() ? requestedUserId.trim() : 'default';
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

      // ── Context matching (service, user, app) ────────────────────────────

      if (parent.service !== service) {
        res.status(403).json({ error: 'Service does not match parent receipt' });
        return;
      }
      if (parent.userId !== userId) {
        res.status(403).json({ error: 'User does not match parent receipt' });
        return;
      }
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
          const chain = verifyReceiptChain([...ancestorReceipts, parentReceipt], getReceiptPublicKey(), {
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

      // ── Ancestor status check (if vault supports agents) ─────────────────
      // A revoked/suspended ancestor anywhere in the chain — not just the
      // immediate parent — must not be able to anchor a fresh sub-delegation
      // to a still-active descendant DID. There's no persisted table of
      // delegations keyed by delegationId to walk here, so this walks the
      // chain embedded in the signed receipt itself: every receipt carries a
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

      const agentId = agentRecord?.id ?? agentDid;
      const permission = await vault.getPermission?.(agentId, service) ?? null;
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

      // ── Validate delegation chain ────────────────────────────────────────

      let validation;
      try {
        validation = validateSubDelegation({
          parent: {
            delegationId: parent.delegationId,
            agentDid: parent.sub,
            service: parent.service,
            userId: parent.userId,
            appClientId: parent.appClientId,
            scopesGranted: parent.scopes,
            chainDepth: parent.chainDepth,
          },
          childAgentDid: agentDid,
          service,
          userId,
          appClientId,
          requestedScopes,
          permission: {
            allowedScopes: permission.allowedScopes,
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

      // ── Enforce the child agent's scope ceiling ──────────────────────────
      // Mirror the direct-delegation path (a non-empty scopeCeiling is a hard
      // per-agent cap; empty means unbounded). Without this, sub-delegation
      // could grant an agent scopes above the ceiling that the same agent is
      // capped to on direct delegation.
      if (agentRecord?.scopeCeiling.length) {
        const withinCeiling = validation.grantedScopes.filter((scope) =>
          scopeCoveredBy(agentRecord!.scopeCeiling, scope),
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

      // ── Retrieve token from vault ────────────────────────────────────────

      const providerConfig = getProviderConfig(service);
      const getOpts: Parameters<typeof vault.get>[0] = {
        provider: service,
        userId,
      };
      if (providerConfig) {
        const adapter = createAdapter(providerConfig.slug as BuiltinAdapterSlug);
        getOpts.adapter = {
          refreshAccessToken: async (refreshToken, clientId, clientSecret) => {
            const client = new OAuthClient({
              adapter,
              clientId,
              clientSecret,
              redirectUri: `${config.redirectBaseUri}/connect/${service}/callback`,
            });
            const result = await client.refreshToken(refreshToken);
            return {
              accessToken: result.access_token,
              refreshToken: result.refresh_token,
              expiresIn: result.expires_in,
            };
          },
        };
        getOpts.clientId = providerConfig.clientId;
        getOpts.clientSecret = providerConfig.clientSecret;
      }

      const entry = await vault.get(getOpts);
      if (!entry) {
        res.status(404).json({
          error: `No credentials stored for '${service}'. Connect first: GET /connect/${service}`,
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

      // ── Issue child receipt ──────────────────────────────────────────────

      const delegationId = `del_${crypto.randomUUID().replace(/-/g, '')}`;
      const parentReceiptHash = crypto.createHash('sha256').update(parentReceipt).digest('hex');

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
      });

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
        ...(webBotAuthIdentity && {
          metadata: {
            identitySource: 'web-bot-auth',
            webBotAuthKeyId: webBotAuthIdentity.keyId,
            signatureAgent: webBotAuthIdentity.signatureAgent,
            receiptClaims: parent.receiptClaims,
          },
        }),
      });

      // ── Response ─────────────────────────────────────────────────────────

      const expiresIn = entry.expiresAt
        ? Math.max(1, Math.floor((entry.expiresAt.getTime() - Date.now()) / 1000))
        : DEFAULT_DELEGATION_TTL_SECONDS;

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
        }),
        // Always present: sub-delegation is broker-only at every depth, so
        // this both confirms the format and flags any downgrade from a
        // caller-requested 'raw' token_format.
        token_format_enforced: 'brokered',
        ...(requestedTokenFormat !== 'handle' ? { requested_token_format: requestedTokenFormat } : {}),
      });
    } catch (err) {
      console.error('[POST /api/v1/subdelegate] Error:', err);
      res.status(500).json({ error: 'Sub-delegation failed' });
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
      await revokeStoredProvider(slug, requestUserId(req));

      res.status(204).send();
    } catch (err) {
      console.error('[DELETE /api/token/:provider] Error:', { provider: req.params.provider, err });
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  app.delete('/api/v1/connections/:provider', revokeRateLimiter, requireAgentAuth, verifyWebBotAuth, async (req: Request, res: Response) => {
    try {
      const userId = requestUserId(req);
      const slug = routeParam(req.params.provider);
      if (!slug) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }
      await revokeStoredProvider(slug, userId);
      res.status(204).send();
    } catch (err) {
      console.error('[DELETE /api/v1/connections/:provider] Error:', { provider: req.params.provider, err });
      res.status(500).json({ error: 'Failed to revoke connection' });
    }
  });

  return { app, vault, tofu };
}
