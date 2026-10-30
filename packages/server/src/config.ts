/**
 * @credninja/server — Configuration
 *
 * Loads server configuration from environment variables.
 * Call loadConfig() after dotenv (or process.env is populated).
 */

import path from 'path';
import type { BuiltinAdapterSlug } from '@credninja/oauth';
import type { CredGuard } from '@credninja/guard';
import type { Request } from 'express';
import type { JwsSigner, JwsVerificationKey } from '@credninja/attenuation';

export interface ProviderConfig {
  slug: BuiltinAdapterSlug;
  clientId: string;
  clientSecret: string;
  defaultScopes: string[];
}

export interface RequestAgentPrincipal {
  type: string;
  principalId?: string;
  /**
   * The user this principal acts for, when the verifier knows it. Only a
   * custom agentRequestVerifier can set it (the static bearer principal
   * never has one). On legacy routes a request without user_id then acts on
   * this user, and a request naming a different user_id is refused with
   * 403 user_id_mismatch.
   */
  userId?: string;
  metadata?: Record<string, unknown>;
}

export type AgentRequestAuthResult =
  | { ok: true; principal?: RequestAgentPrincipal }
  | { ok: false; status?: number; error?: string };

export type AgentRequestVerifier =
  (req: Request) => AgentRequestAuthResult | Promise<AgentRequestAuthResult>;

export interface ServerConfig {
  port: number;
  host: string;

  // Vault
  vaultPassphrase: string;
  vaultStorage: 'sqlite' | 'file';
  vaultPath: string;

  // TOFU identity storage
  tofuStorage: 'sqlite' | 'file';
  tofuPath: string;

  // Agent auth
  adminToken: string;
  agentToken?: string;
  agentRequestVerifier?: AgentRequestVerifier;

  // OAuth providers (only those with both clientId and clientSecret)
  providers: ProviderConfig[];

  // Redirect base URI (e.g. http://localhost:3456 or https://cred.example.com)
  redirectBaseUri: string;

  // Single-user mode (env SINGLE_USER_MODE). When true, a legacy request
  // that names no user_id acts on the shared user 'default'. When false (the
  // default), such a request is refused with 400 user_id_required. Naming a
  // user_id explicitly, including 'default', works in both modes.
  singleUserMode?: boolean;

  // Delegation receipt TTL, in seconds. Controls the `exp` claim minted onto
  // new receipts, and the age at which legacy receipts (no `exp` claim) are
  // treated as expired. Defaults to 3600 (1 hour) when unset.
  receiptTtlSeconds?: number;

  // Delegation receipt audience (`aud` claim). Defaults to redirectBaseUri
  // when unset.
  receiptAudience?: string;

  // Receipt signing. Default: an Ed25519 (EdDSA) key derived from the vault
  // passphrase, as before. `receiptSigner` takes any signer (an HSM or KMS
  // adapter, for instance); `receiptSigningKeyPem` (env
  // RECEIPT_SIGNING_KEY_PEM) takes a PKCS#8 Ed25519 or P-256 private key,
  // giving EdDSA or ES256. The header always carries `kid`.
  receiptSigner?: JwsSigner;
  receiptSigningKeyPem?: string;
  // Further keys receipts may verify under (for example the key a rotation
  // replaced), matched by `kid`. With a custom `receiptSigner`, its own
  // public key MUST be listed here under the signer's `kid`; createServer
  // throws otherwise.
  receiptVerificationKeys?: JwsVerificationKey[];
  // The verifier's accepted algorithms (env RECEIPT_ACCEPTED_ALGS, comma
  // separated). Defaults to EdDSA and ES256. A receipt whose header alg is
  // not on the list, or differs from its key's algorithm, is rejected.
  receiptAcceptedAlgs?: string[];
  // Claim layout of newly minted receipts (env RECEIPT_CLAIM_LAYOUT).
  // 'draft-02' (the default): the principal in `sub`, the agent in
  // `client_id` and `act.sub`, prior agents in nested `act`, plus `jti` and
  // `cnf`. 'legacy': the agent in `sub`, for verifiers that key on it.
  // Receipts in either layout are always accepted.
  receiptClaimLayout?: 'draft-02' | 'legacy';

  // SQLite file for the running totals of cumulative constraints (env
  // CUMULATIVE_LEDGER_PATH). Unset keeps them in memory for the life of the
  // process; a delegation whose ancestors the ledger does not hold is
  // refused at exercise, so a restart fails closed rather than resetting a
  // budget.
  cumulativeLedgerPath?: string;

  // Ignored and deprecated (env CRED_REQUIRE_AGENT_IDENTITY): the caller of
  // /api/v1/subdelegate must always prove it is the agent the parent receipt
  // names, with an RFC 7523 actor_token signed by that agent's did:key.
  requireAgentIdentity?: boolean;

  // Consent records (draft Section 8.2) are kept for this many days after
  // the later of their grant and expiry, then purged (env
  // CONSENT_RETENTION_DAYS). At least 90, the draft's minimum; default 90.
  consentRetentionDays?: number;

  // CIBA approvals (draft Section 8.1). The subject is asked through the
  // built-in signed-link approval page, announced by a POST to this webhook
  // (env CRED_APPROVAL_WEBHOOK_URL), or through an external OpenID
  // Provider's CIBA endpoints when cibaProvider is set (env
  // CRED_CIBA_BACKCHANNEL_ENDPOINT, CRED_CIBA_TOKEN_ENDPOINT,
  // CRED_CIBA_CLIENT_ID, CRED_CIBA_CLIENT_SECRET).
  approvalWebhookUrl?: string;
  cibaProvider?: {
    backchannelAuthenticationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
    clientSecret: string;
  };
  // How long an approved consent is reused for later requests it covers
  // before the subject is asked again (env CRED_CIBA_CONSENT_TTL_SECONDS).
  // Default one day.
  cibaConsentTtlSeconds?: number;

  // Cred Link only (env CRED_REQUIRE_DPOP), until Link agents get keys:
  // default true, no Link handle for the key-less static Bearer identity.
  // Agent delegations are always Delegation Tokens bound to the agent's
  // key, whatever this says. false is deprecated and logs a warning.
  requireDpop?: boolean;

  // Hand a provider's access token to the caller (token_format "raw" on
  // /api/v1/delegate, and GET /api/token/:provider) (env
  // CRED_ALLOW_RAW_TOKENS). Default false: a provider token is a bearer
  // credential with the connection's full scope that cannot be bound to an
  // agent key, narrowed, or revoked per delegation, so the server only
  // brokers calls. true is deprecated and logs a warning at startup.
  allowRawTokens?: boolean;

  // Lifetime of a Sub-Delegation Exchange grant, in seconds. Default 60.
  delegationGrantTtlSeconds?: number;

  // Guard — optional policy engine for credential delegation guardrails
  // When provided, evaluates policies before serving delegated tokens.
  guard?: CredGuard;

  // Web Bot Auth ingress verification mode
  webBotAuthMode?: 'off' | 'optional' | 'require';
  webBotAuthNonceStore?: 'memory' | 'sqlite';
  webBotAuthNoncePath?: string;
  webBotAuthAllowedOrigins?: string[];

  // Cred Link (Phase 1, self-hosted). Off unless linkEnabled is true.
  // Requires vaultStorage 'sqlite' (Link permissions live in the vault).
  linkEnabled?: boolean;
  // Link SQLite file. Defaults to link.sqlite next to the vault file.
  linkStorePath?: string;
  // Public base URL of the Link pages and the provider callback
  // (<base>/link/v1/callback/<provider>). Defaults to redirectBaseUri.
  linkBaseUrl?: string;
  // Lifetime of Link brokered handles in seconds. Default 300, capped at 900.
  linkHandleTtlSeconds?: number;
}

/** The Link store path the server uses for a config (explicit, else next to the vault). */
export function resolveLinkStorePath(config: Pick<ServerConfig, 'linkStorePath' | 'vaultPath'>): string {
  if (config.linkStorePath) return config.linkStorePath;
  return path.join(path.dirname(config.vaultPath), 'link.sqlite');
}

/** Fail fast on a Link configuration the server cannot run (decision 1). */
export function assertLinkConfig(config: ServerConfig): void {
  if (!config.linkEnabled) return;
  if (config.vaultStorage !== 'sqlite') {
    throw new Error('LINK_ENABLED requires VAULT_STORAGE=sqlite: Link stores agent permissions in the vault, and the file backend has no permission storage.');
  }
  const base = config.linkBaseUrl ?? config.redirectBaseUri;
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    throw new Error('LINK_BASE_URL must be an absolute http(s) URL');
  }
  // An origin only: the hosted pages and the provider callback live at
  // fixed paths (/link/v1/...), and CSP form-action and cookie scoping
  // assume the service owns the whole origin.
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.search || url.hash || url.username || url.password
    || (url.pathname !== '/' && url.pathname !== '') || /[?#]/.test(base)) {
    throw new Error('LINK_BASE_URL (or REDIRECT_BASE_URI when Link uses it) must be an http(s) origin without path, query, fragment or credentials');
  }
  if (config.linkHandleTtlSeconds !== undefined
    && (!Number.isInteger(config.linkHandleTtlSeconds) || config.linkHandleTtlSeconds <= 0)) {
    throw new Error('LINK_HANDLE_TTL_SECONDS must be a positive integer');
  }
}

const KNOWN_PROVIDERS: { env: string; slug: BuiltinAdapterSlug }[] = [
  { env: 'GOOGLE', slug: 'google' },
  { env: 'GITHUB', slug: 'github' },
  { env: 'SLACK', slug: 'slack' },
  { env: 'NOTION', slug: 'notion' },
  { env: 'SALESFORCE', slug: 'salesforce' },
  { env: 'LINEAR', slug: 'linear' },
  { env: 'HUBSPOT', slug: 'hubspot' },
];

export function loadConfig(): ServerConfig {
  const port = parseInt(process.env.PORT ?? '3456', 10);
  const host = process.env.HOST ?? '127.0.0.1';

  const vaultPassphrase = process.env.VAULT_PASSPHRASE;
  if (!vaultPassphrase) {
    throw new Error('VAULT_PASSPHRASE is required. Generate one: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }

  const vaultStorage = (process.env.VAULT_STORAGE ?? 'sqlite') as 'sqlite' | 'file';
  const vaultPath = process.env.VAULT_PATH ?? (vaultStorage === 'sqlite' ? './data/vault.sqlite' : './data/vault.json');
  const tofuStorage = (process.env.TOFU_STORAGE ?? vaultStorage) as 'sqlite' | 'file';
  const tofuPath = process.env.TOFU_PATH ?? (tofuStorage === 'sqlite' ? './data/tofu.sqlite' : './data/tofu.json');

  const agentToken = process.env.AGENT_TOKEN;
  if (!agentToken) {
    throw new Error(
      'AGENT_TOKEN is required. Generate one: node -e "console.log(\'cred_at_\' + require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  if (!agentToken.startsWith('cred_at_')) {
    throw new Error('AGENT_TOKEN must start with cred_at_');
  }

  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    throw new Error(
      'ADMIN_TOKEN is required. Generate one: node -e "console.log(\'cred_admin_\' + require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  if (!adminToken.startsWith('cred_admin_')) {
    throw new Error('ADMIN_TOKEN must start with cred_admin_');
  }

  const redirectBaseUri = process.env.REDIRECT_BASE_URI ?? `http://localhost:${port}`;
  const webBotAuthMode = (process.env.WEB_BOT_AUTH_MODE ?? 'off') as 'off' | 'optional' | 'require';
  if (!['off', 'optional', 'require'].includes(webBotAuthMode)) {
    throw new Error('WEB_BOT_AUTH_MODE must be one of: off, optional, require');
  }
  const webBotAuthNonceStore = (process.env.WEB_BOT_AUTH_NONCE_STORE ?? 'memory') as 'memory' | 'sqlite';
  if (!['memory', 'sqlite'].includes(webBotAuthNonceStore)) {
    throw new Error('WEB_BOT_AUTH_NONCE_STORE must be one of: memory, sqlite');
  }
  const webBotAuthNoncePath = process.env.WEB_BOT_AUTH_NONCE_PATH
    ?? (webBotAuthNonceStore === 'sqlite' ? './data/web-bot-auth-nonces.sqlite' : undefined);
  const webBotAuthAllowedOrigins = (process.env.WEB_BOT_AUTH_ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  const receiptTtlSecondsRaw = process.env.RECEIPT_TTL_SECONDS;
  let receiptTtlSeconds: number | undefined;
  if (receiptTtlSecondsRaw !== undefined) {
    receiptTtlSeconds = parseInt(receiptTtlSecondsRaw, 10);
    if (!Number.isFinite(receiptTtlSeconds) || receiptTtlSeconds <= 0 || receiptTtlSeconds > 3600) {
      throw new Error('RECEIPT_TTL_SECONDS must be a positive integer of at most 3600 (1 hour)');
    }
  }
  const receiptAudience = process.env.RECEIPT_AUDIENCE || undefined;
  const receiptSigningKeyPem = process.env.RECEIPT_SIGNING_KEY_PEM || undefined;
  const receiptAcceptedAlgs = process.env.RECEIPT_ACCEPTED_ALGS
    ? process.env.RECEIPT_ACCEPTED_ALGS.split(',').map((a) => a.trim()).filter(Boolean)
    : undefined;
  const receiptClaimLayoutRaw = process.env.RECEIPT_CLAIM_LAYOUT || undefined;
  if (receiptClaimLayoutRaw !== undefined && receiptClaimLayoutRaw !== 'draft-02' && receiptClaimLayoutRaw !== 'legacy') {
    throw new Error('RECEIPT_CLAIM_LAYOUT must be one of: draft-02, legacy');
  }
  const cumulativeLedgerPath = process.env.CUMULATIVE_LEDGER_PATH || undefined;
  const requireAgentIdentityRaw = (process.env.CRED_REQUIRE_AGENT_IDENTITY ?? '').trim().toLowerCase();
  let requireAgentIdentity: boolean | undefined;
  if (requireAgentIdentityRaw === 'true' || requireAgentIdentityRaw === '1') requireAgentIdentity = true;
  else if (requireAgentIdentityRaw === 'false' || requireAgentIdentityRaw === '0') requireAgentIdentity = false;
  else if (requireAgentIdentityRaw !== '') throw new Error('CRED_REQUIRE_AGENT_IDENTITY must be true or false');
  const allowRawTokensRaw = (process.env.CRED_ALLOW_RAW_TOKENS ?? '').trim().toLowerCase();
  let allowRawTokens: boolean | undefined;
  if (allowRawTokensRaw === 'true' || allowRawTokensRaw === '1') allowRawTokens = true;
  else if (allowRawTokensRaw === 'false' || allowRawTokensRaw === '0') allowRawTokens = false;
  else if (allowRawTokensRaw !== '') throw new Error('CRED_ALLOW_RAW_TOKENS must be true or false');
  const retentionRaw = (process.env.CONSENT_RETENTION_DAYS ?? '').trim();
  const consentRetentionDays = retentionRaw === '' ? undefined : Number(retentionRaw);
  const cibaTtlRaw = (process.env.CRED_CIBA_CONSENT_TTL_SECONDS ?? '').trim();
  const cibaConsentTtlSeconds = cibaTtlRaw === '' ? undefined : Number(cibaTtlRaw);
  const cibaEnv = {
    backchannelAuthenticationEndpoint: process.env.CRED_CIBA_BACKCHANNEL_ENDPOINT?.trim() ?? '',
    tokenEndpoint: process.env.CRED_CIBA_TOKEN_ENDPOINT?.trim() ?? '',
    clientId: process.env.CRED_CIBA_CLIENT_ID?.trim() ?? '',
    clientSecret: process.env.CRED_CIBA_CLIENT_SECRET ?? '',
  };
  const cibaSet = Object.values(cibaEnv).filter((v) => v !== '').length;
  if (cibaSet > 0 && cibaSet < 4) {
    throw new Error('CRED_CIBA_BACKCHANNEL_ENDPOINT, CRED_CIBA_TOKEN_ENDPOINT, CRED_CIBA_CLIENT_ID and CRED_CIBA_CLIENT_SECRET must be set together');
  }
  const requireDpopRaw = (process.env.CRED_REQUIRE_DPOP ?? '').trim().toLowerCase();
  let requireDpop: boolean | undefined;
  if (requireDpopRaw === 'true' || requireDpopRaw === '1') requireDpop = true;
  else if (requireDpopRaw === 'false' || requireDpopRaw === '0') requireDpop = false;
  else if (requireDpopRaw !== '') throw new Error('CRED_REQUIRE_DPOP must be true or false');

  // Discover configured providers from environment
  const providers: ProviderConfig[] = [];
  for (const { env, slug } of KNOWN_PROVIDERS) {
    const clientId = process.env[`${env}_CLIENT_ID`];
    const clientSecret = process.env[`${env}_CLIENT_SECRET`];
    if (clientId && clientSecret) {
      const defaultScopesRaw = process.env[`${env}_DEFAULT_SCOPES`] ?? '';
      const defaultScopes = defaultScopesRaw
        ? defaultScopesRaw.split(',').map((s) => s.trim()).filter(Boolean)
        : [];
      providers.push({ slug, clientId, clientSecret, defaultScopes });
    }
  }

  const singleUserRaw = (process.env.SINGLE_USER_MODE ?? '').trim().toLowerCase();
  let singleUserMode: boolean;
  if (singleUserRaw === '' || singleUserRaw === 'false' || singleUserRaw === '0') {
    singleUserMode = false;
  } else if (singleUserRaw === 'true' || singleUserRaw === '1') {
    singleUserMode = true;
  } else {
    throw new Error('SINGLE_USER_MODE must be true or false');
  }

  const linkEnabledRaw = (process.env.LINK_ENABLED ?? '').trim().toLowerCase();
  const linkEnabled = linkEnabledRaw === 'true' || linkEnabledRaw === '1';
  const linkStorePath = process.env.LINK_STORE_PATH || undefined;
  const linkBaseUrl = process.env.LINK_BASE_URL || undefined;
  const linkHandleTtlRaw = process.env.LINK_HANDLE_TTL_SECONDS;
  const linkHandleTtlSeconds = linkHandleTtlRaw !== undefined ? parseInt(linkHandleTtlRaw, 10) : undefined;

  return {
    port,
    host,
    vaultPassphrase,
    vaultStorage,
    vaultPath,
    tofuStorage,
    tofuPath,
    adminToken,
    agentToken,
    providers,
    redirectBaseUri,
    singleUserMode,
    receiptTtlSeconds,
    receiptAudience,
    ...(receiptSigningKeyPem ? { receiptSigningKeyPem } : {}),
    ...(receiptAcceptedAlgs ? { receiptAcceptedAlgs } : {}),
    ...(receiptClaimLayoutRaw ? { receiptClaimLayout: receiptClaimLayoutRaw as 'draft-02' | 'legacy' } : {}),
    ...(cumulativeLedgerPath ? { cumulativeLedgerPath } : {}),
    ...(requireAgentIdentity !== undefined ? { requireAgentIdentity } : {}),
    ...(requireDpop !== undefined ? { requireDpop } : {}),
    ...(consentRetentionDays !== undefined ? { consentRetentionDays } : {}),
    ...(cibaConsentTtlSeconds !== undefined ? { cibaConsentTtlSeconds } : {}),
    ...(process.env.CRED_APPROVAL_WEBHOOK_URL?.trim() ? { approvalWebhookUrl: process.env.CRED_APPROVAL_WEBHOOK_URL.trim() } : {}),
    ...(cibaSet === 4 ? { cibaProvider: cibaEnv } : {}),
    ...(allowRawTokens !== undefined ? { allowRawTokens } : {}),
    webBotAuthMode,
    webBotAuthNonceStore,
    webBotAuthNoncePath,
    webBotAuthAllowedOrigins,
    linkEnabled,
    ...(linkStorePath ? { linkStorePath } : {}),
    ...(linkBaseUrl ? { linkBaseUrl } : {}),
    ...(linkHandleTtlSeconds !== undefined ? { linkHandleTtlSeconds } : {}),
  };
}
