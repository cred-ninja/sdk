/**
 * Cred Link, Phase 1: shared contracts (Workstream 0).
 *
 * Source of truth: CRED-LINK-SPEC.md. Section references below ("spec 2")
 * point into that document.
 *
 * Workstreams referenced in the comments:
 *   - the server: packages/server (Link routes, hosted pages, SQLite LinkStore
 *     and LinkSecretStore, client auth, provider hop).
 *   - the guard hooks: packages/guard and packages/vault (LinkHooks implementation,
 *     clientGrantPolicy, Permission storage additions).
 *   - the widget: packages/link and packages/link-react.
 *
 * Rules for this file: types, constants and pure helpers only. No I/O, no
 * imports from other packages, no `node:` imports, no Buffer, no DOM types.
 * It must run unchanged in browsers and in Node.
 *
 * Naming convention:
 *   - Wire shapes (HTTP bodies, query strings, form fields, postMessage
 *     payloads) are snake_case, as the spec shows them.
 *   - Record types (LinkClient, Connection, ClientGrant, LinkTransaction) are
 *     also snake_case, matching the spec's own TypeScript and the column
 *     names a SQL store will use. Timestamps on records are ISO-8601 UTC
 *     strings.
 *   - Exceptions, both mirroring existing camelCase TypeScript: LinkTheme
 *     (the widget prop shape in spec 1) and LinkPermission / PermissionPort
 *     (structural mirrors of @credninja/vault's Permission and
 *     PermissionStore, which use camelCase and Date).
 *   - Scope arrays stored on Link records are always in canonical form
 *     (see canonicalScopeSet): canonical names, deduplicated, sorted.
 */

// ════════════════════════════════════════════════════════════════════════════
// Internal helpers (not exported)
// ════════════════════════════════════════════════════════════════════════════

function includesValue<T extends string>(list: readonly T[], value: unknown): value is T {
  return typeof value === 'string' && (list as readonly string[]).includes(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** True when the string contains a C0/C1 control character or a Unicode line/paragraph separator. */
function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) return true;
    // Invisible and bidirectional formatting characters: they let a display
    // name read differently from its code points (for example U+202E).
    if (c === 0x061c || (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e)
      || (c >= 0x2060 && c <= 0x2069) || c === 0xfeff) return true;
  }
  return false;
}

/**
 * Characters that must not appear in a name shown to the user as the
 * identity of an app: control, format (soft hyphen, zero width, bidi, tag
 * characters), private use, unassigned and lone surrogate code points, line
 * and paragraph separators, variation selectors, and the invisible fillers
 * that are classed as letters or marks. Matched per code point.
 */
const INVISIBLE_IN_DISPLAY_NAME =
  /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Cn}\p{Zl}\p{Zp}\p{Variation_Selector}\u034f\u115f\u1160\u3164\uffa0]/u;

function isSafeDisplayName(value: string): boolean {
  return !hasControlCharacter(value) && !INVISIBLE_IN_DISPLAY_NAME.test(value);
}

// ════════════════════════════════════════════════════════════════════════════
// 1. Identifiers and enums
// ════════════════════════════════════════════════════════════════════════════

/**
 * The seven Link providers (spec 3). A subset of @credninja/oauth's
 * BuiltinAdapterSlug; 'salesforce-sandbox' is deliberately not a Link
 * provider in Phase 1.
 * Produced by: the protocol package. Consumed by: all packages.
 */
export const LINK_PROVIDERS = [
  'google',
  'github',
  'slack',
  'notion',
  'salesforce',
  'linear',
  'hubspot',
] as const;

/** A Link provider slug (spec 1 calls this ProviderSlug). All packages. */
export type LinkProviderSlug = (typeof LINK_PROVIDERS)[number];

/** Type guard for LinkProviderSlug. All packages. */
export function isLinkProviderSlug(value: unknown): value is LinkProviderSlug {
  return includesValue(LINK_PROVIDERS, value);
}

/**
 * Id prefixes (spec 3 and 4 name conn_, grt_, org_; the rest are the protocol package
 * choices; perm_ and evt_ are the existing vault prefixes). Ids are
 * prefix + LINK_ID_BODY_PATTERN. Generators live in the server (they need
 * randomness); recommended body: crypto.randomUUID() without dashes, which
 * is the repo's existing convention.
 */
export const LINK_ID_PREFIXES = {
  connection: 'conn_',
  grant: 'grt_',
  org: 'org_',
  transaction: 'ltx_',
  request: 'req_',
  permission: 'perm_',
  auditEvent: 'evt_',
} as const;

/** Body of a prefixed id: 1 to 64 ASCII alphanumerics. The protocol package choice. */
export const LINK_ID_BODY_PATTERN = /^[A-Za-z0-9]{1,64}$/;

/** Connection id (spec 4). */
export type ConnectionId = `conn_${string}`;
/** Client-grant id (spec 3). */
export type GrantId = `grt_${string}`;
/** Organization id (spec 3, 4). */
export type OrgId = `org_${string}`;
/** Link transaction id, `tid` in the envelope (spec 2). */
export type TransactionId = `ltx_${string}`;

function hasIdShape(value: unknown, prefix: string): boolean {
  return typeof value === 'string'
    && value.startsWith(prefix)
    && LINK_ID_BODY_PATTERN.test(value.slice(prefix.length));
}

/** Type guard for ConnectionId. All packages. */
export function isConnectionId(value: unknown): value is ConnectionId {
  return hasIdShape(value, LINK_ID_PREFIXES.connection);
}
/** Type guard for GrantId. All packages. */
export function isGrantId(value: unknown): value is GrantId {
  return hasIdShape(value, LINK_ID_PREFIXES.grant);
}
/** Type guard for OrgId. All packages. */
export function isOrgId(value: unknown): value is OrgId {
  return hasIdShape(value, LINK_ID_PREFIXES.org);
}
/** Type guard for TransactionId. Used by the server. */
export function isTransactionId(value: unknown): value is TransactionId {
  return hasIdShape(value, LINK_ID_PREFIXES.transaction);
}

/**
 * The single implicit org of Phase 1 (spec 4 multi-tenancy is out of scope,
 * but every record still carries org_id). The server writes it.
 */
export const LINK_DEFAULT_ORG_ID: OrgId = 'org_default';

/**
 * Developer app client_id grammar. The protocol package choice: no required prefix, because
 * spec 8 backfills legacy rows with client_id 'local'.
 */
export const LINK_CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Type guard for a syntactically valid client_id. Used by the server, the guard hooks. */
export function isLinkClientId(value: unknown): value is string {
  return typeof value === 'string' && LINK_CLIENT_ID_PATTERN.test(value);
}

/**
 * Format of every 256-bit Link secret (envelope handle, binding cookie
 * value, the random part of request_uri and of the activation code):
 * 32 random bytes, base64url, no padding = 43 characters (spec 5).
 */
export const LINK_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** Prefix of the PAR request_uri, the widget's `token` (spec 1, 2). */
export const LINK_REQUEST_URI_PREFIX = 'urn:cred:link:';

/** Prefix of the one-time activation code (spec 2). The protocol package choice, aids secret scanning. */
export const LINK_ACTIVATION_CODE_PREFIX = 'cred_lac_';

/** Type guard: envelope handle `h` (spec 2). Used by the server. */
export function isLinkHandle(value: unknown): value is string {
  return typeof value === 'string' && LINK_SECRET_PATTERN.test(value);
}

/** Type guard: transaction-binding cookie value (spec 2). Used by the server. */
export function isLinkBindingCookieValue(value: unknown): value is string {
  return isLinkHandle(value);
}

/** Type guard: request_uri / widget token (spec 1, 2). Used by the server, the widget. */
export function isLinkRequestUri(value: unknown): value is string {
  return typeof value === 'string'
    && value.startsWith(LINK_REQUEST_URI_PREFIX)
    && LINK_SECRET_PATTERN.test(value.slice(LINK_REQUEST_URI_PREFIX.length));
}

/** Type guard: activation code (spec 2). Used by the server. */
export function isLinkActivationCode(value: unknown): value is string {
  return typeof value === 'string'
    && value.startsWith(LINK_ACTIVATION_CODE_PREFIX)
    && LINK_SECRET_PATTERN.test(value.slice(LINK_ACTIVATION_CODE_PREFIX.length));
}

/**
 * How secrets are stored at rest (spec 5: "hashed at rest"). Every
 * `*_hash` field on Link records is lowercase hex SHA-256 of the full
 * secret string as transmitted (UTF-8), including any prefix. The server
 * computes hashes (needs crypto); the store only compares them.
 */
export const LINK_SECRET_HASH_ALGORITHM = 'sha256-hex' as const;

/** PAR intent (spec 2). */
export const LINK_INTENTS = ['connect', 'update', 'reauth'] as const;
/** PAR intent (spec 2). All packages. */
export type LinkIntent = (typeof LINK_INTENTS)[number];
/** Type guard for LinkIntent. */
export function isLinkIntent(value: unknown): value is LinkIntent {
  return includesValue(LINK_INTENTS, value);
}

/** subject_type (spec 2, 3). 'client' = workspace or bot install. */
export const LINK_SUBJECT_TYPES = ['user', 'client'] as const;
/** subject_type (spec 2, 3). All packages. */
export type LinkSubjectType = (typeof LINK_SUBJECT_TYPES)[number];
/** Type guard for LinkSubjectType. */
export function isLinkSubjectType(value: unknown): value is LinkSubjectType {
  return includesValue(LINK_SUBJECT_TYPES, value);
}

/** Widget mode (spec 1). */
export const LINK_WIDGET_MODES = ['popup', 'redirect', 'embedded'] as const;
/** Widget mode (spec 1). The widget sets it, the server reads it from authorize. */
export type LinkWidgetMode = (typeof LINK_WIDGET_MODES)[number];
/** Default widget mode (spec 1). */
export const LINK_DEFAULT_WIDGET_MODE: LinkWidgetMode = 'popup';
/** Type guard for LinkWidgetMode. */
export function isLinkWidgetMode(value: unknown): value is LinkWidgetMode {
  return includesValue(LINK_WIDGET_MODES, value);
}

/** Transaction step (spec 2 LinkTransaction.step). */
export const LINK_STEPS = ['picker', 'provider', 'confirm', 'done'] as const;
/** Transaction step (spec 2). Used by the server. */
export type LinkStep = (typeof LINK_STEPS)[number];
/** Steps a user can exit from (spec 1 onExit). Used by the server, the widget. */
export type LinkExitStep = Exclude<LinkStep, 'done'>;
/** The exit steps as a list. */
export const LINK_EXIT_STEPS = ['picker', 'provider', 'confirm'] as const satisfies readonly LinkExitStep[];

/**
 * Allowed step transitions. The server's store enforces these in
 * LinkStore.advanceTransaction (compare-and-set on `from`).
 *   picker   -> provider   picker submitted
 *   provider -> confirm    provider callback exchanged the code
 *   confirm  -> provider   user went back: new PKCE pair, earlier staged tokens revoked (spec 2)
 *   confirm  -> done       only via LinkStore.commitConfirm
 */
export const LINK_STEP_TRANSITIONS: Readonly<Record<LinkStep, readonly LinkStep[]>> = {
  picker: ['provider'],
  provider: ['confirm'],
  confirm: ['provider', 'done'],
  done: [],
};

/** Whether `from -> to` is an allowed step transition. Used by the server. */
export function isLinkStepTransitionAllowed(from: LinkStep, to: LinkStep): boolean {
  return LINK_STEP_TRANSITIONS[from].includes(to);
}

/**
 * Connection status. The spec does not enumerate these; the protocol package choice:
 * grant statuses minus 'expired', plus 'frozen' for grant_reuse_detected
 * (spec 7: "connection frozen").
 */
export const LINK_CONNECTION_STATUSES = ['pending', 'active', 'needs_reauth', 'frozen', 'revoked'] as const;
/** Connection status. All packages. */
export type LinkConnectionStatus = (typeof LINK_CONNECTION_STATUSES)[number];
/** Type guard for LinkConnectionStatus. */
export function isLinkConnectionStatus(value: unknown): value is LinkConnectionStatus {
  return includesValue(LINK_CONNECTION_STATUSES, value);
}

/** Client-grant status (spec 3). */
export const LINK_GRANT_STATUSES = ['pending', 'active', 'needs_reauth', 'revoked', 'expired'] as const;
/** Client-grant status (spec 3). All packages. */
export type LinkGrantStatus = (typeof LINK_GRANT_STATUSES)[number];
/** Type guard for LinkGrantStatus. */
export function isLinkGrantStatus(value: unknown): value is LinkGrantStatus {
  return includesValue(LINK_GRANT_STATUSES, value);
}

/**
 * Grant status a connection status change cascades to. LinkStore
 * .setConnectionStatus applies this to the connection's grant in the same
 * write. 'pending' is never set through setConnectionStatus.
 */
export const LINK_GRANT_STATUS_FOR_CONNECTION_STATUS: Readonly<Record<LinkConnectionStatus, LinkGrantStatus>> = {
  pending: 'pending',
  active: 'active',
  needs_reauth: 'needs_reauth',
  frozen: 'needs_reauth',
  revoked: 'revoked',
};

/** Connection custody (spec 4). Phase 1 writes only 'self'. */
export const LINK_CUSTODIES = ['hosted', 'self'] as const;
/** Connection custody (spec 4). */
export type LinkCustody = (typeof LINK_CUSTODIES)[number];

/** Terminal outcome of a transaction. The protocol package choice (spec only has consumed_at). Used by the server. */
export const LINK_TRANSACTION_OUTCOMES = ['activated', 'failed', 'cancelled', 'expired'] as const;
/** Terminal outcome of a transaction. Used by the server. */
export type LinkTransactionOutcome = (typeof LINK_TRANSACTION_OUTCOMES)[number];

/** org_policy.usage (spec 3). Semantics unspecified in the spec; Phase 1 writes 'allow'. */
export const LINK_ORG_POLICY_USAGES = ['deny', 'allow', 'require'] as const;
/** org_policy.usage (spec 3). */
export type LinkOrgPolicyUsage = (typeof LINK_ORG_POLICY_USAGES)[number];
/** Default org_policy written on new grants (the protocol package choice). */
export const LINK_DEFAULT_ORG_POLICY: Readonly<{ usage: LinkOrgPolicyUsage }> = Object.freeze({ usage: 'allow' });

/**
 * Token format Link connections default to on /api/v1/delegate (spec 8,
 * Phase 1 note). Used by the server.
 */
export const LINK_DEFAULT_TOKEN_FORMAT = 'handle' as const;

/** Client authentication methods for Link client endpoints (spec 2). */
export const LINK_CLIENT_AUTH_METHODS = ['private_key_jwt', 'client_secret_basic'] as const;
/** Client authentication method (spec 2). Used by the server. */
export type LinkClientAuthMethod = (typeof LINK_CLIENT_AUTH_METHODS)[number];

/**
 * private_key_jwt assertion type (RFC 7523). The protocol package convention for carrying
 * it, since the management API has GET and DELETE routes with no body:
 * `Authorization: Bearer <client assertion JWT>`, iss = sub = client_id,
 * aud = the server's base URL (config.redirectBaseUri), exp at most
 * LINK_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS after iat, jti single use.
 * client_secret_basic uses `Authorization: Basic` (RFC 6749 2.3.1).
 */
export const LINK_CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
/** Upper bound on a client assertion's lifetime. The protocol package choice. Used by the server. */
export const LINK_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS = 300;

// ════════════════════════════════════════════════════════════════════════════
// 2. Error codes and bodies
// ════════════════════════════════════════════════════════════════════════════

/**
 * Widget-facing error codes, returned to the client through onError or the
 * redirect (spec 1, spec 2 "Returned to the client").
 * Produced by: the server. Consumed by: the widget.
 */
export const LINK_ERROR_CODES = [
  'access_denied',
  'invalid_scope',
  'required_scope_declined',
  'provider_error',
  'temporarily_unavailable',
  'server_error',
] as const;
/** Widget-facing error code (spec 1). */
export type LinkErrorCode = (typeof LINK_ERROR_CODES)[number];
/** Type guard for LinkErrorCode. */
export function isLinkErrorCode(value: unknown): value is LinkErrorCode {
  return includesValue(LINK_ERROR_CODES, value);
}

/**
 * Typed machine error codes for agent-facing calls (spec 5 "Protocol
 * behavior"), including the two existing codes the server already returns.
 * Produced by: the guard hooks (checkLinkAccess) and the server. Consumed by agents.
 */
export const LINK_MACHINE_ERROR_CODES = [
  'grant_revoked',
  'grant_expired',
  'grant_reuse_detected',
  'subject_disabled',
  'reauth_required',
  'provider_scope_changed',
  'insufficient_scope',
  'permission_required',
  'consent_required',
  'scope_escalation_denied',
] as const;
/** Typed machine error code (spec 5). */
export type LinkMachineErrorCode = (typeof LINK_MACHINE_ERROR_CODES)[number];
/** Type guard for LinkMachineErrorCode. */
export function isLinkMachineErrorCode(value: unknown): value is LinkMachineErrorCode {
  return includesValue(LINK_MACHINE_ERROR_CODES, value);
}

/**
 * HTTP status for each machine code. The protocol package choice: all 403, matching the
 * server's existing consent_required and scope_escalation_denied (the agent
 * authenticated fine; the user's grant does not allow the call).
 */
export const LINK_MACHINE_ERROR_STATUS: Readonly<Record<LinkMachineErrorCode, number>> = {
  grant_revoked: 403,
  grant_expired: 403,
  grant_reuse_detected: 403,
  subject_disabled: 403,
  reauth_required: 403,
  provider_scope_changed: 403,
  insufficient_scope: 403,
  permission_required: 403,
  consent_required: 403,
  scope_escalation_denied: 403,
};

/**
 * Error codes of the client-authenticated Link API (PAR and connection
 * management). The protocol package choice where the spec is silent: invalid_request for
 * malformed input, invalid_scope for scopes outside the catalog or outside
 * grant.scopes. access_denied is only ever sent as the opaque failure.
 * Produced by: the server. Consumed by: developer backends.
 */
export const LINK_API_ERROR_CODES = [
  'invalid_request',
  'invalid_scope',
  'access_denied',
  'temporarily_unavailable',
  'server_error',
] as const;
/** Link API error code. */
export type LinkApiErrorCode = (typeof LINK_API_ERROR_CODES)[number];

/** HTTP status for each Link API error code. Used by the server. */
export const LINK_API_ERROR_STATUS: Readonly<Record<LinkApiErrorCode, number>> = {
  invalid_request: 400,
  invalid_scope: 400,
  access_denied: 401,
  temporarily_unavailable: 503,
  server_error: 500,
};

/** Every error code a Link HTTP response body may carry. */
export type LinkWireErrorCode = LinkErrorCode | LinkMachineErrorCode | LinkApiErrorCode;

/**
 * The single error body shape (spec 5 "Errors are typed codes only").
 * `message`, when present, is static server text only: never provider
 * error text and never exception messages (spec 5 gap list).
 * Produced by: the server. Consumed by: agents, developer backends.
 */
export interface LinkErrorBody<C extends string = LinkWireErrorCode> {
  error: C;
  request_id: string;
  message?: string;
  /** Space-separated scopes the call lacked (insufficient_scope, permission_required). */
  scope?: string;
  /** Where a human can reconnect (spec 7). */
  reauth_url?: string;
  /** Where a human can grant a missing scope (spec 6 incremental auth). */
  upgrade_uri?: string;
  /** Existing field on consent_required. */
  consent_url?: string;
}

/**
 * The one opaque failure (spec 5 "Enumeration"): unknown client, bad
 * secret, unknown or foreign connection, bad activation code or subject
 * mismatch. Exactly this body, status 401, plus the Cred-Request-Id header.
 * The body deliberately carries no request_id.
 * Produced by: the server.
 */
export const LINK_OPAQUE_FAILURE_BODY: Readonly<{ error: 'access_denied' }> = Object.freeze({ error: 'access_denied' });
/** HTTP status of the opaque failure (spec 5). */
export const LINK_OPAQUE_FAILURE_STATUS = 401;

/** Response header carrying the request id (spec 5). Used by the server. */
export const CRED_REQUEST_ID_HEADER = 'Cred-Request-Id';

/**
 * Machine code an agent receives when the connection is not usable, by
 * connection status. 'active' maps to null (usable). For needs_reauth the
 * connection's own status_reason wins when set (spec 7: grant_revoked or
 * grant_expired). Used by the guard hooks, the server.
 */
export const LINK_MACHINE_CODE_FOR_CONNECTION_STATUS: Readonly<Record<LinkConnectionStatus, LinkMachineErrorCode | null>> = {
  pending: 'consent_required',
  active: null,
  needs_reauth: 'reauth_required',
  frozen: 'grant_reuse_detected',
  revoked: 'grant_revoked',
};

/** Same as above, by grant status. Used by the guard hooks, the server. */
export const LINK_MACHINE_CODE_FOR_GRANT_STATUS: Readonly<Record<LinkGrantStatus, LinkMachineErrorCode | null>> = {
  pending: 'consent_required',
  active: null,
  needs_reauth: 'reauth_required',
  revoked: 'grant_revoked',
  expired: 'grant_expired',
};

// ════════════════════════════════════════════════════════════════════════════
// 3. Scope catalog and scope-set helpers
// ════════════════════════════════════════════════════════════════════════════

/** A provider-keyed scope map, as in PAR `scopes` and `required_scopes` (spec 2). */
export type LinkScopeMap = Partial<Record<LinkProviderSlug, string[]>>;

/** Catalog `access` values (spec 3). */
export const LINK_SCOPE_ACCESS = ['read', 'write', 'admin'] as const;
/** Catalog `access` (spec 3). */
export type LinkScopeAccess = (typeof LINK_SCOPE_ACCESS)[number];

/** Catalog `risk` values. The spec names the field but not its values; the protocol package choice. */
export const LINK_SCOPE_RISKS = ['low', 'medium', 'high'] as const;
/** Catalog `risk`. */
export type LinkScopeRisk = (typeof LINK_SCOPE_RISKS)[number];

/** Catalog `enforced_by` (spec 3). */
export const LINK_SCOPE_ENFORCERS = ['provider', 'cred'] as const;
/** Catalog `enforced_by` (spec 3). */
export type LinkScopeEnforcer = (typeof LINK_SCOPE_ENFORCERS)[number];

/**
 * Catalog flags, one per "Flag" column phrase in spec 3. Behavior the
 * server must apply:
 *   hidden            never shown as a toggle; always requested from the provider; never part of grant.scopes
 *   always_required   always requested and shown locked, as if in required_scopes
 *   never_offer       never offered on the picker; PAR requesting it fails invalid_scope
 *   preferred_default pre-selected on the picker when requested
 *   includes_delete, over_broad, restricted, ambiguous, no_read_only_form,
 *   not_data_permission: display warnings only
 */
export const LINK_SCOPE_FLAGS = [
  'includes_delete',
  'over_broad',
  'restricted',
  'ambiguous',
  'preferred_default',
  'no_read_only_form',
  'not_data_permission',
  'hidden',
  'always_required',
  'never_offer',
] as const;
/** Catalog flag. */
export type LinkScopeFlag = (typeof LINK_SCOPE_FLAGS)[number];

/**
 * One catalog entry (spec 3). `scope` is in canonical form.
 * Produced by: the protocol package (LINK_SCOPE_CATALOG). Consumed by: the server (PAR
 * validation, picker, confirm), the widget (optional narrowing checks).
 */
export interface ScopeCatalogEntry {
  provider: LinkProviderSlug;
  scope: string;
  label: string;
  access: LinkScopeAccess;
  risk: LinkScopeRisk;
  enforced_by: LinkScopeEnforcer;
  flags: readonly LinkScopeFlag[];
}

function entry(
  provider: LinkProviderSlug,
  scope: string,
  label: string,
  access: LinkScopeAccess,
  risk: LinkScopeRisk,
  flags: readonly LinkScopeFlag[] = [],
  enforced_by: LinkScopeEnforcer = 'provider',
): ScopeCatalogEntry {
  return Object.freeze({ provider, scope, label, access, risk, enforced_by, flags: Object.freeze([...flags]) });
}

/**
 * The Phase 1 scope catalog, transcribed from the spec 3 table and then
 * corrected against provider behavior: hidden identity scopes for Google
 * (needed for a stable provider_account_id) and HubSpot's mandatory
 * 'oauth' scope, read-only Sheets and Docs entries, and delete flags. A scope a
 * PAR requests for a provider must appear here (else invalid_scope).
 * Notion has no OAuth scopes: its single entry 'content' is a Cred-side
 * scope (enforced_by 'cred') standing for whatever capabilities the Notion
 * integration was configured with. A combined table row ("drive.readonly,
 * drive") becomes one entry per scope.
 */
export const LINK_SCOPE_CATALOG: readonly ScopeCatalogEntry[] = Object.freeze([
  entry('google', 'openid', 'Confirm which Google account this is', 'read', 'low', ['not_data_permission', 'hidden']),
  entry('google', 'email', 'See your email address', 'read', 'low', ['not_data_permission', 'hidden']),
  entry('google', 'userinfo.email', 'See your email address', 'read', 'low', ['not_data_permission', 'hidden']),
  entry('google', 'calendar.readonly', 'See all your calendars and events', 'read', 'medium'),
  entry('google', 'calendar.events', 'Create, change and delete events', 'write', 'medium', ['includes_delete']),
  entry('google', 'gmail.readonly', 'Read all your email', 'read', 'high', ['over_broad', 'restricted']),
  entry('google', 'gmail.send', 'Send email as you', 'write', 'high'),
  entry('google', 'gmail.compose', 'Create drafts and send email', 'write', 'high', ['ambiguous', 'restricted']),
  entry('google', 'drive.file', 'Only files you open with this app', 'write', 'low', ['preferred_default']),
  entry('google', 'drive.readonly', 'See every Drive file', 'read', 'high', ['over_broad', 'restricted']),
  entry('google', 'drive', 'See, change, share and delete every Drive file', 'admin', 'high', ['over_broad', 'restricted', 'includes_delete']),
  entry('google', 'spreadsheets.readonly', 'Read all Sheets', 'read', 'high', ['over_broad']),
  entry('google', 'spreadsheets', 'Read and change all Sheets', 'write', 'high', ['over_broad']),
  entry('google', 'documents.readonly', 'Read all Docs', 'read', 'high', ['over_broad']),
  entry('google', 'documents', 'Read and change all Docs', 'write', 'high', ['over_broad']),

  entry('github', 'read:user', 'Read your profile', 'read', 'low'),
  entry('github', 'user', 'Read and change your profile', 'write', 'medium', ['ambiguous']),
  entry('github', 'public_repo', 'Read and write public repos', 'write', 'high', ['no_read_only_form']),
  entry('github', 'repo', 'Full control of private and public repos', 'admin', 'high', ['over_broad']),
  entry('github', 'workflow', 'Change Actions workflow files', 'admin', 'high', ['over_broad']),

  entry('slack', 'channels:read', 'List public channels', 'read', 'low', ['ambiguous']),
  entry('slack', 'chat:write', 'Post, edit and delete the messages it sends', 'write', 'medium', ['ambiguous', 'includes_delete']),
  entry('slack', 'users:read', 'See people', 'read', 'low'),
  entry('slack', 'files:write', 'Upload, edit and delete files', 'write', 'medium', ['includes_delete']),

  entry('notion', 'content', 'Read and change the pages you choose in Notion', 'write', 'medium', ['ambiguous', 'includes_delete'], 'cred'),

  entry('salesforce', 'api', 'Access and manage your data', 'admin', 'high', ['over_broad']),
  entry('salesforce', 'refresh_token', 'Stay connected', 'read', 'low', ['not_data_permission', 'hidden']),

  entry('linear', 'read', 'Read workspace data', 'read', 'low', ['always_required']),
  entry('linear', 'issues:create', 'Create issues', 'write', 'low', ['preferred_default']),
  entry('linear', 'comments:create', 'Create comments', 'write', 'low', ['preferred_default']),
  entry('linear', 'write', 'Change or delete anything', 'write', 'high', ['over_broad', 'includes_delete']),
  entry('linear', 'admin', 'Administer workspace', 'admin', 'high', ['over_broad', 'never_offer']),

  entry('hubspot', 'oauth', 'Stay connected', 'read', 'low', ['not_data_permission', 'hidden']),
  entry('hubspot', 'crm.objects.contacts.read', 'View contacts', 'read', 'low'),
  entry('hubspot', 'crm.objects.contacts.write', 'Create, change and delete contacts', 'write', 'medium', ['includes_delete']),
  entry('hubspot', 'content', 'Manage site content', 'write', 'high', ['over_broad']),
  entry('hubspot', 'automation', 'Manage workflows', 'write', 'high', ['over_broad']),
]);

/** Catalog entries for one provider. Used by the server, the widget. */
export function linkScopeCatalogFor(provider: LinkProviderSlug): ScopeCatalogEntry[] {
  return LINK_SCOPE_CATALOG.filter((e) => e.provider === provider);
}

/** Catalog lookup, comparing in canonical form. null when not in the catalog. Used by the server. */
export function findScopeCatalogEntry(provider: LinkProviderSlug, scope: string): ScopeCatalogEntry | null {
  const wanted = canonicalScope(scope);
  return LINK_SCOPE_CATALOG.find((e) => e.provider === provider && e.scope === wanted) ?? null;
}

const GOOGLE_AUTH_SCOPE_PREFIX = 'https://www.googleapis.com/auth/';

/**
 * Canonical form of one scope. Byte-for-byte the same rule as
 * `canonicalScope` in packages/server/src/server.ts: trim, drop one
 * trailing slash, and turn a Google auth URL into its lowercase short name.
 * Every other scope keeps its case. All packages.
 */
export function canonicalScope(scope: string): string {
  const trimmed = scope.trim().replace(/\/$/, '');
  const normalized = trimmed.toLowerCase();
  if (normalized.startsWith(GOOGLE_AUTH_SCOPE_PREFIX)) {
    return normalized.slice(GOOGLE_AUTH_SCOPE_PREFIX.length);
  }
  return trimmed;
}

/** Whether two scopes are the same in canonical form (server's scopeEquivalent). */
export function scopesEquivalent(left: string, right: string): boolean {
  return canonicalScope(left) === canonicalScope(right);
}

/**
 * Canonical scope set: canonical names, empties dropped, deduplicated,
 * sorted by code unit. This is the form every Link record stores. Equality
 * only, no wildcards: Link scopes are provider-native strings.
 * All packages.
 */
export function canonicalScopeSet(scopes: readonly string[]): string[] {
  const set = new Set<string>();
  for (const scope of scopes) {
    if (typeof scope !== 'string') continue;
    const c = canonicalScope(scope);
    if (c !== '') set.add(c);
  }
  return Array.from(set).sort();
}

/** True when every scope in `subset` is in `superset` (canonical comparison). Empty subset is true. */
export function isScopeSubset(subset: readonly string[], superset: readonly string[]): boolean {
  const sup = new Set(canonicalScopeSet(superset));
  return canonicalScopeSet(subset).every((s) => sup.has(s));
}

/** Canonical intersection of two scope lists. */
export function intersectScopes(a: readonly string[], b: readonly string[]): string[] {
  const bs = new Set(canonicalScopeSet(b));
  return canonicalScopeSet(a).filter((s) => bs.has(s));
}

/** Canonical union of two scope lists. */
export function unionScopes(a: readonly string[], b: readonly string[]): string[] {
  return canonicalScopeSet([...a, ...b]);
}

/** Canonical `a` minus `b` (for example the scopes a call lacks). */
export function scopeDifference(a: readonly string[], b: readonly string[]): string[] {
  const bs = new Set(canonicalScopeSet(b));
  return canonicalScopeSet(a).filter((s) => !bs.has(s));
}

/** Whether two scope lists are the same set in canonical form. */
export function scopeSetsEqual(a: readonly string[], b: readonly string[]): boolean {
  const ca = canonicalScopeSet(a);
  const cb = canonicalScopeSet(b);
  return ca.length === cb.length && ca.every((s, i) => s === cb[i]);
}

/**
 * Audience per provider (spec 3: "provider API origin; exact instance host
 * for Salesforce"). Salesforce is null: its audience is the connection's
 * instance_url origin, see linkAudienceFor. Google spans several API hosts;
 * its audience is an identifier, not the broker allowlist.
 */
export const LINK_PROVIDER_AUDIENCES: Readonly<Record<LinkProviderSlug, string | null>> = {
  google: 'https://www.googleapis.com',
  github: 'https://api.github.com',
  slack: 'https://slack.com',
  notion: 'https://api.notion.com',
  salesforce: null,
  linear: 'https://api.linear.app',
  hubspot: 'https://api.hubapi.com',
};

/** Same grammar as SALESFORCE_HOST_PATTERN in packages/server/src/server.ts. */
const SALESFORCE_HOST_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.(?:salesforce\.com|force\.com)$/;

/**
 * The grant audience for a provider (spec 3, spec 5 Salesforce pinning).
 * For Salesforce, `instance_url` must be `https://<host>` (optional `/`)
 * with a host matching the server's Salesforce grammar and not starting
 * with a dotted IPv4 quad; the audience is `https://<lowercase host>`.
 * Returns null when no valid audience can be formed. The server writes it,
 * the guard hooks looks grants up by it.
 */
export function linkAudienceFor(provider: LinkProviderSlug, instance_url?: string | null): string | null {
  const fixed = LINK_PROVIDER_AUDIENCES[provider];
  if (fixed !== null) return fixed;
  if (typeof instance_url !== 'string') return null;
  const m = /^https:\/\/([^/?#:@]+)\/?$/i.exec(instance_url.trim());
  if (!m) return null;
  const host = m[1].toLowerCase();
  if (!SALESFORCE_HOST_PATTERN.test(host)) return null;
  if (/^(\d{1,3}\.){3}\d{1,3}\./.test(host)) return null;
  return `https://${host}`;
}

// ════════════════════════════════════════════════════════════════════════════
// 4. Data model (records)
// ════════════════════════════════════════════════════════════════════════════

/** Minimal JWK shape (RFC 7517). Mirrors nothing existing. Used by the server. */
export interface LinkJwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  [member: string]: unknown;
}

/**
 * Hosted-page theme (spec 1 widget prop, camelCase as the spec writes it).
 * Also the registered default theme on LinkClient (spec 4 link_clients.theme).
 * appName and logoUrl identify the app to the user on the consent pages,
 * so they come only from the client's registration: the authorize query
 * (which the browser controls) never carries them, and the widget's values
 * for them are ignored. The cosmetic fields (accent, radius, font,
 * colorScheme) follow per-field precedence: authorize query, then
 * registered theme, then Cred defaults. Use sanitizeLinkTheme on
 * registration input and sanitizeLinkCosmeticTheme on query input.
 */
export interface LinkTheme {
  appName?: string;
  logoUrl?: string;
  accent?: string;
  radius?: number;
  font?: string;
  colorScheme?: 'light' | 'dark' | 'auto';
}

interface LinkClientBase {
  client_id: string;
  org_id: OrgId;
  name: string;
  /** Exact-match list (spec 5). */
  redirect_uris: string[];
  /** Exact-match list of web origins, scheme://host[:port] (spec 1, 5). */
  origins: string[];
  theme?: LinkTheme;
  /** spec 4 raw-token escape hatch. Phase 1 stores it; false by default. */
  allow_raw_tokens: boolean;
  status: 'active' | 'disabled';
  created_at: string;
  updated_at: string;
}

/**
 * A registered developer app (spec 4 link_clients). The auth method decides
 * which credential field is present. provider_creds_enc (hosted custody)
 * is out of scope for Phase 1: provider credentials come from server config.
 * Produced by: the server (registration). Consumed by: the server.
 */
export type LinkClient =
  | (LinkClientBase & { token_endpoint_auth_method: 'private_key_jwt'; jwks: { keys: LinkJwk[] }; client_secret_hash?: never })
  | (LinkClientBase & { token_endpoint_auth_method: 'client_secret_basic'; client_secret_hash: string; jwks?: never });

/**
 * A connected provider account (spec 4 connections). Unique among
 * non-revoked rows on (client_id, audience, subject, provider_account_id).
 * No token material: secrets live behind LinkSecretStore.
 * Produced by: the server (LinkStore). Consumed by: the server, the guard hooks.
 */
export interface Connection {
  id: ConnectionId;
  org_id: OrgId;
  client_id: string;
  provider: LinkProviderSlug;
  /** See linkAudienceFor. */
  audience: string;
  subject: string;
  subject_type: LinkSubjectType;
  /** Stable provider-side account id (Google sub, GitHub user id, Slack team+user, ...). */
  provider_account_id: string;
  /** Display label from the exchange (email, login, workspace name). Not authoritative. */
  account_label?: string;
  /** What the provider actually granted, canonical. */
  provider_scopes: string[];
  /** Salesforce only (spec 5): the exact instance URL captured at connect time. */
  instance_url?: string;
  status: LinkConnectionStatus;
  /** Why the connection left 'active' (spec 7), e.g. grant_revoked or grant_expired. */
  status_reason?: LinkMachineErrorCode;
  custody: LinkCustody;
  /** Bumped on every change to provider_scopes, status or secrets. */
  version: number;
  created_at: string;
  updated_at: string;
}

/**
 * A client-grant record (spec 3), one per connection in Phase 1. Carries no
 * agent. Invariant: scopes is a subset of the connection's provider_scopes
 * (plus enforced_by 'cred' catalog scopes), never containing 'hidden' scopes.
 * Produced by: the server (LinkStore). Consumed by: the guard hooks.
 */
export interface ClientGrant {
  id: GrantId;
  org_id: OrgId;
  client_id: string;
  audience: string;
  subject: string;
  subject_type: LinkSubjectType;
  /** What agents may exercise, canonical. */
  scopes: string[];
  org_policy: { usage: LinkOrgPolicyUsage };
  /** Phase 1: always []. */
  authorization_details_types: string[];
  connection_id: ConnectionId;
  status: LinkGrantStatus;
  /** Bumped on every scopes or status change. */
  version: number;
  granted_at: string;
  updated_at: string;
  expires_at?: string;
}

/**
 * Server-side state of one hosted flow (spec 2 LinkTransaction, extended
 * with the fields the flow needs). Holds no tokens: staged tokens live in
 * LinkSecretStore under the tid. Staged changes for update and reauth (and
 * for a connect that lands on an existing connection) are
 * `provider_granted_scopes` (new connection.provider_scopes) and
 * `confirmed_scopes` (new grant.scopes); they are applied only by
 * LinkStore.commitActivation.
 * Produced and consumed by: the server. The guard hooks reads `agent_id` and
 * `intent` through the hook inputs.
 */
export interface LinkTransaction {
  tid: TransactionId;
  org_id: OrgId;
  client_id: string;
  intent: LinkIntent;
  /** Always from the authenticated PAR (or reauth) call, never from a connection. */
  subject: string;
  subject_type: LinkSubjectType;
  /** Allowed providers: PAR value, narrowed at authorize. One element for update and reauth. */
  providers: LinkProviderSlug[];
  /** Canonical, narrowed at authorize. */
  requested_scopes: LinkScopeMap;
  /** Canonical, always a subset of requested_scopes per provider. */
  required_scopes: LinkScopeMap;
  /** Phase 1: always []. */
  authorization_details: unknown[];
  redirect_uri: string;
  origin: string;
  /** The developer's `state`, echoed back in results. */
  client_state?: string;
  /** Seeds a Permission on activation (spec 3). */
  agent_id?: string;
  /** update/reauth: from the request. connect: set by commitConfirm. */
  connection_id?: ConnectionId;
  /** connect: set by commitConfirm. update/reauth: the existing grant. */
  grant_id?: GrantId;
  /**
   * True when commitConfirm inserted a new pending connection and grant for
   * this transaction (so failure or expiry must revoke them). False when the
   * transaction stages onto an existing connection.
   */
  creates_connection?: boolean;
  /** From authorize; decides how results are delivered. */
  mode?: LinkWidgetMode;
  /** Theme overrides received at authorize. */
  theme?: LinkTheme;

  // Binding (spec 2, 5)
  request_uri_hash: string;
  request_uri_consumed_at?: string;
  /** Hash of the one outstanding envelope handle. */
  handle_hash?: string;
  /** Hash of the __Host-cred_link_tx cookie value, set by the first top-level page. */
  binding_cookie_hash?: string;

  // Provider hop
  step: LinkStep;
  provider?: LinkProviderSlug;
  /** The user's picker toggles, canonical. */
  selected_scopes?: string[];
  /** Exactly what was sent to the provider (smallest covering set plus hidden/always_required). */
  provider_requested_scopes?: string[];
  pkce_verifier?: string;
  /** Starts at 0; incremented each time the provider hop (re)starts. */
  provider_attempt: number;

  // Exchange result, no tokens (spec 2: "granted scopes and account label only")
  exchanged_at?: string;
  provider_granted_scopes?: string[];
  provider_account_id?: string;
  account_label?: string;
  instance_url?: string;

  // Confirm
  confirmed_at?: string;
  confirmed_scopes?: string[];
  activation_code_hash?: string;

  // Activation
  activation_claimed_at?: string;
  activated_at?: string;

  // Lifecycle
  created_at: string;
  updated_at: string;
  /** created_at + LINK_TRANSACTION_TTL_SECONDS. Also the cookie expiry. */
  expires_at: string;
  /** Set once the transaction reaches a terminal outcome. */
  consumed_at?: string;
  outcome?: LinkTransactionOutcome;
  /** Widget error code recorded on outcome 'failed'. */
  error?: LinkErrorCode;
}

/** Fields of LinkTransaction that advanceTransaction may change. null clears an optional field. Used by the server. */
export type LinkTransactionPatch = {
  [K in
    | 'provider'
    | 'selected_scopes'
    | 'provider_requested_scopes'
    | 'pkce_verifier'
    | 'provider_attempt'
    | 'exchanged_at'
    | 'provider_granted_scopes'
    | 'provider_account_id'
    | 'account_label'
    | 'instance_url']?: LinkTransaction[K] | null;
};

/** Input to LinkStore.createTransaction: everything PAR decides. Used by the server. */
export type NewLinkTransaction = Pick<
  LinkTransaction,
  | 'tid'
  | 'org_id'
  | 'client_id'
  | 'intent'
  | 'subject'
  | 'subject_type'
  | 'providers'
  | 'requested_scopes'
  | 'required_scopes'
  | 'authorization_details'
  | 'redirect_uri'
  | 'origin'
  | 'client_state'
  | 'agent_id'
  | 'connection_id'
  | 'grant_id'
  | 'request_uri_hash'
  | 'created_at'
  | 'expires_at'
>;

/** Lifetime of request_uri and of the whole transaction, seconds (spec 2 `expires_in: 600`). */
export const LINK_TRANSACTION_TTL_SECONDS = 600;

/** Transaction-binding cookie (spec 2). HttpOnly, Secure, SameSite=Lax, Path=/. Used by the server. */
export const LINK_TX_COOKIE_NAME = '__Host-cred_link_tx';

/**
 * Envelope (spec 2): the provider `state` value and the only parameter on
 * hosted pages. Encode with encodeLinkEnvelope, decode with decodeLinkEnvelope.
 * Used by the server.
 */
export interface LinkEnvelope {
  /** 256-bit handle, base64url (LINK_SECRET_PATTERN). */
  h: string;
  tid: TransactionId;
  /** client_id. */
  cid: string;
}

/** Upper bound on an encoded envelope's length. */
export const LINK_ENVELOPE_MAX_LENGTH = 512;

/** Audit resource type Link adds to the vault's AuditResource union (spec 4). The guard hooks adds it, the server writes it. */
export const LINK_AUDIT_RESOURCE_TYPE_GRANT = 'grant' as const;

/**
 * AuditEvent.metadata for every grant create, update or revoke (spec 5
 * "Silent grant changes"). Written fail-closed by the server.
 */
export interface LinkGrantAuditMetadata {
  grant_id: GrantId;
  connection_id: ConnectionId;
  client_id: string;
  subject: string;
  provider: LinkProviderSlug;
  before_scopes: string[] | null;
  after_scopes: string[];
  before_status: LinkGrantStatus | null;
  after_status: LinkGrantStatus;
  version: number;
  reason: 'confirm' | 'activate' | 'provider_scope_changed' | 'narrow' | 'revoke' | 'reauth_required' | 'expire';
  tid?: TransactionId;
}

// ════════════════════════════════════════════════════════════════════════════
// 5. Wire shapes
// ════════════════════════════════════════════════════════════════════════════

/** All Link routes (spec 2, 4). `:provider` and `:id` are path parameters. */
export const LINK_PATHS = {
  par: '/link/v1/par',
  authorize: '/link/v1/authorize',
  callback: '/link/v1/callback/:provider',
  /** Picker form POST target (the protocol package choice; spec only says "choose provider and permissions"). */
  picker: '/link/v1/picker',
  /** Confirm form POST target (the protocol package choice). */
  confirm: '/link/v1/confirm',
  connections: '/link/v1/connections',
  connection: '/link/v1/connections/:id',
  activate: '/link/v1/connections/:id/activate',
  refresh: '/link/v1/connections/:id/refresh',
  reauth: '/link/v1/connections/:id/reauth',
  permissions: '/link/v1/connections/:id/permissions',
} as const;

/** A Link route template. */
export type LinkPath = (typeof LINK_PATHS)[keyof typeof LINK_PATHS];

/** Fill `:id` and `:provider` in a LINK_PATHS template (percent-encoded). Throws if a needed value is missing. */
export function fillLinkPath(path: LinkPath, params: { id?: string; provider?: string } = {}): string {
  return path.replace(/:(id|provider)\b/g, (_m, name: 'id' | 'provider') => {
    const v = params[name];
    if (typeof v !== 'string' || v === '') throw new TypeError(`fillLinkPath: missing ${name}`);
    return encodeURIComponent(v);
  });
}

/** Default hosted Link base URL (spec 1). Used by the widget. */
export const LINK_DEFAULT_BASE_URL = 'https://link.cred.ninja';

// ── POST /link/v1/par ───────────────────────────────────────────────────────

interface ParRequestBase {
  subject: string;
  subject_type: LinkSubjectType;
  /** Provider-native or canonical names; stored canonical. */
  scopes?: LinkScopeMap;
  /** Must be a subset of `scopes` per provider. */
  required_scopes?: LinkScopeMap;
  /** Phase 1: must be absent or []. */
  authorization_details?: unknown[];
  /** Exact match against the client's registration. Required for all modes. */
  redirect_uri: string;
  /** Exact match against the client's registration. Required for all modes. */
  origin: string;
  /** The developer's CSRF value, echoed back. */
  state?: string;
  agent_id?: string | null;
}

/** PAR body for intent 'connect' (spec 2). `providers` required and non-empty. */
export interface ParConnectRequest extends ParRequestBase {
  intent: 'connect';
  providers: LinkProviderSlug[];
  /** Required (spec 2 example) so its absence is visible. */
  scopes: LinkScopeMap;
  connection_id?: null;
}

/**
 * PAR body for 'update' and 'reauth' (spec 6). `connection_id` must belong
 * to (authenticated client, subject), otherwise the opaque failure.
 * `providers`, when present, must equal [connection.provider].
 * update: `scopes` are the extra scopes; the provider is asked for the union
 * with the current grant. reauth: `scopes` absent means the current grant.
 */
export interface ParUpdateOrReauthRequest extends ParRequestBase {
  intent: 'update' | 'reauth';
  connection_id: string;
  providers?: LinkProviderSlug[];
}

/** PAR request body (spec 2), discriminated by `intent`. Client-authenticated. Used by the server. */
export type ParRequest = ParConnectRequest | ParUpdateOrReauthRequest;

/** PAR response, status 201 (spec 2). Used by the server. */
export interface ParResponse {
  /** The widget `token`. */
  request_uri: string;
  expires_in: number;
}

// ── GET /link/v1/authorize ──────────────────────────────────────────────────

/** Query parameter names on GET /link/v1/authorize. */
export const LINK_AUTHORIZE_PARAMS = {
  client_id: 'client_id',
  request_uri: 'request_uri',
  mode: 'mode',
  /** Comma-separated slugs, narrowing only. */
  providers: 'providers',
  /** JSON object {slug: string[]}, narrowing only. */
  scopes: 'scopes',
  accent: 'accent',
  radius: 'radius',
  font: 'font',
  color_scheme: 'color_scheme',
} as const;

/**
 * GET /link/v1/authorize query (spec 2). The widget only holds the token,
 * so client_id is optional; when present it must match the transaction.
 * providers and scopes can only narrow what was pushed.
 * Produced by: the widget (buildLinkAuthorizeQuery). Consumed by: the server
 * (parseLinkAuthorizeQuery).
 */
export interface LinkAuthorizeQuery {
  request_uri: string;
  client_id?: string;
  mode: LinkWidgetMode;
  providers?: LinkProviderSlug[];
  scopes?: LinkScopeMap;
  theme?: LinkTheme;
}

// ── GET /link/v1/callback/:provider ─────────────────────────────────────────

/** Provider callback query (spec 2). `state` is the encoded envelope. Used by the server. */
export interface LinkCallbackQuery {
  state?: string;
  code?: string;
  /** Provider error (e.g. access_denied). Never rendered or echoed as text. */
  error?: string;
  error_description?: string;
  /** Some providers (Google) return granted scopes here. */
  scope?: string;
}

// ── Hosted page forms ───────────────────────────────────────────────────────

/** Form field names on the hosted picker and confirm pages (x-www-form-urlencoded). Used by the server. */
export const LINK_FORM_FIELDS = {
  /** The encoded envelope (hidden field). */
  envelope: 'e',
  action: 'action',
  provider: 'provider',
  /** Repeated once per selected scope. */
  scope: 'scope',
} as const;

/** POST /link/v1/picker body, parsed (spec 2 "choose provider and permissions"). Used by the server. */
export interface LinkPickerSubmission {
  e: string;
  action: 'continue' | 'cancel';
  /** Required when action is 'continue'. */
  provider?: LinkProviderSlug;
  /** Selected scope toggles. */
  scopes: string[];
}

/**
 * POST /link/v1/confirm body, parsed (spec 2 "confirm (may narrow)").
 * 'back' restarts the provider hop. Used by the server.
 */
export interface LinkConfirmSubmission {
  e: string;
  action: 'confirm' | 'back' | 'cancel';
  /** Confirmed scopes; must be a subset of provider_granted_scopes. */
  scopes: string[];
}

// ── Widget results ──────────────────────────────────────────────────────────

/** onSuccess payload (spec 1). The connection is pending until activated. */
export interface LinkSuccessPayload {
  connection_id: ConnectionId;
  /** One-time activation code. */
  code: string;
  grant_id: GrantId;
  provider: LinkProviderSlug;
  /** Confirmed scopes, canonical. */
  scopes: string[];
  state?: string;
}

/** onError payload (spec 1). */
export interface LinkErrorPayload {
  error: LinkErrorCode;
  request_id: string;
  state?: string;
}

/** onExit payload (spec 1). `state` added (the protocol package) so redirect-mode exits can be correlated. */
export interface LinkExitPayload {
  step: LinkExitStep;
  provider?: LinkProviderSlug;
  state?: string;
}

/** A widget result, discriminated by `outcome`. The server produces, the widget consumes. */
export type LinkResult =
  | ({ outcome: 'success' } & LinkSuccessPayload)
  | ({ outcome: 'error' } & LinkErrorPayload)
  | ({ outcome: 'exit' } & LinkExitPayload);

/** postMessage `type` strings (spec 1 'cred.link.result'; the others are the protocol package additions). */
export const LINK_MESSAGE_TYPES = {
  /** Final result. */
  result: 'cred.link.result',
  /** Posted by each hosted page on load, and by the picker just before leaving for the provider; lets the widget report onExit.step when a popup is closed. */
  step: 'cred.link.step',
  /** Posted by the embedded picker iframe with its content height in CSS px. */
  resize: 'cred.link.resize',
} as const;

/** Message schema version, carried as `v`. */
export const LINK_MESSAGE_VERSION = 1;

/** cred.link.result message. */
export type LinkResultMessage = { type: 'cred.link.result'; v: 1 } & LinkResult;
/** cred.link.step message. */
export interface LinkStepMessage {
  type: 'cred.link.step';
  v: 1;
  step: LinkExitStep;
  provider?: LinkProviderSlug;
}
/** cred.link.resize message. */
export interface LinkResizeMessage {
  type: 'cred.link.resize';
  v: 1;
  height: number;
}

/**
 * Every postMessage a hosted page sends (spec 1). Delivery rules:
 *   popup:    posted to window.opener, targetOrigin = transaction.origin.
 *   embedded: the picker runs in the iframe and posts step/resize to
 *             window.parent (targetOrigin = transaction.origin). The provider
 *             hop and confirm run top-level in a window the picker opens;
 *             the result is relayed through the iframe, so the widget
 *             receives every message from the iframe's contentWindow.
 *   redirect: no messages; see LINK_REDIRECT_PARAMS.
 * The widget accepts a message only when event.origin equals its baseUrl's
 * origin and event.source is the window or iframe it opened, and then only
 * after parseLinkMessage returns non-null.
 */
export type LinkMessage = LinkResultMessage | LinkStepMessage | LinkResizeMessage;

/**
 * Redirect-mode query parameters appended to the registered redirect_uri
 * (spec 1). `cred_link` carries the outcome. Scopes are space-separated in
 * `scope` (OAuth convention).
 */
export const LINK_REDIRECT_PARAMS = {
  outcome: 'cred_link',
  connection_id: 'connection_id',
  code: 'code',
  grant_id: 'grant_id',
  provider: 'provider',
  scope: 'scope',
  state: 'state',
  error: 'error',
  request_id: 'request_id',
  step: 'step',
} as const;

// ── Connection management API (spec 4) ──────────────────────────────────────

/** Grant as shown by the management API. */
export interface LinkGrantView {
  grant_id: GrantId;
  scopes: string[];
  status: LinkGrantStatus;
  version: number;
  granted_at: string;
  updated_at: string;
  expires_at?: string;
}

/** Connection as shown by the management API ("status, provider, subject, grant"). */
export interface LinkConnectionView {
  connection_id: ConnectionId;
  provider: LinkProviderSlug;
  subject: string;
  subject_type: LinkSubjectType;
  status: LinkConnectionStatus;
  status_reason?: LinkMachineErrorCode;
  provider_account_id: string;
  account_label?: string;
  audience: string;
  provider_scopes: string[];
  created_at: string;
  updated_at: string;
  grant: LinkGrantView | null;
}

/** GET /link/v1/connections?subject=  (subject required, the protocol package choice). */
export interface ListConnectionsQuery {
  subject: string;
}
/** GET /link/v1/connections response. */
export interface ListConnectionsResponse {
  connections: LinkConnectionView[];
}

/** GET /link/v1/connections/:id response. Client-scoped; foreign or unknown id = opaque failure. */
export type GetConnectionResponse = LinkConnectionView;

/**
 * POST /link/v1/connections/:id/activate body (spec 2). `subject` is the
 * user in the backend's current session. Any failure = opaque failure.
 */
export interface ActivateConnectionRequest {
  code: string;
  subject: string;
}
/** Activate response: the connection after activation (status 'active'). */
export type ActivateConnectionResponse = LinkConnectionView;

/** DELETE /link/v1/connections/:id response. */
export interface RevokeConnectionResponse {
  connection_id: ConnectionId;
  status: 'revoked';
  /**
   * Whether the tokens were also revoked at the provider. false when the
   * provider has no revocation endpoint, or when another live connection on
   * this server uses the same provider account: every client shares the
   * server's provider OAuth app, and at Google, Salesforce and Slack one
   * revocation ends the whole authorization for that account, which would
   * break the other connection. The local tokens are deleted either way.
   */
  provider_revoked: boolean;
}

/** POST /link/v1/connections/:id/refresh response ("returns status only"). */
export interface RefreshConnectionResponse {
  connection_id: ConnectionId;
  status: LinkConnectionStatus;
  status_reason?: LinkMachineErrorCode;
}

/**
 * POST /link/v1/connections/:id/reauth body (spec 4). Sugar for PAR with
 * intent 'reauth' and this connection_id. redirect_uri and origin may be
 * omitted only when the client has exactly one of each registered.
 */
export interface ReauthConnectionRequest {
  subject: string;
  redirect_uri?: string;
  origin?: string;
  state?: string;
  agent_id?: string | null;
}
/** Reauth response, status 201. */
export type ReauthConnectionResponse = ParResponse;

/**
 * POST /link/v1/connections/:id/permissions body (spec 3, 4). Upsert:
 * sets this agent's allowedScopes to exactly `scopes`, which must be a
 * subset of grant.scopes (else invalid_scope).
 */
export interface SetConnectionPermissionRequest {
  agent_id: string;
  scopes: string[];
}

/** Permission as shown by the management API. */
export interface LinkPermissionView {
  permission_id: string;
  agent_id: string;
  connection_id: ConnectionId;
  scopes: string[];
  delegatable: boolean;
  max_delegation_depth: number;
  created_at: string;
  updated_at: string;
}
/** POST .../permissions response. */
export interface SetConnectionPermissionResponse {
  permission: LinkPermissionView;
}

/**
 * Fields Link adds to the existing POST /api/v1/delegate body (spec 8).
 * Naming a connection_id makes it a Link call: checkLinkAccess runs and
 * token_format defaults to LINK_DEFAULT_TOKEN_FORMAT. Used by the server.
 */
export interface LinkDelegateRequestFields {
  connection_id?: string;
  token_format?: 'raw' | 'handle';
}

// ════════════════════════════════════════════════════════════════════════════
// 6. Storage interfaces
// ════════════════════════════════════════════════════════════════════════════

/** Result of entering a transaction through a request_uri or an envelope handle. Used by the server. */
export type LinkTransactionEntry =
  /** The presented secret was current: it is now consumed and `new_handle_hash` is outstanding. */
  | { kind: 'fresh'; transaction: LinkTransaction }
  /** The secret was already consumed but the binding cookie matched: re-render the current step; `new_handle_hash` replaced the outstanding handle. */
  | { kind: 'reentry'; transaction: LinkTransaction }
  /** Render the local error page. The transaction is untouched. */
  | { kind: 'rejected'; reason: 'unknown' | 'expired' | 'client_mismatch' | 'replayed' | 'finished' };

/** Result of LinkStore.commitConfirm. Used by the server. */
export type LinkConfirmCommit =
  /** This call wrote the confirm effect. */
  | { kind: 'committed'; transaction: LinkTransaction }
  /** An earlier call already did: return its result (connection_id, grant_id, confirmed_scopes on the transaction). */
  | { kind: 'already_committed'; transaction: LinkTransaction }
  /** update/reauth (or connect onto an existing connection) finished on a different provider account: end with access_denied. */
  | { kind: 'account_mismatch'; transaction: LinkTransaction }
  /** The target connection is revoked or gone: end with access_denied. */
  | { kind: 'connection_unavailable'; transaction: LinkTransaction };

/** Result of LinkStore.claimActivation. The server maps every failure to the opaque failure. */
export type LinkActivationClaim =
  | { ok: true; transaction: LinkTransaction }
  /** No unclaimed transaction for (client_id, connection_id, code hash). Nothing changed. */
  | { ok: false; reason: 'invalid_code' }
  /**
   * The code matched but the transaction expired or the subject did not
   * match. The store has already ended the transaction (outcome 'failed' or
   * 'expired') and revoked any connection and grant it created; the server
   * must revoke and delete the staged tokens for `transaction.tid`.
   */
  | { ok: false; reason: 'expired' | 'subject_mismatch'; transaction: LinkTransaction };

/**
 * Async storage for everything Link persists except tokens (spec 4).
 * Implemented by the server on SQLite. Called by the server and the guard hooks.
 * Every method is atomic on its own (one SQLite transaction); none returns
 * token material. Methods that "return null" never throw for a missing row.
 */
export interface LinkStore {
  // ── Clients ──────────────────────────────────────────────────────────────
  getClient(client_id: string): Promise<LinkClient | null>;
  /** Insert or replace a client registration. */
  putClient(client: LinkClient): Promise<void>;
  /** Every registered client, any status, ordered by client_id (admin listing). */
  listClients(): Promise<LinkClient[]>;

  // ── Transactions ─────────────────────────────────────────────────────────
  /** Insert at PAR time: step 'picker', provider_attempt 0, no handle yet. */
  createTransaction(tx: NewLinkTransaction): Promise<LinkTransaction>;
  getTransaction(tid: TransactionId): Promise<LinkTransaction | null>;
  /**
   * GET /authorize. Looks the transaction up by request_uri_hash.
   * fresh: request_uri not yet consumed, not expired, client_id matches
   *   (when given) -> set request_uri_consumed_at, handle_hash =
   *   new_handle_hash, mode, theme, narrowed providers/scopes, and
   *   binding_cookie_hash = new_binding_cookie_hash when given.
   * reentry: already consumed, not terminal, presented_cookie_hash equals
   *   binding_cookie_hash -> handle_hash = new_handle_hash only.
   * rejected otherwise ('replayed' = consumed without the matching cookie).
   */
  enterByRequestUri(input: {
    request_uri_hash: string;
    client_id?: string;
    presented_cookie_hash: string | null;
    new_handle_hash: string;
    /** Set when this response sets the binding cookie (top-level modes). */
    new_binding_cookie_hash?: string;
    mode: LinkWidgetMode;
    theme?: LinkTheme;
    /** Already intersected with the pushed values by the caller. */
    narrowed?: { providers: LinkProviderSlug[]; requested_scopes: LinkScopeMap };
    now: string;
  }): Promise<LinkTransactionEntry>;
  /**
   * Every later hop (picker POST, callback, confirm POST). The envelope's
   * cid must equal the transaction's client_id.
   * fresh: handle_hash matches and transaction not expired or terminal,
   *   and, when binding_cookie_hash is already set, presented_cookie_hash
   *   equals it (spec 5: the handle is bound to the transaction cookie; a
   *   handle presented from another browser is rejected as 'replayed' and
   *   the transaction is untouched) -> handle_hash = new_handle_hash; if
   *   binding_cookie_hash is unset and new_binding_cookie_hash is given,
   *   set it (first top-level page in embedded mode).
   * reentry: handle does not match but presented_cookie_hash equals
   *   binding_cookie_hash -> handle_hash = new_handle_hash.
   * rejected otherwise; 'replayed' leaves the transaction untouched.
   */
  enterByHandle(input: {
    tid: TransactionId;
    client_id: string;
    handle_hash: string;
    presented_cookie_hash: string | null;
    new_handle_hash: string;
    new_binding_cookie_hash?: string;
    now: string;
  }): Promise<LinkTransactionEntry>;
  /**
   * Compare-and-set step transition (LINK_STEP_TRANSITIONS, excluding
   * confirm -> done) plus a field patch. Returns null when the transaction
   * is not at `from`, is terminal, or has expired. provider -> confirm must
   * carry exchanged_at (the exchange effect marker).
   */
  advanceTransaction(input: {
    tid: TransactionId;
    from: LinkStep;
    to: LinkStep;
    patch: LinkTransactionPatch;
    now: string;
  }): Promise<LinkTransaction | null>;
  /**
   * The confirm effect, exactly once per tid (spec 2 "a repeated confirm
   * returns the first result"). Requires step 'confirm'. In one write:
   *   connect, no live connection (a status other than pending or revoked)
   *     for (client_id, audience, subject, provider_account_id): insert this
   *     transaction's own pending connection and pending grant from
   *     `new_connection` / `new_grant`, creates_connection = true. A pending
   *     connection created by another transaction is never shared: every
   *     connect transaction owns exactly the pending rows it created, so
   *     ending one flow can never touch what another flow activated.
   *   connect onto a live connection, update, reauth: write nothing to the
   *     connection or grant; check the connection is not revoked and has the
   *     same provider_account_id; creates_connection = false.
   * confirmed_scopes must be a subset of the transaction's requested_scopes
   * for the provider (the browser can only narrow what was pushed, spec 1)
   * and of what the provider granted; otherwise the call is refused. The
   * stored provider_scopes come from the transaction's
   * provider_granted_scopes, never from the caller.
   * Then set confirmed_scopes, activation_code_hash, confirmed_at,
   * connection_id, grant_id, step 'done'.
   */
  commitConfirm(input: {
    tid: TransactionId;
    confirmed_scopes: string[];
    activation_code_hash: string;
    new_connection: Pick<
      Connection,
      'id' | 'audience' | 'provider_account_id' | 'account_label' | 'provider_scopes' | 'instance_url' | 'custody'
    >;
    new_grant: Pick<ClientGrant, 'id' | 'org_policy' | 'authorization_details_types'>;
    now: string;
  }): Promise<LinkConfirmCommit>;
  /**
   * Replace the activation code hash of a confirmed, unclaimed transaction
   * (used when a repeated confirm must hand out a code again, since only
   * the hash is stored). Returns false if already claimed or terminal.
   */
  replaceActivationCode(input: { tid: TransactionId; activation_code_hash: string; now: string }): Promise<boolean>;
  /**
   * First half of activation (spec 2). Atomically finds the confirmed,
   * unclaimed transaction for (client_id, connection_id,
   * activation_code_hash), sets activation_claimed_at, and compares
   * `subject` with transaction.subject. See LinkActivationClaim.
   */
  claimActivation(input: {
    client_id: string;
    connection_id: string;
    activation_code_hash: string;
    subject: string;
    now: string;
  }): Promise<LinkActivationClaim>;
  /**
   * Second half: the database commit. It runs BEFORE the staged tokens
   * move, so a failed activation never changes a live connection's tokens.
   * The server then calls LinkSecretStore.commitStaged under the
   * connection's token lock; if that fails it sets the connection to
   * needs_reauth. creates_connection: connection and grant pending ->
   * active, unless a live connection for the same (client_id, audience,
   * subject, provider_account_id) now exists because another transaction
   * was activated first: then the call is refused, the transaction ends as
   * failed and the pending rows it created are revoked (first activation
   * wins). Otherwise apply the staged change: connection
   * provider_scopes = provider_granted_scopes, status 'active',
   * status_reason cleared, version + 1; grant scopes = confirmed_scopes,
   * status 'active', version + 1. Ends the transaction (activated_at,
   * consumed_at, outcome 'activated').
   * previous_grant_scopes is null when the grant was created by this
   * transaction.
   */
  commitActivation(input: { tid: TransactionId; now: string }): Promise<{
    connection: Connection;
    grant: ClientGrant;
    previous_grant_scopes: string[] | null;
  }>;
  /**
   * End a transaction early (cancel, provider error, declined scope, account
   * mismatch). If creates_connection and not activated, revoke the
   * connection and grant it created. Returns null if already terminal.
   * The server then revokes and deletes the staged tokens.
   */
  endTransaction(input: {
    tid: TransactionId;
    outcome: 'failed' | 'cancelled';
    error?: LinkErrorCode;
    now: string;
  }): Promise<LinkTransaction | null>;
  /**
   * Expiry sweep (spec 2). Ends up to `limit` non-terminal transactions
   * with expires_at <= now (outcome 'expired'), revoking connections and
   * grants they created (grant status 'expired'), and returns them so
   * the server can revoke and delete their staged tokens.
   */
  sweepExpiredTransactions(input: { now: string; limit: number }): Promise<LinkTransaction[]>;

  // ── Connections ──────────────────────────────────────────────────────────
  getConnection(connection_id: string): Promise<Connection | null>;
  /** Ownership check by client only (GET, DELETE, refresh, permissions). null if unknown or foreign. */
  getClientConnection(input: { client_id: string; connection_id: string }): Promise<Connection | null>;
  /** Ownership check by (client, subject) (PAR update/reauth, reauth). null if unknown or foreign. */
  getSubjectConnection(input: { client_id: string; subject: string; connection_id: string }): Promise<Connection | null>;
  /** All connections of (client, subject), any status, newest first. */
  listConnections(input: { client_id: string; subject: string }): Promise<Connection[]>;
  /**
   * Every non-revoked connection on this server for one provider account,
   * across all clients and subjects, pending included. Used to decide
   * whether revoking a token at the provider would break someone else.
   */
  listAccountConnections(input: { provider: LinkProviderSlug; provider_account_id: string }): Promise<Connection[]>;
  /**
   * Every non-terminal transaction that has completed a provider exchange
   * for this provider account (so tokens for it are staged), across all
   * clients and subjects. Same purpose as listAccountConnections.
   */
  listOpenAccountTransactions(input: { provider: LinkProviderSlug; provider_account_id: string }): Promise<LinkTransaction[]>;
  /**
   * Set a connection's status and cascade to its grant using
   * LINK_GRANT_STATUS_FOR_CONNECTION_STATUS; bumps both versions. 'revoked'
   * is terminal: returns null for a revoked or unknown connection. Never
   * sets 'pending'.
   */
  setConnectionStatus(input: {
    connection_id: string;
    status: Exclude<LinkConnectionStatus, 'pending'>;
    reason?: LinkMachineErrorCode;
    now: string;
  }): Promise<{ connection: Connection; grant: ClientGrant | null } | null>;
  /**
   * Record what the provider now reports (spec 7 provider_scope_changed):
   * connection.provider_scopes = provider_scopes; grant.scopes intersected
   * with it (never widened). Versions bump only when something changed.
   */
  applyProviderScopes(input: { connection_id: string; provider_scopes: string[]; now: string }): Promise<{
    connection: Connection;
    grant: ClientGrant | null;
    previous_grant_scopes: string[] | null;
  } | null>;

  // ── Grants ───────────────────────────────────────────────────────────────
  getGrant(grant_id: string): Promise<ClientGrant | null>;
  getGrantForConnection(connection_id: string): Promise<ClientGrant | null>;
  /** Grants for (client, audience, subject). A list: one subject may connect two accounts of one provider. */
  listGrants(input: { client_id: string; audience: string; subject: string }): Promise<ClientGrant[]>;
  /**
   * Narrow a grant in place (spec 6 "Narrowing needs no provider round
   * trip"). The stored scopes become intersect(current, scopes): this
   * method can never widen. Bumps version when changed. Returns null when
   * unknown, not active, or expected_version does not match.
   */
  narrowGrant(input: { grant_id: string; scopes: string[]; expected_version?: number; now: string }): Promise<{
    grant: ClientGrant;
    previous_scopes: string[];
  } | null>;
}

/** Plaintext provider token set. Only LinkSecretStore and the server's provider code ever see it. */
export interface LinkTokenSet {
  access_token: string;
  refresh_token?: string;
  /** ISO-8601 UTC. */
  expires_at?: string;
  token_type?: string;
}

/**
 * Token custody (spec 4 connection_secrets). Separate from LinkStore so
 * policy code can be handed a LinkStore without any path to tokens.
 * Implemented and used by the server only, AES-256-GCM per field.
 */
export interface LinkSecretStore {
  /** Tokens from a provider exchange, held under the transaction until activation. Replaces any earlier staged set for the tid. */
  putStaged(tid: TransactionId, tokens: LinkTokenSet): Promise<void>;
  getStaged(tid: TransactionId): Promise<LinkTokenSet | null>;
  deleteStaged(tid: TransactionId): Promise<void>;
  /**
   * Move the staged set to the connection, replacing its tokens. If the
   * staged set has no refresh_token, the connection's existing refresh_token
   * is kept. Returns false if nothing was staged.
   */
  commitStaged(tid: TransactionId, connection_id: ConnectionId): Promise<boolean>;
  get(connection_id: ConnectionId): Promise<LinkTokenSet | null>;
  /** Write rotated tokens after a refresh. */
  put(connection_id: ConnectionId, tokens: LinkTokenSet): Promise<void>;
  delete(connection_id: ConnectionId): Promise<void>;
}

// ════════════════════════════════════════════════════════════════════════════
// 7. Policy ports and hooks
// ════════════════════════════════════════════════════════════════════════════

/**
 * Structural mirror of @credninja/vault's Permission (packages/vault/src/
 * types.ts). For Link connections, connectionId is the conn_ id (legacy
 * rows use the provider slug). Keep in sync by hand.
 */
export interface LinkPermission {
  id: string;
  agentId: string;
  connectionId: string;
  allowedScopes: string[];
  rateLimit?: { maxRequests: number; windowMs: number };
  ttlOverride?: number;
  requiresApproval: boolean;
  delegatable: boolean;
  maxDelegationDepth: number;
  createdAt: Date;
  updatedAt: string;
  expiresAt?: Date;
  createdBy: string;
}

/** Mirror of vault's CreatePermissionInput (packages/vault/src/permissions.ts). */
export interface LinkCreatePermissionInput {
  agentId: string;
  connectionId: string;
  allowedScopes: string[];
  rateLimit?: { maxRequests: number; windowMs: number };
  ttlOverride?: number;
  requiresApproval: boolean;
  delegatable: boolean;
  maxDelegationDepth: number;
  expiresAt?: Date;
  createdBy: string;
}

/** Mirror of vault's UpdatePermissionInput. */
export type LinkUpdatePermissionInput = Partial<
  Omit<LinkPermission, 'id' | 'agentId' | 'connectionId' | 'createdBy' | 'createdAt' | 'updatedAt'>
>;

/**
 * The subset of vault's PermissionStore that exists today. An instance of
 * @credninja/vault PermissionStore is assignable to this interface as is.
 */
export interface PermissionPort {
  get(agentId: string, connectionId: string): Promise<LinkPermission | null>;
  list(agentId: string): Promise<LinkPermission[]>;
  create(input: LinkCreatePermissionInput): Promise<LinkPermission>;
  update(id: string, input: LinkUpdatePermissionInput): Promise<LinkPermission>;
  revoke(permissionId: string): Promise<void>;
}

/**
 * What Link policy code needs. The two extra methods do not exist in
 * vault yet; the guard hooks adds them to vault's PermissionStore (and its
 * StorageBackend) so the vault store satisfies this interface.
 */
export interface LinkPermissionPort extends PermissionPort {
  /** All permissions on one connection, any agent. */
  listForConnection(connectionId: string): Promise<LinkPermission[]>;
  /**
   * Set every permission on the connection to allowedScopes ∩ scopes
   * (canonical comparison), atomically. Returns the rows that changed.
   */
  intersectForConnection(connectionId: string, scopes: readonly string[]): Promise<LinkPermission[]>;
}

/** Values Link writes on every Permission it creates (spec 3). */
export const LINK_PERMISSION_DEFAULTS = Object.freeze({
  delegatable: false,
  maxDelegationDepth: 0,
  requiresApproval: false,
} as const);

/** onActivate input. The server builds it from commitActivation's result. */
export interface LinkActivateHookInput {
  intent: LinkIntent;
  connection: Connection;
  /** The grant after activation. */
  grant: ClientGrant;
  /** From the PAR request; null when none. */
  agent_id: string | null;
  tid: TransactionId;
  /** Permission.createdBy for seeded rows, e.g. `link:<client_id>`. */
  actor: string;
}

/** onGrantUpdated input. */
export interface LinkGrantUpdatedHookInput {
  /** The grant after the change. */
  grant: ClientGrant;
  previous_scopes: string[];
  reason: 'activate' | 'provider_scope_changed' | 'narrow';
}

/** checkLinkAccess input (spec 4 call-time check, spec 6). The server builds it. */
export interface LinkAccessCheckInput {
  operation: 'delegate' | 'use';
  /** As named by the call; may be unknown or malformed. */
  connection_id: string;
  /**
   * The calling agent's verified principal id, in the same id space as
   * Permission.agentId. null when the request carries no agent identity.
   */
  agent_id: string | null;
  /** The `service` the call names, if any; must equal connection.provider. */
  provider?: string;
  /** Scopes the call asks for. Empty means "everything this agent may use". */
  requested_scopes: string[];
  /** use only: carried by the brokered handle minted at delegate time. */
  grant_id?: string;
  grant_version?: number;
  /** ISO-8601 UTC. */
  now: string;
}

/** checkLinkAccess result. */
export type LinkAccessResult =
  | {
      ok: true;
      connection: Connection;
      grant: ClientGrant;
      permission: LinkPermission;
      /** Canonical scopes the call may exercise: requested (or all) ∩ grant.scopes ∩ permission.allowedScopes. */
      effective_scopes: string[];
    }
  | {
      ok: false;
      code: LinkMachineErrorCode;
      /** LINK_MACHINE_ERROR_STATUS[code]. */
      status: number;
      /** For insufficient_scope and permission_required: the scopes that were not covered. */
      missing_scopes?: string[];
    };

/** setAgentPermission input (POST .../permissions). */
export interface LinkSetAgentPermissionInput {
  client_id: string;
  connection_id: ConnectionId;
  agent_id: string;
  scopes: string[];
  /** Permission.createdBy, e.g. `link:<client_id>`. */
  actor: string;
}

/** setAgentPermission result. */
export type LinkSetAgentPermissionResult =
  | { ok: true; permission: LinkPermission }
  | { ok: false; error: 'invalid_scope' | LinkMachineErrorCode; status: number };

/**
 * The policy code the server calls but does not own (spec 3, 4, 6).
 * Implemented by the guard hooks over a LinkStore and a LinkPermissionPort.
 * Called by the server.
 *
 * Call order on activation: commitActivation, then onGrantUpdated (only
 * when previous_grant_scopes is non-null and differs), then onActivate.
 * If a hook throws, the server answers server_error; the connection stays
 * active, which is safe because access is deny-by-default per agent and
 * checkLinkAccess re-checks Permission ⊆ grant at call time.
 */
export interface LinkHooks {
  /**
   * When agent_id is set: upsert that agent's Permission on the connection
   * with allowedScopes = grant.scopes and LINK_PERMISSION_DEFAULTS. No-op
   * otherwise.
   */
  onActivate(input: LinkActivateHookInput): Promise<void>;
  /** Intersect every Permission on the grant's connection with grant.scopes. */
  onGrantUpdated(input: LinkGrantUpdatedHookInput): Promise<void>;
  /**
   * The enforcement check for /api/v1/delegate and /api/v1/use calls that
   * name a Link connection, run whether or not a Guard is configured.
   * In order:
   *   requested_scopes with a blank entry           -> permission_required (malformed, never "everything")
   *   unknown connection or provider mismatch       -> permission_required
   *   connection's client unknown or not active     -> grant_revoked
   *   connection status not active                  -> status_reason, else LINK_MACHINE_CODE_FOR_CONNECTION_STATUS
   *   grant missing                                 -> grant_revoked
   *   grant status not active, or expires_at passed -> LINK_MACHINE_CODE_FOR_GRANT_STATUS (expired -> grant_expired)
   *   use: grant_id differs                         -> grant_revoked
   *   agent_id null, no Permission, or expired      -> permission_required
   *   requested scope outside grant.scopes          -> insufficient_scope (missing_scopes)
   *   requested scope outside permission            -> permission_required (missing_scopes)
   * grant_version is informational: a stale version passes when the
   * current grant and permission still cover the scopes. Handles carry no
   * provider token and this check runs on every call, so status, scopes and
   * permission are always current; requiring a version match would only
   * break outstanding handles each time a grant is widened.
   */
  checkLinkAccess(input: LinkAccessCheckInput): Promise<LinkAccessResult>;
  /** POST .../permissions: upsert with scopes ⊆ grant.scopes; grant must be active. */
  setAgentPermission(input: LinkSetAgentPermissionInput): Promise<LinkSetAgentPermissionResult>;
}

/** How the server obtains LinkHooks from the guard hooks. */
export type LinkHooksFactory = (deps: { store: LinkStore; permissions: LinkPermissionPort }) => LinkHooks;

// ════════════════════════════════════════════════════════════════════════════
// 8. Pure helpers: envelope
// ════════════════════════════════════════════════════════════════════════════

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

/** base64url (no padding) of an ASCII string. Throws on non-ASCII input. */
function asciiToBase64Url(input: string): string {
  let out = '';
  let i = 0;
  const byteAt = (k: number): number => {
    const c = input.charCodeAt(k);
    if (c > 0x7f) throw new TypeError('asciiToBase64Url: non-ASCII input');
    return c;
  };
  for (; i + 2 < input.length; i += 3) {
    const n = (byteAt(i) << 16) | (byteAt(i + 1) << 8) | byteAt(i + 2);
    out += B64URL_ALPHABET[(n >> 18) & 63] + B64URL_ALPHABET[(n >> 12) & 63]
      + B64URL_ALPHABET[(n >> 6) & 63] + B64URL_ALPHABET[n & 63];
  }
  const rest = input.length - i;
  if (rest === 1) {
    const n = byteAt(i) << 16;
    out += B64URL_ALPHABET[(n >> 18) & 63] + B64URL_ALPHABET[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (byteAt(i) << 16) | (byteAt(i + 1) << 8);
    out += B64URL_ALPHABET[(n >> 18) & 63] + B64URL_ALPHABET[(n >> 12) & 63] + B64URL_ALPHABET[(n >> 6) & 63];
  }
  return out;
}

/** Decode base64url (no padding) to a printable-ASCII string, or null. */
function base64UrlToPrintableAscii(input: string): string | null {
  if (!B64URL_PATTERN.test(input) || input.length % 4 === 1) return null;
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < input.length; i++) {
    buffer = (buffer << 6) | B64URL_ALPHABET.indexOf(input[i]);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      const byte = (buffer >> bits) & 0xff;
      if (byte < 0x20 || byte > 0x7e) return null;
      out += String.fromCharCode(byte);
    }
    buffer &= (1 << bits) - 1;
  }
  return out;
}

function isValidEnvelopeFields(env: { h: unknown; tid: unknown; cid: unknown }): env is LinkEnvelope {
  return isLinkHandle(env.h) && isTransactionId(env.tid) && isLinkClientId(env.cid);
}

/**
 * Encode an envelope: base64url of the JSON {"h","tid","cid"} in that key
 * order (spec 2). Throws TypeError on invalid fields (a server bug).
 * Used by the server.
 */
export function encodeLinkEnvelope(envelope: LinkEnvelope): string {
  if (!isValidEnvelopeFields(envelope)) {
    throw new TypeError('encodeLinkEnvelope: invalid envelope fields');
  }
  return asciiToBase64Url(JSON.stringify({ h: envelope.h, tid: envelope.tid, cid: envelope.cid }));
}

/**
 * Decode an envelope from untrusted input. Returns null, never throws, on
 * anything malformed: wrong type, too long, not canonical base64url, not
 * printable ASCII, not JSON, extra or missing keys, invalid field formats,
 * or any encoding other than the one encodeLinkEnvelope produces (the
 * decoded value is re-encoded and must match byte for byte, which rules out
 * duplicate keys, whitespace and reordered keys). Used by the server.
 */
export function decodeLinkEnvelope(input: unknown): LinkEnvelope | null {
  if (typeof input !== 'string' || input.length === 0 || input.length > LINK_ENVELOPE_MAX_LENGTH) return null;
  const json = base64UrlToPrintableAscii(input);
  if (json === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) return null;
  const keys = Object.keys(parsed);
  if (keys.length !== 3 || !hasOwn(parsed, 'h') || !hasOwn(parsed, 'tid') || !hasOwn(parsed, 'cid')) return null;
  const candidate = { h: parsed.h, tid: parsed.tid, cid: parsed.cid };
  if (!isValidEnvelopeFields(candidate)) return null;
  const envelope: LinkEnvelope = { h: candidate.h, tid: candidate.tid, cid: candidate.cid };
  return encodeLinkEnvelope(envelope) === input ? envelope : null;
}

// ════════════════════════════════════════════════════════════════════════════
// 9. Pure helpers: query strings, theme, messages, redirect results
// ════════════════════════════════════════════════════════════════════════════

/** Parsed query: every value for every key, in order. */
type QueryValues = Map<string, string[]>;

function parseQueryString(query: string): QueryValues | null {
  const s = query.startsWith('?') ? query.slice(1) : query;
  const out: QueryValues = new Map();
  if (s === '') return out;
  for (const part of s.split('&')) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    const rawKey = eq === -1 ? part : part.slice(0, eq);
    const rawValue = eq === -1 ? '' : part.slice(eq + 1);
    let key: string;
    let value: string;
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
      value = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    } catch {
      return null;
    }
    const list = out.get(key);
    if (list) list.push(value);
    else out.set(key, [value]);
  }
  return out;
}

function queryFromInput(input: string | Record<string, unknown>): QueryValues | null {
  if (typeof input === 'string') return parseQueryString(input);
  if (!isPlainObject(input)) return null;
  const out: QueryValues = new Map();
  for (const key of Object.keys(input)) {
    const v = input[key];
    if (v === undefined) continue;
    if (typeof v === 'string') out.set(key, [v]);
    else if (Array.isArray(v) && v.every((x) => typeof x === 'string')) out.set(key, [...(v as string[])]);
    else return null;
  }
  return out;
}

/** The single value of `key`; undefined if absent; null if repeated. */
function single(q: QueryValues, key: string): string | undefined | null {
  const list = q.get(key);
  if (!list || list.length === 0) return undefined;
  return list.length === 1 ? list[0] : null;
}

function buildQueryString(pairs: Array<[string, string | undefined]>): string {
  return pairs
    .filter((p): p is [string, string] => typeof p[1] === 'string')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

/** Validation rules for theme fields. Hosted pages must still escape on render. */
export const LINK_THEME_LIMITS = {
  appNameMaxLength: 64,
  logoUrlMaxLength: 2048,
  /** #rgb or #rrggbb. */
  accentPattern: /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/,
  radiusMax: 24,
  /** One family name, letters digits spaces hyphens; the page appends fallbacks. */
  fontPattern: /^[A-Za-z0-9][A-Za-z0-9 -]{0,63}$/,
} as const;

/**
 * Keep only valid theme fields from untrusted input (the theme is
 * cosmetic, so invalid fields are dropped rather than failing the flow).
 * logoUrl must be https. The server (authorize), the widget (props).
 */
export function sanitizeLinkTheme(input: unknown): LinkTheme {
  const out: LinkTheme = {};
  if (!isPlainObject(input)) return out;
  const { appName, logoUrl, accent, radius, font, colorScheme } = input;
  if (typeof appName === 'string' && appName.trim() !== '' && appName.length <= LINK_THEME_LIMITS.appNameMaxLength
    && isSafeDisplayName(appName)) {
    out.appName = appName.trim().normalize('NFC');
  }
  if (typeof logoUrl === 'string' && logoUrl.length <= LINK_THEME_LIMITS.logoUrlMaxLength
    && /^https:\/\/[^\s"'<>\\]+$/.test(logoUrl)) {
    out.logoUrl = logoUrl;
  }
  if (typeof accent === 'string' && LINK_THEME_LIMITS.accentPattern.test(accent)) out.accent = accent;
  if (typeof radius === 'number' && Number.isInteger(radius) && radius >= 0 && radius <= LINK_THEME_LIMITS.radiusMax) {
    out.radius = radius;
  }
  if (typeof font === 'string' && LINK_THEME_LIMITS.fontPattern.test(font)) out.font = font;
  if (colorScheme === 'light' || colorScheme === 'dark' || colorScheme === 'auto') out.colorScheme = colorScheme;
  return out;
}

/**
 * The cosmetic subset of a theme: everything except appName and logoUrl.
 * Used for anything the browser supplies (authorize query, widget props),
 * so a page cannot relabel which app is asking for consent. The server,
 * the widget.
 */
export function sanitizeLinkCosmeticTheme(input: unknown): LinkTheme {
  const { appName: _appName, logoUrl: _logoUrl, ...cosmetic } = sanitizeLinkTheme(input);
  void _appName;
  void _logoUrl;
  return cosmetic;
}

function parseScopeMapJson(raw: string): LinkScopeMap | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) return null;
  const out: LinkScopeMap = {};
  for (const key of Object.keys(parsed)) {
    if (!isLinkProviderSlug(key)) return null;
    const list = parsed[key];
    if (!Array.isArray(list) || !list.every((s) => typeof s === 'string' && s.trim() !== '')) return null;
    out[key] = canonicalScopeSet(list as string[]);
  }
  return out;
}

/**
 * Build the GET /link/v1/authorize query string (no leading '?').
 * Used by the widget.
 */
export function buildLinkAuthorizeQuery(query: LinkAuthorizeQuery): string {
  const P = LINK_AUTHORIZE_PARAMS;
  const theme = query.theme ? sanitizeLinkCosmeticTheme(query.theme) : {};
  return buildQueryString([
    [P.request_uri, query.request_uri],
    [P.client_id, query.client_id],
    [P.mode, query.mode],
    [P.providers, query.providers && query.providers.length > 0 ? query.providers.join(',') : undefined],
    [P.scopes, query.scopes ? JSON.stringify(query.scopes) : undefined],
    [P.accent, theme.accent],
    [P.radius, theme.radius !== undefined ? String(theme.radius) : undefined],
    [P.font, theme.font],
    [P.color_scheme, theme.colorScheme],
  ]);
}

/**
 * Parse an authorize query from a raw query string or an already-parsed
 * object (Express req.query). Returns null when a security-relevant
 * parameter is malformed or repeated: request_uri, client_id, mode,
 * providers, scopes. Theme parameters are sanitized and dropped if invalid.
 * Narrowing is returned as given (canonicalized); the server intersects it
 * with the pushed values. Used by the server.
 */
export function parseLinkAuthorizeQuery(input: string | Record<string, unknown>): LinkAuthorizeQuery | null {
  const q = queryFromInput(input);
  if (!q) return null;
  const P = LINK_AUTHORIZE_PARAMS;

  const requestUri = single(q, P.request_uri);
  if (!isLinkRequestUri(requestUri)) return null;
  const result: LinkAuthorizeQuery = { request_uri: requestUri, mode: LINK_DEFAULT_WIDGET_MODE };

  const clientId = single(q, P.client_id);
  if (clientId === null) return null;
  if (clientId !== undefined) {
    if (!isLinkClientId(clientId)) return null;
    result.client_id = clientId;
  }

  const mode = single(q, P.mode);
  if (mode === null) return null;
  if (mode !== undefined) {
    if (!isLinkWidgetMode(mode)) return null;
    result.mode = mode;
  }

  const providers = single(q, P.providers);
  if (providers === null) return null;
  if (providers !== undefined) {
    const list = providers.split(',');
    if (list.length === 0 || !list.every(isLinkProviderSlug)) return null;
    result.providers = Array.from(new Set(list as LinkProviderSlug[]));
  }

  const scopes = single(q, P.scopes);
  if (scopes === null) return null;
  if (scopes !== undefined) {
    const map = parseScopeMapJson(scopes);
    if (!map) return null;
    result.scopes = map;
  }

  const radiusRaw = single(q, P.radius);
  const theme = sanitizeLinkCosmeticTheme({
    accent: single(q, P.accent) ?? undefined,
    radius: typeof radiusRaw === 'string' && /^\d{1,2}$/.test(radiusRaw) ? Number(radiusRaw) : undefined,
    font: single(q, P.font) ?? undefined,
    colorScheme: single(q, P.color_scheme) ?? undefined,
  });
  if (Object.keys(theme).length > 0) result.theme = theme;
  return result;
}

function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === 'string';
}

function isScopeArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((s) => typeof s === 'string');
}

function parseLinkResultFields(data: Record<string, unknown>): LinkResult | null {
  const state = data.state;
  if (!isOptionalString(state)) return null;
  switch (data.outcome) {
    case 'success': {
      const { connection_id, code, grant_id, provider, scopes } = data;
      if (!isConnectionId(connection_id) || !isLinkActivationCode(code) || !isGrantId(grant_id)
        || !isLinkProviderSlug(provider) || !isScopeArray(scopes)) return null;
      const r: LinkResult = { outcome: 'success', connection_id, code, grant_id, provider, scopes: [...scopes] };
      if (state !== undefined) r.state = state;
      return r;
    }
    case 'error': {
      const { error, request_id } = data;
      if (!isLinkErrorCode(error) || typeof request_id !== 'string' || request_id === '') return null;
      const r: LinkResult = { outcome: 'error', error, request_id };
      if (state !== undefined) r.state = state;
      return r;
    }
    case 'exit': {
      const { step, provider } = data;
      if (!includesValue(LINK_EXIT_STEPS, step)) return null;
      if (provider !== undefined && !isLinkProviderSlug(provider)) return null;
      const r: LinkResult = { outcome: 'exit', step };
      if (provider !== undefined) r.provider = provider;
      if (state !== undefined) r.state = state;
      return r;
    }
    default:
      return null;
  }
}

/**
 * Validate a postMessage payload from untrusted `event.data`. Returns a
 * fresh object with only the known fields, or null. Origin and source
 * checks are the caller's job. The widget (and the server tests).
 */
export function parseLinkMessage(data: unknown): LinkMessage | null {
  if (!isPlainObject(data) || data.v !== LINK_MESSAGE_VERSION) return null;
  switch (data.type) {
    case LINK_MESSAGE_TYPES.result: {
      const result = parseLinkResultFields(data);
      return result ? { type: 'cred.link.result', v: 1, ...result } : null;
    }
    case LINK_MESSAGE_TYPES.step: {
      const { step, provider } = data;
      if (!includesValue(LINK_EXIT_STEPS, step)) return null;
      if (provider !== undefined && !isLinkProviderSlug(provider)) return null;
      const m: LinkStepMessage = { type: 'cred.link.step', v: 1, step };
      if (provider !== undefined) m.provider = provider;
      return m;
    }
    case LINK_MESSAGE_TYPES.resize: {
      const { height } = data;
      if (typeof height !== 'number' || !Number.isFinite(height) || height < 0 || height > 10_000) return null;
      return { type: 'cred.link.resize', v: 1, height };
    }
    default:
      return null;
  }
}

/** Build a cred.link.result message from a result. Used by the server. */
export function linkResultMessage(result: LinkResult): LinkResultMessage {
  return { type: 'cred.link.result', v: 1, ...result };
}

/**
 * Encode a result as redirect-mode query parameters (no leading '?').
 * Used by the server.
 */
export function encodeLinkRedirectResult(result: LinkResult): string {
  const P = LINK_REDIRECT_PARAMS;
  switch (result.outcome) {
    case 'success':
      return buildQueryString([
        [P.outcome, 'success'],
        [P.connection_id, result.connection_id],
        [P.code, result.code],
        [P.grant_id, result.grant_id],
        [P.provider, result.provider],
        [P.scope, result.scopes.join(' ')],
        [P.state, result.state],
      ]);
    case 'error':
      return buildQueryString([
        [P.outcome, 'error'],
        [P.error, result.error],
        [P.request_id, result.request_id],
        [P.state, result.state],
      ]);
    case 'exit':
      return buildQueryString([
        [P.outcome, 'exit'],
        [P.step, result.step],
        [P.provider, result.provider],
        [P.state, result.state],
      ]);
  }
}

/**
 * Append a redirect-mode result to a registered redirect_uri. Throws if the
 * redirect_uri has a fragment (registration must reject those). Used by the server.
 */
export function appendLinkRedirectResult(redirect_uri: string, result: LinkResult): string {
  if (redirect_uri.includes('#')) throw new TypeError('appendLinkRedirectResult: redirect_uri has a fragment');
  const sep = redirect_uri.includes('?') ? (redirect_uri.endsWith('?') || redirect_uri.endsWith('&') ? '' : '&') : '?';
  return `${redirect_uri}${sep}${encodeLinkRedirectResult(result)}`;
}

/**
 * Parse a redirect-mode result from a query string (with or without '?')
 * or a parsed query object. Returns null when `cred_link` is absent or any
 * Link parameter is malformed or repeated; other parameters (the
 * developer's own) are ignored. The widget, developer backends.
 */
export function parseLinkRedirectResult(input: string | Record<string, unknown>): LinkResult | null {
  const q = queryFromInput(input);
  if (!q) return null;
  const P = LINK_REDIRECT_PARAMS;
  const fields: Record<string, unknown> = {};
  for (const key of Object.values(P)) {
    const v = single(q, key);
    if (v === null) return null;
    if (v !== undefined) fields[key] = v;
  }
  const outcome = fields[P.outcome];
  if (outcome === 'success') {
    const scope = fields[P.scope];
    if (typeof scope !== 'string') return null;
    fields.scopes = scope === '' ? [] : scope.split(' ');
    if ((fields.scopes as string[]).some((s) => s === '')) return null;
  }
  return parseLinkResultFields({ ...fields, outcome });
}
