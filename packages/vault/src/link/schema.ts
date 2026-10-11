import type {
  ClientGrant,
  Connection,
  ConnectionId,
  GrantId,
  LinkClient,
  LinkConnectionStatus,
  LinkCustody,
  LinkErrorCode,
  LinkGrantStatus,
  LinkIntent,
  LinkJwk,
  LinkMachineErrorCode,
  LinkOrgPolicyUsage,
  LinkProviderSlug,
  LinkScopeMap,
  LinkStep,
  LinkSubjectType,
  LinkTheme,
  LinkTransaction,
  LinkTransactionOutcome,
  LinkWidgetMode,
  OrgId,
  TransactionId,
} from '@credninja/protocol';

/**
 * Schema version stored in PRAGMA user_version of the Link database file.
 * Version 1 is the first shipped layout (LINK_SCHEMA_SQL below). A later
 * layout bumps this number and adds a step to SqliteLinkStore.migrate().
 */
export const LINK_SCHEMA_VERSION = 1;

/**
 * Link storage schema (SQLite). Its own database file, separate from the
 * vault's. Every statement is idempotent. JSON columns hold arrays or
 * objects written by this store only. Scope arrays are canonical
 * (canonicalScopeSet). Timestamps are ISO-8601 UTC strings in the fixed
 * `toISOString()` form, so lexicographic comparison is time order.
 */
export const LINK_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS link_clients (
    client_id                  TEXT PRIMARY KEY,
    org_id                     TEXT NOT NULL,
    name                       TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL
      CHECK (token_endpoint_auth_method IN ('private_key_jwt', 'client_secret_basic')),
    client_secret_hash         TEXT,
    jwks_json                  TEXT,
    redirect_uris_json         TEXT NOT NULL,
    origins_json               TEXT NOT NULL,
    theme_json                 TEXT,
    allow_raw_tokens           INTEGER NOT NULL DEFAULT 0,
    status                     TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS link_connections (
    id                   TEXT PRIMARY KEY,
    org_id               TEXT NOT NULL,
    client_id            TEXT NOT NULL,
    provider             TEXT NOT NULL,
    audience             TEXT NOT NULL,
    subject              TEXT NOT NULL,
    subject_type         TEXT NOT NULL CHECK (subject_type IN ('user', 'client')),
    provider_account_id  TEXT NOT NULL,
    account_label        TEXT,
    provider_scopes_json TEXT NOT NULL,
    instance_url         TEXT,
    status               TEXT NOT NULL
      CHECK (status IN ('pending', 'active', 'needs_reauth', 'frozen', 'revoked')),
    status_reason        TEXT,
    custody              TEXT NOT NULL CHECK (custody IN ('hosted', 'self')),
    version              INTEGER NOT NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_link_connections_live_key
    ON link_connections(client_id, audience, subject, provider_account_id)
    WHERE status NOT IN ('pending', 'revoked');
  CREATE INDEX IF NOT EXISTS idx_link_connections_subject
    ON link_connections(client_id, subject, created_at);
  CREATE INDEX IF NOT EXISTS idx_link_connections_account
    ON link_connections(provider, provider_account_id);

  CREATE TABLE IF NOT EXISTS link_grants (
    id                               TEXT PRIMARY KEY,
    org_id                           TEXT NOT NULL,
    client_id                        TEXT NOT NULL,
    audience                         TEXT NOT NULL,
    subject                          TEXT NOT NULL,
    subject_type                     TEXT NOT NULL CHECK (subject_type IN ('user', 'client')),
    scopes_json                      TEXT NOT NULL,
    org_policy_json                  TEXT NOT NULL,
    authorization_details_types_json TEXT NOT NULL,
    connection_id                    TEXT NOT NULL UNIQUE REFERENCES link_connections(id),
    status                           TEXT NOT NULL
      CHECK (status IN ('pending', 'active', 'needs_reauth', 'revoked', 'expired')),
    version                          INTEGER NOT NULL,
    granted_at                       TEXT NOT NULL,
    updated_at                       TEXT NOT NULL,
    expires_at                       TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_link_grants_lookup
    ON link_grants(client_id, audience, subject);

  CREATE TABLE IF NOT EXISTS link_transactions (
    tid                            TEXT PRIMARY KEY,
    org_id                         TEXT NOT NULL,
    client_id                      TEXT NOT NULL,
    intent                         TEXT NOT NULL CHECK (intent IN ('connect', 'update', 'reauth')),
    subject                        TEXT NOT NULL,
    subject_type                   TEXT NOT NULL CHECK (subject_type IN ('user', 'client')),
    providers_json                 TEXT NOT NULL,
    requested_scopes_json          TEXT NOT NULL,
    required_scopes_json           TEXT NOT NULL,
    authorization_details_json     TEXT NOT NULL,
    redirect_uri                   TEXT NOT NULL,
    origin                         TEXT NOT NULL,
    client_state                   TEXT,
    agent_id                       TEXT,
    connection_id                  TEXT,
    grant_id                       TEXT,
    creates_connection             INTEGER,
    mode                           TEXT,
    theme_json                     TEXT,
    request_uri_hash               TEXT NOT NULL,
    request_uri_consumed_at        TEXT,
    handle_hash                    TEXT,
    binding_cookie_hash            TEXT,
    step                           TEXT NOT NULL CHECK (step IN ('picker', 'provider', 'confirm', 'done')),
    provider                       TEXT,
    selected_scopes_json           TEXT,
    provider_requested_scopes_json TEXT,
    pkce_verifier                  TEXT,
    provider_attempt               INTEGER NOT NULL DEFAULT 0,
    exchanged_at                   TEXT,
    provider_granted_scopes_json   TEXT,
    provider_account_id            TEXT,
    account_label                  TEXT,
    instance_url                   TEXT,
    confirmed_at                   TEXT,
    confirmed_scopes_json          TEXT,
    activation_code_hash           TEXT,
    activation_claimed_at          TEXT,
    activated_at                   TEXT,
    created_at                     TEXT NOT NULL,
    updated_at                     TEXT NOT NULL,
    expires_at                     TEXT NOT NULL,
    consumed_at                    TEXT,
    outcome                        TEXT
      CHECK (outcome IS NULL OR outcome IN ('activated', 'failed', 'cancelled', 'expired')),
    error                          TEXT
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_link_transactions_request_uri
    ON link_transactions(request_uri_hash);
  CREATE INDEX IF NOT EXISTS idx_link_transactions_activation
    ON link_transactions(connection_id, activation_code_hash);
  CREATE INDEX IF NOT EXISTS idx_link_transactions_open_expiry
    ON link_transactions(expires_at) WHERE consumed_at IS NULL;
  CREATE INDEX IF NOT EXISTS idx_link_transactions_open_account
    ON link_transactions(provider, provider_account_id) WHERE consumed_at IS NULL;
`;

// ── Row shapes (exactly the columns above) ──────────────────────────────────

export interface ClientRow {
  client_id: string;
  org_id: string;
  name: string;
  token_endpoint_auth_method: 'private_key_jwt' | 'client_secret_basic';
  client_secret_hash: string | null;
  jwks_json: string | null;
  redirect_uris_json: string;
  origins_json: string;
  theme_json: string | null;
  allow_raw_tokens: number;
  status: 'active' | 'disabled';
  created_at: string;
  updated_at: string;
}

export interface ConnectionRow {
  id: string;
  org_id: string;
  client_id: string;
  provider: string;
  audience: string;
  subject: string;
  subject_type: string;
  provider_account_id: string;
  account_label: string | null;
  provider_scopes_json: string;
  instance_url: string | null;
  status: string;
  status_reason: string | null;
  custody: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface GrantRow {
  id: string;
  org_id: string;
  client_id: string;
  audience: string;
  subject: string;
  subject_type: string;
  scopes_json: string;
  org_policy_json: string;
  authorization_details_types_json: string;
  connection_id: string;
  status: string;
  version: number;
  granted_at: string;
  updated_at: string;
  expires_at: string | null;
}

export interface TransactionRow {
  tid: string;
  org_id: string;
  client_id: string;
  intent: string;
  subject: string;
  subject_type: string;
  providers_json: string;
  requested_scopes_json: string;
  required_scopes_json: string;
  authorization_details_json: string;
  redirect_uri: string;
  origin: string;
  client_state: string | null;
  agent_id: string | null;
  connection_id: string | null;
  grant_id: string | null;
  creates_connection: number | null;
  mode: string | null;
  theme_json: string | null;
  request_uri_hash: string;
  request_uri_consumed_at: string | null;
  handle_hash: string | null;
  binding_cookie_hash: string | null;
  step: string;
  provider: string | null;
  selected_scopes_json: string | null;
  provider_requested_scopes_json: string | null;
  pkce_verifier: string | null;
  provider_attempt: number;
  exchanged_at: string | null;
  provider_granted_scopes_json: string | null;
  provider_account_id: string | null;
  account_label: string | null;
  instance_url: string | null;
  confirmed_at: string | null;
  confirmed_scopes_json: string | null;
  activation_code_hash: string | null;
  activation_claimed_at: string | null;
  activated_at: string | null;
  created_at: string;
  updated_at: string;
  expires_at: string;
  consumed_at: string | null;
  outcome: string | null;
  error: string | null;
}

// ── Row to record ───────────────────────────────────────────────────────────

function json<T>(text: string): T {
  return JSON.parse(text) as T;
}

/** Copies `value` onto `target[key]` only when it is not null, so optional fields stay absent. */
function setOpt<T extends object, K extends keyof T>(target: T, key: K, value: T[K] | null): void {
  if (value !== null && value !== undefined) target[key] = value;
}

export function rowToClient(row: ClientRow): LinkClient {
  const base = {
    client_id: row.client_id,
    org_id: row.org_id as OrgId,
    name: row.name,
    redirect_uris: json<string[]>(row.redirect_uris_json),
    origins: json<string[]>(row.origins_json),
    allow_raw_tokens: row.allow_raw_tokens === 1,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
  const theme = row.theme_json === null ? undefined : json<LinkTheme>(row.theme_json);
  if (row.token_endpoint_auth_method === 'private_key_jwt') {
    const client: LinkClient = {
      ...base,
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: json<{ keys: LinkJwk[] }>(row.jwks_json ?? '{"keys":[]}'),
    };
    if (theme) client.theme = theme;
    return client;
  }
  const client: LinkClient = {
    ...base,
    token_endpoint_auth_method: 'client_secret_basic',
    client_secret_hash: row.client_secret_hash ?? '',
  };
  if (theme) client.theme = theme;
  return client;
}

export function rowToConnection(row: ConnectionRow): Connection {
  const c: Connection = {
    id: row.id as ConnectionId,
    org_id: row.org_id as OrgId,
    client_id: row.client_id,
    provider: row.provider as LinkProviderSlug,
    audience: row.audience,
    subject: row.subject,
    subject_type: row.subject_type as LinkSubjectType,
    provider_account_id: row.provider_account_id,
    provider_scopes: json<string[]>(row.provider_scopes_json),
    status: row.status as LinkConnectionStatus,
    custody: row.custody as LinkCustody,
    version: row.version,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
  setOpt(c, 'account_label', row.account_label);
  setOpt(c, 'instance_url', row.instance_url);
  setOpt(c, 'status_reason', row.status_reason as LinkMachineErrorCode | null);
  return c;
}

export function rowToGrant(row: GrantRow): ClientGrant {
  const g: ClientGrant = {
    id: row.id as GrantId,
    org_id: row.org_id as OrgId,
    client_id: row.client_id,
    audience: row.audience,
    subject: row.subject,
    subject_type: row.subject_type as LinkSubjectType,
    scopes: json<string[]>(row.scopes_json),
    org_policy: json<{ usage: LinkOrgPolicyUsage }>(row.org_policy_json),
    authorization_details_types: json<string[]>(row.authorization_details_types_json),
    connection_id: row.connection_id as ConnectionId,
    status: row.status as LinkGrantStatus,
    version: row.version,
    granted_at: row.granted_at,
    updated_at: row.updated_at,
  };
  setOpt(g, 'expires_at', row.expires_at);
  return g;
}

export function rowToTransaction(row: TransactionRow): LinkTransaction {
  const t: LinkTransaction = {
    tid: row.tid as TransactionId,
    org_id: row.org_id as OrgId,
    client_id: row.client_id,
    intent: row.intent as LinkIntent,
    subject: row.subject,
    subject_type: row.subject_type as LinkSubjectType,
    providers: json<LinkProviderSlug[]>(row.providers_json),
    requested_scopes: json<LinkScopeMap>(row.requested_scopes_json),
    required_scopes: json<LinkScopeMap>(row.required_scopes_json),
    authorization_details: json<unknown[]>(row.authorization_details_json),
    redirect_uri: row.redirect_uri,
    origin: row.origin,
    request_uri_hash: row.request_uri_hash,
    step: row.step as LinkStep,
    provider_attempt: row.provider_attempt,
    created_at: row.created_at,
    updated_at: row.updated_at,
    expires_at: row.expires_at,
  };
  setOpt(t, 'client_state', row.client_state);
  setOpt(t, 'agent_id', row.agent_id);
  setOpt(t, 'connection_id', row.connection_id as ConnectionId | null);
  setOpt(t, 'grant_id', row.grant_id as GrantId | null);
  if (row.creates_connection !== null) t.creates_connection = row.creates_connection === 1;
  setOpt(t, 'mode', row.mode as LinkWidgetMode | null);
  if (row.theme_json !== null) t.theme = json<LinkTheme>(row.theme_json);
  setOpt(t, 'request_uri_consumed_at', row.request_uri_consumed_at);
  setOpt(t, 'handle_hash', row.handle_hash);
  setOpt(t, 'binding_cookie_hash', row.binding_cookie_hash);
  setOpt(t, 'provider', row.provider as LinkProviderSlug | null);
  if (row.selected_scopes_json !== null) t.selected_scopes = json<string[]>(row.selected_scopes_json);
  if (row.provider_requested_scopes_json !== null) {
    t.provider_requested_scopes = json<string[]>(row.provider_requested_scopes_json);
  }
  setOpt(t, 'pkce_verifier', row.pkce_verifier);
  setOpt(t, 'exchanged_at', row.exchanged_at);
  if (row.provider_granted_scopes_json !== null) {
    t.provider_granted_scopes = json<string[]>(row.provider_granted_scopes_json);
  }
  setOpt(t, 'provider_account_id', row.provider_account_id);
  setOpt(t, 'account_label', row.account_label);
  setOpt(t, 'instance_url', row.instance_url);
  setOpt(t, 'confirmed_at', row.confirmed_at);
  if (row.confirmed_scopes_json !== null) t.confirmed_scopes = json<string[]>(row.confirmed_scopes_json);
  setOpt(t, 'activation_code_hash', row.activation_code_hash);
  setOpt(t, 'activation_claimed_at', row.activation_claimed_at);
  setOpt(t, 'activated_at', row.activated_at);
  setOpt(t, 'consumed_at', row.consumed_at);
  setOpt(t, 'outcome', row.outcome as LinkTransactionOutcome | null);
  setOpt(t, 'error', row.error as LinkErrorCode | null);
  return t;
}
