/**
 * The Link schema exactly as the Phase 1 build created it (user_version 1),
 * copied verbatim from LINK_SCHEMA_SQL in the staged Phase 1 copy of
 * packages/vault/src/link/schema.ts (`git show :packages/vault/src/link/schema.ts`).
 * Used only to build genuine version 1 files for the upgrade tests.
 */
export const LINK_SCHEMA_V1_SQL = `
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
