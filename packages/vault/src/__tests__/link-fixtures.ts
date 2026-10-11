import { createHash, randomBytes } from 'crypto';
import type {
  ConnectionId,
  GrantId,
  LinkConfirmCommit,
  LinkProviderSlug,
  LinkTransaction,
  NewLinkTransaction,
  TransactionId,
} from '@credninja/protocol';
import type { SqliteLinkStore } from '../link/index.js';

/** Fixed test epoch. The store never reads the clock, so tests drive time with at(). */
export const T0 = Date.parse('2026-10-11T12:00:00.000Z');

export function at(seconds: number): string {
  return new Date(T0 + seconds * 1000).toISOString();
}

/** Stand-in for the server's sha256-hex of a secret. */
export function h(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

export function uid(): string {
  return randomBytes(8).toString('hex');
}

export function newTx(overrides: Partial<NewLinkTransaction> = {}): NewLinkTransaction {
  const id = uid();
  return {
    tid: `ltx_${id}` as TransactionId,
    org_id: 'org_default',
    client_id: 'acme',
    intent: 'connect',
    subject: 'user-123',
    subject_type: 'user',
    providers: ['google', 'slack'],
    requested_scopes: { google: ['calendar.readonly', 'gmail.send', 'https://www.googleapis.com/auth/drive.file'] },
    required_scopes: { google: ['calendar.readonly'] },
    authorization_details: [],
    redirect_uri: 'https://app.example.com/cred/return',
    origin: 'https://app.example.com',
    client_state: 'dev-csrf',
    request_uri_hash: h(`request-uri-${id}`),
    created_at: at(0),
    expires_at: at(600),
    ...overrides,
  };
}

export interface DrivenTx {
  tx: LinkTransaction;
  /** Hash of the currently outstanding handle. */
  handle: string;
  /** Hash of the binding cookie. */
  cookie: string;
}

/**
 * Walks a fresh transaction through authorize, picker and callback to step
 * 'confirm', the way the server would.
 */
export async function driveToConfirm(
  store: SqliteLinkStore,
  input: NewLinkTransaction,
  opts: {
    provider?: LinkProviderSlug;
    granted?: string[];
    accountId?: string;
    now?: number;
  } = {},
): Promise<DrivenTx> {
  const now = opts.now ?? 1;
  const provider = opts.provider ?? 'google';
  await store.createTransaction(input);
  const cookie = h(`cookie-${input.tid}`);
  const h1 = h(`h1-${input.tid}`);
  const entered = await store.enterByRequestUri({
    request_uri_hash: input.request_uri_hash,
    client_id: input.client_id,
    presented_cookie_hash: null,
    new_handle_hash: h1,
    new_binding_cookie_hash: cookie,
    mode: 'popup',
    now: at(now),
  });
  if (entered.kind !== 'fresh') throw new Error(`authorize: ${JSON.stringify(entered)}`);

  const h2 = h(`h2-${input.tid}`);
  const picker = await store.enterByHandle({
    tid: input.tid, client_id: input.client_id, handle_hash: h1, presented_cookie_hash: cookie, new_handle_hash: h2, now: at(now + 1),
  });
  if (picker.kind !== 'fresh') throw new Error(`picker: ${JSON.stringify(picker)}`);
  const toProvider = await store.advanceTransaction({
    tid: input.tid,
    from: 'picker',
    to: 'provider',
    patch: { provider, selected_scopes: ['calendar.readonly'], pkce_verifier: 'verifier-1', provider_attempt: 1 },
    now: at(now + 1),
  });
  if (!toProvider) throw new Error('picker -> provider failed');

  const h3 = h(`h3-${input.tid}`);
  const callback = await store.enterByHandle({
    tid: input.tid, client_id: input.client_id, handle_hash: h2, presented_cookie_hash: cookie, new_handle_hash: h3, now: at(now + 2),
  });
  if (callback.kind !== 'fresh') throw new Error(`callback: ${JSON.stringify(callback)}`);
  const toConfirm = await store.advanceTransaction({
    tid: input.tid,
    from: 'provider',
    to: 'confirm',
    patch: {
      exchanged_at: at(now + 2),
      provider_granted_scopes: opts.granted ?? ['calendar.readonly', 'gmail.send'],
      provider_account_id: opts.accountId ?? 'google-sub-1',
      account_label: 'user@example.com',
      pkce_verifier: null,
    },
    now: at(now + 2),
  });
  if (!toConfirm) throw new Error('provider -> confirm failed');
  return { tx: toConfirm, handle: h3, cookie };
}

export function newIds(): { connection: ConnectionId; grant: GrantId } {
  const id = uid();
  return { connection: `conn_${id}` as ConnectionId, grant: `grt_${id}` as GrantId };
}

export async function confirm(
  store: SqliteLinkStore,
  tid: TransactionId,
  opts: { scopes?: string[]; code?: string; accountId?: string; now?: number; granted?: string[] } = {},
): Promise<LinkConfirmCommit> {
  const ids = newIds();
  const tx = await store.getTransaction(tid);
  return store.commitConfirm({
    tid,
    confirmed_scopes: opts.scopes ?? ['calendar.readonly'],
    activation_code_hash: h(opts.code ?? `code-${tid}`),
    new_connection: {
      id: ids.connection,
      audience: 'https://www.googleapis.com',
      provider_account_id: opts.accountId ?? 'google-sub-1',
      account_label: 'user@example.com',
      // Defaults to the exchange result recorded on the transaction, as the server does.
      provider_scopes: opts.granted ?? tx?.provider_granted_scopes ?? [],
      custody: 'self',
    },
    new_grant: { id: ids.grant, org_policy: { usage: 'allow' }, authorization_details_types: [] },
    now: at(opts.now ?? 10),
  });
}

/** Connect, confirm and activate one connection. Returns the activated transaction's tid and the ids. */
export async function connectActive(
  store: SqliteLinkStore,
  overrides: Partial<NewLinkTransaction> = {},
  opts: { accountId?: string; scopes?: string[]; granted?: string[]; provider?: LinkProviderSlug } = {},
): Promise<{ tid: TransactionId; connection_id: ConnectionId; grant_id: GrantId }> {
  const input = newTx(overrides);
  await driveToConfirm(store, input, { accountId: opts.accountId, granted: opts.granted, provider: opts.provider });
  const c = await confirm(store, input.tid, { accountId: opts.accountId, scopes: opts.scopes, granted: opts.granted });
  if (c.kind !== 'committed') throw new Error(`confirm: ${c.kind}`);
  const claim = await store.claimActivation({
    client_id: input.client_id,
    connection_id: c.transaction.connection_id as string,
    activation_code_hash: h(`code-${input.tid}`),
    subject: input.subject,
    now: at(20),
  });
  if (!claim.ok) throw new Error(`claim: ${claim.reason}`);
  await store.commitActivation({ tid: input.tid, now: at(21) });
  return {
    tid: input.tid,
    connection_id: c.transaction.connection_id as ConnectionId,
    grant_id: c.transaction.grant_id as GrantId,
  };
}
