/**
 * What the audit log may say about an upstream call or refused URL, and how
 * repeats of a refusal are held down.
 *
 * The log must say where a call went without keeping what was in the request:
 * a query string or a path can carry a token, an email address or a customer
 * name. So a route keeps only words known to be part of a provider's API, and
 * every other segment becomes `{id}`. An unknown word costs some detail in the
 * log; a known word cannot leak anything.
 */
import crypto from 'node:crypto';
import type { AuditEvent } from '@credninja/vault';

const MAX_ROUTE_LENGTH = 256;
const MAX_ORIGIN_LENGTH = 128;

/** Recorded instead of an origin that is not a known provider host: a host can carry a secret too. */
export const REFUSED_ORIGIN = 'refused';
const TRUNCATED_SUFFIX = '/...';

const ROUTE_WORDS: ReadonlySet<string> = new Set([
  // Shared
  'api', 'graphql', 'oauth', 'oauth2', 'batch', 'upload', 'search', 'query', 'users', 'user', 'me',
  // GitHub
  'repos', 'orgs', 'issues', 'pulls', 'contents', 'comments', 'commits', 'branches', 'releases', 'gists',
  'notifications', 'rate_limit', 'actions', 'merge', 'labels', 'reviews', 'members', 'teams',
  // Google
  'gmail', 'messages', 'threads', 'drafts', 'send', 'trash', 'untrash', 'modify', 'profile', 'history', 'settings',
  'calendar', 'calendars', 'calendarList', 'events', 'freeBusy', 'colors', 'quickAdd',
  'drive', 'files', 'about', 'export', 'copy', 'permissions', 'changes', 'revisions', 'drives',
  'spreadsheets', 'values', 'documents', 'people', 'connections', 'contactGroups',
  'admin', 'directory', 'groups', 'userinfo',
  // HubSpot
  'crm', 'objects', 'contacts', 'companies', 'deals', 'tickets', 'line_items', 'quotes', 'owners', 'properties',
  'associations', 'schemas', 'cms', 'content', 'automation',
  // Notion
  'pages', 'databases', 'data_sources', 'blocks', 'children',
  // Salesforce
  'services', 'data', 'sobjects', 'describe', 'composite', 'tooling', 'limits', 'parameterizedSearch',
]);

// Slack names its methods in the path, so a shape cannot tell a method from
// an identifier: only names listed here are kept.
const SLACK_METHOD_NAMES: ReadonlySet<string> = new Set([
  'api.test', 'auth.test', 'auth.revoke', 'apps.uninstall',
  'chat.postMessage', 'chat.postEphemeral', 'chat.update', 'chat.delete', 'chat.scheduleMessage',
  'conversations.list', 'conversations.info', 'conversations.history', 'conversations.replies', 'conversations.members',
  'conversations.create', 'conversations.join', 'conversations.invite', 'conversations.leave', 'conversations.open', 'conversations.archive',
  'users.list', 'users.info', 'users.lookupByEmail', 'users.conversations',
  'files.list', 'files.info', 'files.delete', 'files.upload', 'files.getUploadURLExternal', 'files.completeUploadExternal',
  'reactions.add', 'reactions.remove', 'reactions.get', 'search.messages', 'team.info',
]);

function routeSegment(segment: string, slackMethodPosition: boolean): string {
  if (ROUTE_WORDS.has(segment)) return segment;
  // An API version: v1, v60.0.
  if (/^v\d{1,2}(\.\d{1,2})?$/.test(segment)) return segment;
  if (slackMethodPosition && SLACK_METHOD_NAMES.has(segment)) return segment;
  return '{id}';
}

/**
 * The origin and redacted route of a URL, for an audit event. Never the query,
 * fragment or credentials. The origin is recorded only when `isKnownOrigin`
 * says it is a provider host, else the fixed marker; the route is null for
 * what is not an http(s) URL.
 */
export function auditOriginAndRoute(url: string, isKnownOrigin: (origin: string) => boolean): { origin: string; route: string | null } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { origin: REFUSED_ORIGIN, route: null };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return { origin: REFUSED_ORIGIN, route: null };
  const origin = parsed.origin.length <= MAX_ORIGIN_LENGTH && isKnownOrigin(parsed.origin) ? parsed.origin : REFUSED_ORIGIN;
  const segments = parsed.pathname.split('/').slice(1);
  const onSlack = parsed.origin === 'https://slack.com';
  let route = segments.map((segment, index) => (segment === ''
    ? ''
    : routeSegment(segment, onSlack && index === 1 && segments[0] === 'api'))).join('/');
  route = `/${route}`;
  if (route.length > MAX_ROUTE_LENGTH) {
    const cut = route.slice(0, MAX_ROUTE_LENGTH - TRUNCATED_SUFFIX.length);
    route = `${cut.slice(0, cut.lastIndexOf('/'))}${TRUNCATED_SUFFIX}`;
  }
  return { origin, route };
}

export interface RefusalAggregatorOptions {
  write: (event: AuditEvent) => void;
  windowMs?: number;
  /** Bounds the refusals and the actors held in memory. */
  maxKeys?: number;
  /** Distinct refusals one actor may write per window, before the rest collapse into one summary. */
  maxFirstWritesPerActor?: number;
  now?: () => number;
}

/** What makes two refusals the same: bounded values only, beside actor, resource and error. */
const REFUSAL_KEY_FIELDS = ['delegationId', 'method', 'origin', 'policy', 'route'] as const;
/** Values a caller chooses. The first is kept and the rest counted, so they cannot mint new refusals. */
const CLAIM_FIELDS = ['claimedUserId', 'claimedAgentDid'] as const;
/** A distinct count saturates here, which bounds the memory a flood of claims can take. */
const MAX_TRACKED_CLAIMS = 32;

interface HeldRefusal {
  event: AuditEvent;
  startedAt: number;
  repeats: number;
  claims: Map<string, Set<string>>;
}

interface ActorWindow {
  startedAt: number;
  firstWrites: number;
  overflow: HeldRefusal | null;
}

function refusalKey(event: AuditEvent): string {
  return JSON.stringify([
    event.actor.id,
    event.resource.id,
    event.errorMessage,
    ...REFUSAL_KEY_FIELDS.map((field) => event.metadata?.[field] ?? null),
  ]);
}

function hold(event: AuditEvent, startedAt: number): HeldRefusal {
  const entry: HeldRefusal = { event, startedAt, repeats: 0, claims: new Map() };
  noteClaims(entry, event);
  return entry;
}

function noteClaims(entry: HeldRefusal, event: AuditEvent): void {
  for (const field of CLAIM_FIELDS) {
    const value = event.metadata?.[field];
    if (typeof value !== 'string') continue;
    const seen = entry.claims.get(field) ?? new Set<string>();
    if (seen.size < MAX_TRACKED_CLAIMS) seen.add(value);
    entry.claims.set(field, seen);
  }
}

/**
 * Holds down a flood of refusals in a log that is written once and chained.
 *
 * The first refusal of a kind in a window is written at once. Repeats are
 * counted, then written as one summary when the window ends, so a refusal of a
 * different delegation, method, destination or policy is never hidden by a noisy
 * one. Values a caller chooses are not part of a refusal's kind: the summary
 * counts them. An actor can still vary a route, so each actor has a cap on first
 * writes per window, and past it everything collapses into one summary marked
 * `overflow`. A window therefore writes a bounded number of rows per actor.
 *
 * Counts live in process memory, so a crash loses at most one window's counts,
 * never a first event.
 */
export function createRefusalAggregator(options: RefusalAggregatorOptions) {
  const windowMs = options.windowMs ?? 60_000;
  const maxKeys = options.maxKeys ?? 1_000;
  const maxFirstWrites = options.maxFirstWritesPerActor ?? 20;
  const now = options.now ?? Date.now;
  const held = new Map<string, HeldRefusal>();
  const actors = new Map<string, ActorWindow>();

  function writeSummary(entry: HeldRefusal, marker: Record<string, unknown> = {}): void {
    if (entry.repeats === 0) return;
    const distinct = Object.fromEntries([...entry.claims].filter(([, seen]) => seen.size > 1).map(([field, seen]) => [field, seen.size]));
    const capped = [...entry.claims.values()].some((seen) => seen.size >= MAX_TRACKED_CLAIMS);
    options.write({
      ...entry.event,
      id: `evt_${crypto.randomUUID().replace(/-/g, '')}`,
      timestamp: new Date(now()),
      correlationId: crypto.randomUUID(),
      metadata: {
        ...entry.event.metadata,
        ...marker,
        aggregated: true,
        repeats: entry.repeats,
        windowStartedAt: new Date(entry.startedAt).toISOString(),
        ...(Object.keys(distinct).length > 0 ? { distinctClaims: distinct } : {}),
        ...(capped ? { distinctClaimsCapped: MAX_TRACKED_CLAIMS } : {}),
      },
    });
  }

  function endActorWindow(actorId: string, window: ActorWindow): void {
    actors.delete(actorId);
    if (window.overflow) writeSummary(window.overflow, { overflow: true });
  }

  /** The actor's current window, a new one if the last has ended. */
  function actorWindow(actorId: string, at: number): ActorWindow {
    const current = actors.get(actorId);
    if (current && at - current.startedAt < windowMs) return current;
    if (current) endActorWindow(actorId, current);
    if (actors.size >= maxKeys) {
      const [oldestId, oldest] = actors.entries().next().value as [string, ActorWindow];
      endActorWindow(oldestId, oldest);
    }
    const fresh: ActorWindow = { startedAt: at, firstWrites: 0, overflow: null };
    actors.set(actorId, fresh);
    return fresh;
  }

  return {
    /** Write this refusal, or count it. */
    record(event: AuditEvent): void {
      const key = refusalKey(event);
      const at = now();
      const entry = held.get(key);
      if (entry && at - entry.startedAt < windowMs) {
        entry.repeats += 1;
        noteClaims(entry, event);
        return;
      }
      if (entry) {
        held.delete(key);
        writeSummary(entry);
      }
      const window = actorWindow(event.actor.id, at);
      if (window.firstWrites >= maxFirstWrites) {
        window.overflow ??= hold(event, at);
        window.overflow.repeats += 1;
        noteClaims(window.overflow, event);
        return;
      }
      window.firstWrites += 1;
      if (held.size >= maxKeys) {
        const [oldestKey, oldest] = held.entries().next().value as [string, HeldRefusal];
        held.delete(oldestKey);
        writeSummary(oldest);
      }
      held.set(key, hold(event, at));
      options.write(event);
    },
    flushExpired(): void {
      const at = now();
      for (const [key, entry] of held) {
        if (at - entry.startedAt < windowMs) continue;
        held.delete(key);
        writeSummary(entry);
      }
      for (const [actorId, window] of actors) {
        if (at - window.startedAt >= windowMs) endActorWindow(actorId, window);
      }
    },
    /** Write every summary now, for a clean shutdown. */
    flush(): void {
      for (const [key, entry] of held) {
        held.delete(key);
        writeSummary(entry);
      }
      for (const [actorId, window] of actors) endActorWindow(actorId, window);
    },
  };
}

/**
 * Write held summaries when the process is told to stop. SQLite writes are
 * synchronous, so the summaries are on disk before the process exits. A failed
 * flush is logged and never keeps the process alive.
 */
export function flushOnShutdown(
  flush: () => void,
  proc: Pick<NodeJS.Process, 'once' | 'exit'> = process,
): void {
  for (const [signal, status] of [['SIGTERM', 143], ['SIGINT', 130]] as const) {
    proc.once(signal, () => {
      try {
        flush();
      } catch (err) {
        console.error('[audit] Failed to write refusal summaries at shutdown:', err instanceof Error ? err.message : err);
      }
      proc.exit(status);
    });
  }
}
