/**
 * Operation classification: what one brokered API call does, and which grants
 * cover it.
 *
 * A provider's scope is only as good as the check in front of its token, and a
 * URL allowlist cannot tell `gmail.readonly` from `gmail.send`: both reach the
 * same host. These tables can. They are an allowlist, so a call they do not name
 * is refused, never read as allowed: a new provider endpoint stays closed until
 * someone maps it.
 *
 * Each table comes from the provider's documentation. Where a provider accepts
 * more scopes than are listed here the table is narrower on purpose, and where
 * its docs do not give scopes per endpoint (GitHub, HubSpot) the table follows
 * its scope descriptions. Google, not this table, has the last word on whether a
 * token really holds a scope. This decides only whether the broker forwards.
 */
import { Kind, parse, type DocumentNode, type SelectionSetNode } from 'graphql';

export type OperationAccess = 'read' | 'write';

export interface OperationRequest {
  service: string;
  method: string;
  /** The canonical URL that will be forwarded (see canonicalBrokerUrl). */
  url: string;
  /** The JSON body that will be forwarded. */
  body?: unknown;
}

export type OperationVerdict =
  | { outcome: 'allowed'; operation: string; access: OperationAccess }
  /** The table does not map this call or these scopes. Refuse: operation_not_mapped. */
  | { outcome: 'not_mapped'; reason: string }
  /** It maps the call, and these scopes do not cover it. Refuse: scope_insufficient. */
  | { outcome: 'insufficient'; operation: string; access: OperationAccess; needs: readonly string[] };

const ANY_GRANT = Symbol('any grant');
type Needs = readonly string[] | typeof ANY_GRANT;

interface Rule {
  methods: readonly string[];
  /** `/` separated. `*` is one segment, `**` the rest (at least one), `*:verb` a segment with that suffix. */
  pattern: string;
  needs: Needs;
  access: OperationAccess;
}

interface ProviderTable {
  /** Origins the rules apply to; a function for hosts that vary per customer. */
  origins: ReadonlySet<string> | ((origin: string) => boolean);
  rules: readonly Rule[];
  /** Scopes this provider can name that no rule needs, so a grant of only these is not "unknown". */
  otherScopes?: readonly string[];
}

const READ_METHODS = ['GET'];
const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

function rule(methods: string | readonly string[], pattern: string, needs: Needs, access: OperationAccess): Rule {
  return { methods: typeof methods === 'string' ? [methods] : methods, pattern, needs, access };
}
const read = (pattern: string, needs: Needs): Rule => rule(READ_METHODS, pattern, needs, 'read');
const write = (methods: string | readonly string[], pattern: string, needs: Needs): Rule => rule(methods, pattern, needs, 'write');

// ── Google ──────────────────────────────────────────────────────────────────

const GMAIL_READ = ['mail.google.com', 'gmail.modify', 'gmail.readonly', 'gmail.metadata'];
const GMAIL_SEND = ['mail.google.com', 'gmail.modify', 'gmail.compose', 'gmail.send'];
const GMAIL_DRAFT = ['mail.google.com', 'gmail.modify', 'gmail.compose'];
const GMAIL_MODIFY = ['mail.google.com', 'gmail.modify'];
const GMAIL_RULES = (prefix: string): Rule[] => [
  read(`${prefix}/messages`, GMAIL_READ),
  write('POST', `${prefix}/messages/send`, GMAIL_SEND),
  read(`${prefix}/messages/*`, GMAIL_READ),
  write('POST', `${prefix}/messages/*/modify`, GMAIL_MODIFY),
  write('POST', `${prefix}/messages/*/trash`, GMAIL_MODIFY),
  write('POST', `${prefix}/messages/*/untrash`, GMAIL_MODIFY),
  write('DELETE', `${prefix}/messages/*`, ['mail.google.com']),
  read(`${prefix}/threads`, GMAIL_READ),
  read(`${prefix}/threads/*`, GMAIL_READ),
  read(`${prefix}/labels`, GMAIL_READ),
  read(`${prefix}/profile`, GMAIL_READ),
  read(`${prefix}/drafts`, [...GMAIL_READ, 'gmail.compose']),
  read(`${prefix}/drafts/*`, [...GMAIL_READ, 'gmail.compose']),
  write('POST', `${prefix}/drafts`, GMAIL_DRAFT),
  write('POST', `${prefix}/drafts/send`, GMAIL_SEND),
];

const CALENDAR_EVENTS_READ = ['calendar.readonly', 'calendar', 'calendar.events.readonly', 'calendar.events', 'calendar.app.created', 'calendar.events.freebusy', 'calendar.events.owned', 'calendar.events.owned.readonly', 'calendar.events.public.readonly'];
const CALENDAR_EVENTS_WRITE = ['calendar', 'calendar.events', 'calendar.app.created', 'calendar.events.owned'];
const CALENDAR_RULES: Rule[] = [
  read('/calendar/v3/calendars/*/events', CALENDAR_EVENTS_READ),
  read('/calendar/v3/calendars/*/events/*', CALENDAR_EVENTS_READ),
  write('POST', '/calendar/v3/calendars/*/events', CALENDAR_EVENTS_WRITE),
  write(['PUT', 'PATCH', 'DELETE'], '/calendar/v3/calendars/*/events/*', CALENDAR_EVENTS_WRITE),
  // A read that POSTs its query.
  rule('POST', '/calendar/v3/freeBusy', ['calendar.readonly', 'calendar', 'calendar.events.freebusy', 'calendar.freebusy'], 'read'),
  read('/calendar/v3/users/me/calendarList', ['calendar.readonly', 'calendar', 'calendar.calendarlist', 'calendar.calendarlist.readonly']),
  read('/calendar/v3/users/me/calendarList/*', ['calendar.readonly', 'calendar', 'calendar.calendarlist', 'calendar.calendarlist.readonly']),
  read('/calendar/v3/calendars/*', ['calendar.readonly', 'calendar', 'calendar.calendars', 'calendar.calendars.readonly']),
];

const DRIVE_READ = ['drive', 'drive.file', 'drive.metadata', 'drive.metadata.readonly', 'drive.readonly'];
const DRIVE_WRITE = ['drive', 'drive.file'];
const DRIVE_RULES: Rule[] = [
  read('/drive/v3/about', DRIVE_READ),
  read('/drive/v3/files', DRIVE_READ),
  read('/drive/v3/files/*', DRIVE_READ),
  read('/drive/v3/files/*/export', DRIVE_READ),
  write('POST', '/drive/v3/files', DRIVE_WRITE),
  write(['PATCH', 'DELETE'], '/drive/v3/files/*', DRIVE_WRITE),
  write('POST', '/drive/v3/files/*/copy', DRIVE_WRITE),
];

const SHEETS_READ = ['spreadsheets', 'spreadsheets.readonly'];
const SHEETS_RULES: Rule[] = [
  read('/v4/spreadsheets/*', SHEETS_READ),
  read('/v4/spreadsheets/*/values/*', SHEETS_READ),
  write('POST', '/v4/spreadsheets', ['spreadsheets']),
  write('PUT', '/v4/spreadsheets/*/values/*', ['spreadsheets']),
  write('POST', '/v4/spreadsheets/*/values/*:append', ['spreadsheets']),
  write('POST', '/v4/spreadsheets/*/values/*:clear', ['spreadsheets']),
  write('POST', '/v4/spreadsheets/*:batchUpdate', ['spreadsheets']),
];
const DOCS_RULES: Rule[] = [
  read('/v1/documents/*', ['documents', 'documents.readonly']),
  write('POST', '/v1/documents', ['documents']),
  write('POST', '/v1/documents/*:batchUpdate', ['documents']),
];
const PEOPLE_RULES: Rule[] = [
  read('/v1/people/*', ['contacts', 'contacts.readonly', 'userinfo.email', 'userinfo.profile']),
  read('/v1/people/me/connections', ['contacts', 'contacts.readonly']),
];
const ADMIN_RULES: Rule[] = [
  read('/admin/directory/v1/users', ['admin.directory.user', 'admin.directory.user.readonly']),
  read('/admin/directory/v1/users/*', ['admin.directory.user', 'admin.directory.user.readonly']),
  read('/admin/directory/v1/groups', ['admin.directory.group', 'admin.directory.group.readonly']),
  read('/admin/directory/v1/groups/*', ['admin.directory.group', 'admin.directory.group.readonly']),
];
const IDENTITY = ['openid', 'email', 'profile', 'userinfo.email', 'userinfo.profile'];

/** Google serves different APIs from different hosts, so its table is per origin. */
const GOOGLE_BY_ORIGIN: Readonly<Record<string, readonly Rule[]>> = {
  'https://gmail.googleapis.com': GMAIL_RULES('/gmail/v1/users/*'),
  'https://www.googleapis.com': [
    ...GMAIL_RULES('/gmail/v1/users/*'),
    ...CALENDAR_RULES,
    ...DRIVE_RULES,
    read('/oauth2/v2/userinfo', IDENTITY),
    read('/oauth2/v3/userinfo', IDENTITY),
  ],
  'https://calendar.googleapis.com': CALENDAR_RULES,
  'https://drive.googleapis.com': DRIVE_RULES,
  'https://sheets.googleapis.com': SHEETS_RULES,
  'https://docs.googleapis.com': DOCS_RULES,
  'https://people.googleapis.com': PEOPLE_RULES,
  'https://admin.googleapis.com': ADMIN_RULES,
  'https://openidconnect.googleapis.com': [read('/v1/userinfo', IDENTITY)],
};

// ── Slack ───────────────────────────────────────────────────────────────────

const SLACK_CONVERSATION_READ = ['channels:read', 'groups:read', 'im:read', 'mpim:read'];
const SLACK_CONVERSATION_HISTORY = ['channels:history', 'groups:history', 'im:history', 'mpim:history'];
/**
 * Read methods take GET or POST (Slack reads arguments from either); write
 * methods take POST only, so a write never runs from a GET's query string.
 */
const SLACK_READ_METHODS: Readonly<Record<string, Needs>> = {
  'auth.test': ANY_GRANT,
  'conversations.list': SLACK_CONVERSATION_READ,
  'conversations.info': SLACK_CONVERSATION_READ,
  'conversations.members': SLACK_CONVERSATION_READ,
  'conversations.history': SLACK_CONVERSATION_HISTORY,
  'conversations.replies': SLACK_CONVERSATION_HISTORY,
  'users.list': ['users:read'],
  'users.info': ['users:read'],
  'users.lookupByEmail': ['users:read.email'],
  'files.list': ['files:read'],
};
const SLACK_WRITE_METHODS: Readonly<Record<string, Needs>> = {
  'chat.postMessage': ['chat:write'],
  'chat.update': ['chat:write'],
  'chat.delete': ['chat:write'],
  'reactions.add': ['reactions:write'],
  'files.getUploadURLExternal': ['files:write'],
  'files.completeUploadExternal': ['files:write'],
};

/** Every Slack method the table maps. */
export const SLACK_MAPPED_METHODS: readonly string[] = [...Object.keys(SLACK_READ_METHODS), ...Object.keys(SLACK_WRITE_METHODS)];

// ── GitHub ──────────────────────────────────────────────────────────────────

const GH_WRITE = ['repo', 'public_repo'];
const GH_READ = ['github.read', ...GH_WRITE];
/**
 * What github.read reaches under a repository: code, issues and pull requests.
 * An allowlist, since `repo` at the provider also reads secrets' metadata, hooks,
 * keys and settings, and a delegation called read-only must not. Anything else
 * under /repos needs the provider scope itself.
 */
const GH_REPOSITORY_READS: Rule[] = [
  '/repos/*/*',
  '/repos/*/*/readme',
  '/repos/*/*/languages',
  '/repos/*/*/topics',
  '/repos/*/*/contributors',
  '/repos/*/*/tags',
  '/repos/*/*/branches',
  '/repos/*/*/branches/*',
  '/repos/*/*/labels',
  '/repos/*/*/labels/*',
  '/repos/*/*/milestones',
  '/repos/*/*/milestones/*',
  '/repos/*/*/contents',
  '/repos/*/*/contents/**',
  '/repos/*/*/commits',
  '/repos/*/*/commits/**',
  '/repos/*/*/compare/**',
  '/repos/*/*/git/**',
  '/repos/*/*/issues',
  '/repos/*/*/issues/**',
  '/repos/*/*/pulls',
  '/repos/*/*/pulls/**',
  '/repos/*/*/releases',
  '/repos/*/*/releases/**',
].map((pattern) => read(pattern, GH_READ));

// ── HubSpot ─────────────────────────────────────────────────────────────────

const HUBSPOT_RULES: Rule[] = [
  ...['contacts', 'companies', 'deals', 'tickets', 'line_items', 'quotes'].flatMap((type) => {
    const base = `/crm/v3/objects/${type}`;
    // HubSpot's legacy `tickets` covers both, and token responses can still name it.
    const legacy = type === 'tickets' ? ['tickets'] : [];
    const canRead = [`crm.objects.${type}.read`, ...legacy];
    const canWrite = [`crm.objects.${type}.write`, ...legacy];
    return [
      read(base, canRead),
      rule('POST', `${base}/search`, canRead, 'read'),
      read(`${base}/*`, canRead),
      write('POST', base, canWrite),
      write(['PATCH', 'DELETE'], `${base}/*`, canWrite),
    ];
  }),
  read('/crm/v3/owners', ['crm.objects.owners.read']),
  read('/crm/v3/owners/*', ['crm.objects.owners.read']),
  ...['contacts', 'companies', 'deals', 'line_items', 'quotes'].flatMap((type) => [
    read(`/crm/v3/properties/${type}`, [`crm.schemas.${type}.read`]),
    read(`/crm/v3/properties/${type}/*`, [`crm.schemas.${type}.read`]),
  ]),
  read('/crm/v3/properties/tickets', ['crm.schemas.tickets.read', 'tickets']),
  read('/crm/v3/properties/tickets/*', ['crm.schemas.tickets.read', 'tickets']),
];

// ── Notion and Salesforce: reads named by Cred ──────────────────────────────

// read_content, update_content and insert_content are names /connect used to
// offer. Notion never saw them, but rows stored under them keep what they said:
// insert creates and appends, update changes what exists, and only `content` deletes.
const NOTION_READ = ['notion.read', 'content', 'read_content'];
const NOTION_INSERT = ['content', 'insert_content'];
const NOTION_UPDATE = ['content', 'update_content'];
const NOTION_WHOLE = ['content'];
const SALESFORCE_READ = ['salesforce.read', 'api', 'full'];
const SALESFORCE_WRITE = ['api', 'full'];
const SALESFORCE_HOST = /^https:\/\/[a-z0-9.-]+\.(?:salesforce\.com|force\.com)$/;

const TABLES: Readonly<Record<string, ProviderTable>> = {
  github: {
    origins: new Set(['https://api.github.com']),
    otherScopes: ['workflow', 'user:email', 'read:packages', 'write:packages'],
    rules: [
      read('/user', ANY_GRANT),
      read('/user/**', ['user', 'read:user', 'user:email', ...GH_WRITE]),
      read('/users/**', ANY_GRANT),
      read('/rate_limit', ANY_GRANT),
      ...GH_REPOSITORY_READS,
      read('/repos/**', GH_WRITE),
      read('/search/**', GH_READ),
      read('/orgs/**', [...GH_WRITE, 'read:org', 'write:org', 'admin:org']),
      read('/gists', [...GH_WRITE, 'gist']),
      read('/gists/**', [...GH_WRITE, 'gist']),
      read('/notifications', ['notifications', 'repo']),
      write('DELETE', '/repos/*/*', ['delete_repo']),
      write(WRITE_METHODS, '/repos/*/*/**', GH_WRITE),
      write('POST', '/user/repos', GH_WRITE),
      write(['PATCH'], '/user', ['user']),
      write(WRITE_METHODS, '/user/**', ['user']),
      write(WRITE_METHODS, '/orgs/**', ['admin:org', 'write:org']),
      write('POST', '/gists', ['gist']),
      write(WRITE_METHODS, '/gists/**', ['gist']),
    ],
  },
  hubspot: {
    origins: new Set(['https://api.hubapi.com']),
    otherScopes: ['oauth', 'content', 'automation'],
    rules: HUBSPOT_RULES,
  },
  notion: {
    origins: new Set(['https://api.notion.com']),
    rules: [
      read('/v1/users', NOTION_READ),
      read('/v1/users/*', NOTION_READ),
      read('/v1/pages/*', NOTION_READ),
      read('/v1/pages/*/properties/*', NOTION_READ),
      read('/v1/blocks/*', NOTION_READ),
      read('/v1/blocks/*/children', NOTION_READ),
      read('/v1/databases/*', NOTION_READ),
      read('/v1/data_sources/*', NOTION_READ),
      read('/v1/comments', NOTION_READ),
      rule('POST', '/v1/search', NOTION_READ, 'read'),
      rule('POST', '/v1/data_sources/*/query', NOTION_READ, 'read'),
      rule('POST', '/v1/databases/*/query', NOTION_READ, 'read'),
      write('POST', '/v1/pages', NOTION_INSERT),
      write('POST', '/v1/databases', NOTION_INSERT),
      write('POST', '/v1/data_sources', NOTION_INSERT),
      write('POST', '/v1/comments', NOTION_INSERT),
      write('PATCH', '/v1/pages/*', NOTION_UPDATE),
      write('PATCH', '/v1/blocks/*', NOTION_UPDATE),
      write('PATCH', '/v1/blocks/*/children', NOTION_INSERT),
      write('PATCH', '/v1/databases/*', NOTION_UPDATE),
      write('PATCH', '/v1/data_sources/*', NOTION_UPDATE),
      write('DELETE', '/v1/blocks/*', NOTION_WHOLE),
    ],
  },
  salesforce: {
    origins: (origin) => SALESFORCE_HOST.test(origin),
    otherScopes: ['refresh_token', 'offline_access', 'web', 'openid', 'id', 'profile', 'email'],
    rules: [
      read('/services/data', SALESFORCE_READ),
      read('/services/data/*', SALESFORCE_READ),
      read('/services/data/*/limits', SALESFORCE_READ),
      read('/services/data/*/query', SALESFORCE_READ),
      read('/services/data/*/query/*', SALESFORCE_READ),
      read('/services/data/*/queryAll', SALESFORCE_READ),
      read('/services/data/*/search', SALESFORCE_READ),
      read('/services/data/*/sobjects', SALESFORCE_READ),
      read('/services/data/*/sobjects/*', SALESFORCE_READ),
      read('/services/data/*/sobjects/*/describe', SALESFORCE_READ),
      read('/services/data/*/sobjects/*/*', SALESFORCE_READ),
      read('/services/data/*/sobjects/*/*/*', SALESFORCE_READ),
      write('POST', '/services/data/*/sobjects/*', SALESFORCE_WRITE),
      write(['PATCH', 'DELETE'], '/services/data/*/sobjects/*/*', SALESFORCE_WRITE),
      write(['PATCH', 'DELETE'], '/services/data/*/sobjects/*/*/*', SALESFORCE_WRITE),
    ],
  },
};

const LINEAR_ORIGIN = 'https://api.linear.app';
const GITHUB_ORIGIN = 'https://api.github.com';
/**
 * What a GitHub GraphQL query needs: the provider scope itself. A query can reach
 * deploy keys, collaborators and a user's keys and gists, so neither an identity
 * scope nor github.read, which is held to an allowlist of REST reads, is enough.
 */
const GITHUB_GRAPHQL_READ = ['repo', 'public_repo'];
/**
 * The GitHub GraphQL mutations the broker forwards, each with the scopes that
 * cover it. Any other is refused: `repo` also covers mutations that administer a
 * repository, which one write scope should not reach by accident. GitHub does
 * not publish scopes per mutation, so these follow its scope descriptions.
 */
const GITHUB_GRAPHQL_MUTATIONS: ReadonlyMap<string, readonly string[]> = new Map([
  ['createIssue', GH_WRITE],
  ['closeIssue', GH_WRITE],
  ['addComment', GH_WRITE],
]);
/** The mutations a narrow Linear scope allows. Linear's own `issues:create` also updates; Cred's label says create. */
const LINEAR_NARROW_MUTATIONS: Readonly<Record<string, ReadonlySet<string>>> = {
  'issues:create': new Set(['issueCreate', 'attachmentCreate']),
  'comments:create': new Set(['commentCreate']),
};
const LINEAR_SCOPES = ['read', 'write', 'issues:create', 'comments:create', 'timeSchedule:write', 'admin'];

// ── Scopes that share a resource partition ──────────────────────────────────

/**
 * Scopes that narrow by resource rather than by operation. The broker can tell
 * that a Drive read or a Slack listing is allowed, but what comes back depends on
 * everything the provider token holds, and narrowing never changes that token. So
 * with a sibling or wider scope still on the token, these reach more than they say.
 */
const RESOURCE_PARTITIONS: Readonly<Record<string, ReadonlyArray<{ partitioned: readonly string[]; family: readonly string[] }>>> = {
  google: [{
    partitioned: ['drive.file', 'drive.metadata', 'drive.metadata.readonly'],
    family: ['drive', 'drive.readonly', 'drive.file', 'drive.metadata', 'drive.metadata.readonly'],
  }],
  slack: [
    { partitioned: ['channels:read', 'groups:read', 'im:read', 'mpim:read'], family: ['channels:read', 'groups:read', 'im:read', 'mpim:read'] },
    { partitioned: ['channels:history', 'groups:history', 'im:history', 'mpim:history'], family: ['channels:history', 'groups:history', 'im:history', 'mpim:history'] },
  ],
};

/** Whether a remaining partitioned scope still reaches what the token holds beyond it. */
export function narrowedScopeStaysExposed(service: string, remaining: readonly string[], providerScopes: readonly string[]): boolean {
  const partitions = Object.prototype.hasOwnProperty.call(RESOURCE_PARTITIONS, service) ? RESOURCE_PARTITIONS[service]! : [];
  return partitions.some(({ partitioned, family }) => remaining.some((scope) => partitioned.includes(scope))
    && providerScopes.some((scope) => family.includes(scope) && !remaining.includes(scope)));
}

// ── Canonical requests ──────────────────────────────────────────────────────

/**
 * The one URL a brokered call may be forwarded to, or null. Parsing resolves dot
 * segments and normalizes case, so what is checked is what is sent. Anything
 * that could mean a different path to the provider than to this check is
 * refused: encoded dots, slashes, backslashes and percents, doubled slashes and
 * control characters. So are credentials, other ports and a trailing-dot host.
 */
export function canonicalBrokerUrl(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return null;
  if (parsed.port !== '' && parsed.port !== '443') return null;
  if (parsed.hostname.endsWith('.')) return null;
  if (/%(2e|2f|5c|25)/i.test(parsed.pathname)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(parsed.pathname);
  } catch {
    return null;
  }
  if (decoded.includes('\\') || decoded.includes('//') || /[\u0000-\u001f\u007f]/.test(decoded)) return null;
  if (decoded.split('/').some((segment) => segment === '.' || segment === '..')) return null;
  return `https://${parsed.hostname.toLowerCase()}${parsed.pathname}${parsed.search}`;
}

// ── Override channels ───────────────────────────────────────────────────────

const OVERRIDE_HEADERS = new Set([
  'x-http-method-override', 'x-http-method', 'x-method-override',
  // Proxies read these as the real target.
  'x-original-url', 'x-rewrite-url', 'x-original-method',
]);
const OVERRIDE_QUERY_KEY = /^(x)?(http)?method(override)?$/i;
const OVERRIDE_BODY_KEY = /^(?:[_$]+(?:http)?method|.*method[-_]?override)$/i;

/**
 * The channel a request tries to change its method through, or null. A JSON body
 * key called just `method` is ordinary data, so the body check is narrower than
 * the query check.
 */
export function methodOverrideChannel(request: { url: string; headers?: Record<string, unknown>; body?: unknown }): 'query' | 'header' | 'body' | null {
  try {
    if ([...new URL(request.url).searchParams.keys()].some((key) => OVERRIDE_QUERY_KEY.test(key.replace(/[-_$.\s]/g, '')))) return 'query';
  } catch {
    return 'query';
  }
  if (Object.keys(request.headers ?? {}).some((key) => OVERRIDE_HEADERS.has(key.trim().toLowerCase()))) return 'header';
  const { body } = request;
  if (body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).some((key) => OVERRIDE_BODY_KEY.test(key))) return 'body';
  return null;
}

/**
 * Whether a caller's headers change how the body is read upstream. Every body
 * forwarded is JSON, and is classified as JSON: a different Content-Type could
 * make a provider read it as something else, such as a GraphQL document or a
 * multipart batch.
 */
export function contentTypeMismatch(headers: Record<string, unknown> | undefined): boolean {
  return Object.entries(headers ?? {}).some(([key, value]) => key.trim().toLowerCase() === 'content-type'
    && !(typeof value === 'string' && /^application\/json\s*(;\s*charset=utf-8\s*)?$/i.test(value.trim())));
}

// ── Classifying ─────────────────────────────────────────────────────────────

function segmentMatches(pattern: string, segment: string): boolean {
  if (segment === '') return false;
  if (pattern === '*') return true;
  if (pattern.startsWith('*:')) return segment.length > pattern.length - 1 && segment.endsWith(pattern.slice(1));
  return pattern === segment;
}

function pathMatches(pattern: string, segments: readonly string[]): boolean {
  const parts = pattern.split('/').slice(1);
  for (let i = 0; i < parts.length; i += 1) {
    if (parts[i] === '**') return i === parts.length - 1 && segments.length > i && segments.slice(i).every((s) => s !== '');
    if (i >= segments.length || !segmentMatches(parts[i]!, segments[i]!)) return false;
  }
  return segments.length === parts.length;
}

/** The most specific rule wins: exact words before `*`, which the tables list in that order per method. */
function findRule(rules: readonly Rule[], method: string, segments: readonly string[]): Rule | undefined {
  return rules.find((candidate) => candidate.methods.includes(method) && pathMatches(candidate.pattern, segments));
}

/** A path a server could read differently: a matrix parameter, or a plain character percent-encoded. */
function ambiguousPath(pathname: string): boolean {
  if (pathname.includes(';')) return true;
  return [...pathname.matchAll(/%([0-9a-f]{2})/gi)].some((match) => /[A-Za-z0-9\-._~]/.test(String.fromCharCode(parseInt(match[1]!, 16))));
}

type GraphqlShape =
  | { kind: 'query' }
  /** Top-level field names, or null when a fragment hides them. */
  | { kind: 'mutation'; fields: string[] | null }
  | { kind: 'refused'; reason: string };

function topLevelFields(selectionSet: SelectionSetNode): string[] | null {
  const fields: string[] = [];
  for (const selection of selectionSet.selections) {
    // The field's name, never its alias: an alias is whatever the caller says.
    if (selection.kind !== Kind.FIELD) return null;
    fields.push(selection.name.value);
  }
  return fields;
}

/**
 * What a GraphQL body does, judged on every operation in it: `operationName`
 * picks one at the server, so it cannot be trusted to pick the same one here.
 */
function classifyGraphql(body: unknown): GraphqlShape {
  if (Array.isArray(body)) return { kind: 'refused', reason: 'graphql_batch' };
  if (!body || typeof body !== 'object') return { kind: 'refused', reason: 'graphql_body' };
  const { query, extensions } = body as { query?: unknown; extensions?: unknown };
  // A persisted query runs a document this check never sees.
  if (extensions !== undefined) return { kind: 'refused', reason: 'graphql_extensions' };
  if (typeof query !== 'string') return { kind: 'refused', reason: 'graphql_body' };
  let document: DocumentNode;
  try {
    document = parse(query, { noLocation: true, maxTokens: 10_000 });
  } catch {
    return { kind: 'refused', reason: 'graphql_unparseable' };
  }
  let mutationFields: string[] | null = [];
  let isMutation = false;
  let operations = 0;
  for (const definition of document.definitions) {
    if (definition.kind === Kind.FRAGMENT_DEFINITION) continue;
    if (definition.kind !== Kind.OPERATION_DEFINITION) return { kind: 'refused', reason: 'graphql_definition' };
    operations += 1;
    if (definition.operation === 'subscription') return { kind: 'refused', reason: 'graphql_subscription' };
    if (definition.operation === 'mutation') {
      isMutation = true;
      const fields = topLevelFields(definition.selectionSet);
      mutationFields = fields === null || mutationFields === null ? null : [...mutationFields, ...fields];
    }
  }
  if (operations === 0) return { kind: 'refused', reason: 'graphql_no_operation' };
  return isMutation ? { kind: 'mutation', fields: mutationFields } : { kind: 'query' };
}

interface Mapped {
  operation: string;
  access: OperationAccess;
  needs: Needs;
  /** Extra coverage for this exact call, for scopes that allow only certain mutations. */
  alsoCoveredBy?: (scope: string) => boolean;
  /** When a call does several things: each entry must be covered, and `needs` alone is not enough. */
  needsEach?: ReadonlyArray<readonly string[]>;
}

function classify(request: OperationRequest): Mapped | { reason: string } {
  let parsed: URL;
  try {
    parsed = new URL(request.url);
  } catch {
    return { reason: 'url' };
  }
  const { origin, pathname } = parsed;
  if (ambiguousPath(pathname)) return { reason: 'ambiguous_path' };
  if (parsed.searchParams.has('uploadType')) return { reason: 'multipart_upload' };
  const segments = pathname.split('/').slice(1);
  const { service, method } = request;

  if (service === 'linear' || (service === 'github' && origin === GITHUB_ORIGIN && pathname === '/graphql')) {
    if ((service === 'linear' && (origin !== LINEAR_ORIGIN || pathname !== '/graphql')) || method !== 'POST') return { reason: 'not_in_table' };
    const shape = classifyGraphql(request.body);
    if (shape.kind === 'refused') return { reason: shape.reason };
    if (service === 'github') {
      if (shape.kind === 'query') return { operation: 'POST /graphql query', access: 'read', needs: GITHUB_GRAPHQL_READ };
      const needsEach = shape.fields?.map((field) => GITHUB_GRAPHQL_MUTATIONS.get(field));
      if (!needsEach || needsEach.length === 0 || needsEach.some((needs) => needs === undefined)) return { reason: 'mutation_not_in_table' };
      const mutationNeeds = needsEach as ReadonlyArray<readonly string[]>;
      return { operation: 'POST /graphql mutation', access: 'write', needs: [...new Set(mutationNeeds.flat())], needsEach: mutationNeeds };
    }
    if (shape.kind === 'query') return { operation: 'POST /graphql query', access: 'read', needs: ['read', 'write', 'admin'] };
    const { fields } = shape;
    return {
      operation: 'POST /graphql mutation',
      access: 'write',
      needs: ['write'],
      alsoCoveredBy: (scope) => fields !== null && fields.length > 0
        && LINEAR_NARROW_MUTATIONS[scope] !== undefined
        && fields.every((field) => LINEAR_NARROW_MUTATIONS[scope]!.has(field)),
    };
  }

  if (service === 'slack') {
    if (origin !== 'https://slack.com' || segments.length !== 2 || segments[0] !== 'api') return { reason: 'not_in_table' };
    const name = segments[1]!;
    if (Object.prototype.hasOwnProperty.call(SLACK_READ_METHODS, name) && (method === 'GET' || method === 'POST')) {
      return { operation: name, access: 'read', needs: SLACK_READ_METHODS[name]! };
    }
    if (Object.prototype.hasOwnProperty.call(SLACK_WRITE_METHODS, name) && method === 'POST') {
      return { operation: name, access: 'write', needs: SLACK_WRITE_METHODS[name]! };
    }
    return { reason: 'not_in_table' };
  }

  let rules: readonly Rule[] | undefined;
  if (service === 'google') {
    rules = Object.prototype.hasOwnProperty.call(GOOGLE_BY_ORIGIN, origin) ? GOOGLE_BY_ORIGIN[origin] : undefined;
  } else if (Object.prototype.hasOwnProperty.call(TABLES, service)) {
    const table = TABLES[service]!;
    const known = typeof table.origins === 'function' ? table.origins(origin) : table.origins.has(origin);
    rules = known ? table.rules : undefined;
  }
  if (!rules) return { reason: 'not_in_table' };
  const found = findRule(rules, method, segments);
  if (!found) return { reason: 'not_in_table' };
  return { operation: `${method} ${found.pattern}`, access: found.access, needs: found.needs };
}

/** A Google scope in the form the table uses, whichever form it was stored in. */
function canonicalScope(service: string, scope: string): string {
  if (service !== 'google') return scope;
  const trimmed = scope.trim().replace(/\/$/, '');
  const lower = trimmed.toLowerCase();
  const authPrefix = 'https://www.googleapis.com/auth/';
  if (lower.startsWith(authPrefix)) return lower.slice(authPrefix.length);
  if (lower === 'https://mail.google.com') return 'mail.google.com';
  return trimmed;
}

const KNOWN_SCOPES = new Map<string, ReadonlySet<string>>();

function knownScopes(service: string): ReadonlySet<string> {
  const cached = KNOWN_SCOPES.get(service);
  if (cached) return cached;
  const known = new Set<string>();
  const addRules = (rules: readonly Rule[]) => {
    for (const { needs } of rules) if (needs !== ANY_GRANT) for (const scope of needs) known.add(scope);
  };
  if (service === 'google') Object.values(GOOGLE_BY_ORIGIN).forEach(addRules);
  if (service === 'slack') {
    for (const needs of [...Object.values(SLACK_READ_METHODS), ...Object.values(SLACK_WRITE_METHODS)]) {
      if (needs !== ANY_GRANT) for (const scope of needs) known.add(scope);
    }
  }
  if (service === 'linear') LINEAR_SCOPES.forEach((scope) => known.add(scope));
  if (Object.prototype.hasOwnProperty.call(TABLES, service)) {
    addRules(TABLES[service]!.rules);
    (TABLES[service]!.otherScopes ?? []).forEach((scope) => known.add(scope));
  }
  if (service === 'github') ['read:user', 'user', 'read:org'].forEach((scope) => known.add(scope));
  KNOWN_SCOPES.set(service, known);
  return known;
}

/** Whether classification has a table for this service at all. */
export function hasOperationTable(service: string): boolean {
  return service === 'google' || service === 'slack' || service === 'linear' || Object.prototype.hasOwnProperty.call(TABLES, service);
}

/**
 * Decide one call against the scopes it runs under. A scope list the table has
 * never heard of answers not_mapped rather than insufficient: nobody can say
 * what it allows. An empty list covers nothing: a caller holding a Notion
 * connection with no named scope passes withDerivedScopes of it, which names it.
 */
export function evaluateOperation(request: OperationRequest, grantedScopes: readonly string[]): OperationVerdict {
  const mapped = classify(request);
  if ('reason' in mapped) return { outcome: 'not_mapped', reason: mapped.reason };
  const { operation, access, needs, alsoCoveredBy, needsEach } = mapped;
  if (needs === ANY_GRANT) return { outcome: 'allowed', operation, access };
  const scopes = grantedScopes.map((scope) => canonicalScope(request.service, scope));
  const covered = needsEach
    ? needsEach.every((each) => each.some((scope) => scopes.includes(scope)))
    : scopes.some((scope) => needs.includes(scope) || alsoCoveredBy?.(scope));
  if (covered) return { outcome: 'allowed', operation, access };
  const known = knownScopes(request.service);
  if (scopes.length > 0 && !scopes.some((scope) => known.has(scope))) return { outcome: 'not_mapped', reason: 'scope_not_in_table' };
  return { outcome: 'insufficient', operation, access, needs };
}
