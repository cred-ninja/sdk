/**
 * Capabilities (draft-sweeney-wimse-credential-delegation-02 Section 5.2):
 * RFC 9396 `authorization_details` of type `cred_delegation`, and the
 * per-provider operation catalogue that gives named operations and
 * resources their meaning.
 *
 * An operation is either an OAuth scope the delegation was granted, which
 * allows whatever that scope allows (the broker's existing per-provider
 * rules), or the name of a catalogue operation, which allows exactly one
 * method and URL template. A resource narrows a catalogue operation to the
 * URL parameters it binds, such as one repository or one file. Anything
 * the catalogue does not name is refused: an unknown operation or resource
 * is never read as broad.
 */
import { CRED_DELEGATION_TYPE, scopeCoveredBy, type CredDelegationDetail } from '@credninja/attenuation';
import { brokerScopeEquivalent, googleScopeMatches } from './google-scopes.js';

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** A resource kind: how `kind:value` binds the URL template's parameters. */
interface ResourceKind {
  kind: string;
  /** Template parameters the value binds, in order, split on '/'. */
  params: string[];
}

export interface CatalogueOperation {
  name: string;
  provider: string;
  method: Method;
  /** `https://host/path`; `{name}` matches one segment, `{name+}` the rest. */
  url: string;
  /** Granting any one of these scopes makes the operation available. */
  scopes: string[];
  /** The resource kind that narrows this operation, if it can be narrowed. */
  resource?: ResourceKind;
  /** A listing's page-size query parameter and the provider's maximum for it. */
  page?: { param: string; max: number };
}

const REPO: ResourceKind = { kind: 'repo', params: ['owner', 'repo'] };
const FILE: ResourceKind = { kind: 'file', params: ['fileId'] };
const GITHUB_REPO_SCOPES = ['repo', 'public_repo'];
const DRIVE_READ = ['drive.readonly', 'drive', 'drive.file', 'drive.metadata.readonly'];
const DRIVE_WRITE = ['drive', 'drive.file'];

const GH = 'https://api.github.com';
const DRIVE = 'https://www.googleapis.com/drive/v3';

export const OPERATION_CATALOGUE: readonly CatalogueOperation[] = [
  { name: 'github.user.get', provider: 'github', method: 'GET', url: `${GH}/user`, scopes: ['read:user', 'user'] },
  { name: 'github.repos.get', provider: 'github', method: 'GET', url: `${GH}/repos/{owner}/{repo}`, scopes: GITHUB_REPO_SCOPES, resource: REPO },
  { name: 'github.contents.get', provider: 'github', method: 'GET', url: `${GH}/repos/{owner}/{repo}/contents/{path+}`, scopes: GITHUB_REPO_SCOPES, resource: REPO },
  { name: 'github.issues.list', provider: 'github', method: 'GET', url: `${GH}/repos/{owner}/{repo}/issues`, scopes: GITHUB_REPO_SCOPES, resource: REPO, page: { param: 'per_page', max: 100 } },
  { name: 'github.issues.get', provider: 'github', method: 'GET', url: `${GH}/repos/{owner}/{repo}/issues/{number}`, scopes: GITHUB_REPO_SCOPES, resource: REPO },
  { name: 'github.issues.create', provider: 'github', method: 'POST', url: `${GH}/repos/{owner}/{repo}/issues`, scopes: GITHUB_REPO_SCOPES, resource: REPO },
  { name: 'github.issues.comment', provider: 'github', method: 'POST', url: `${GH}/repos/{owner}/{repo}/issues/{number}/comments`, scopes: GITHUB_REPO_SCOPES, resource: REPO },
  { name: 'github.pulls.list', provider: 'github', method: 'GET', url: `${GH}/repos/{owner}/{repo}/pulls`, scopes: GITHUB_REPO_SCOPES, resource: REPO, page: { param: 'per_page', max: 100 } },
  { name: 'github.pulls.get', provider: 'github', method: 'GET', url: `${GH}/repos/{owner}/{repo}/pulls/{number}`, scopes: GITHUB_REPO_SCOPES, resource: REPO },
  { name: 'drive.files.list', provider: 'google', method: 'GET', url: `${DRIVE}/files`, scopes: DRIVE_READ, page: { param: 'pageSize', max: 1000 } },
  { name: 'drive.files.get', provider: 'google', method: 'GET', url: `${DRIVE}/files/{fileId}`, scopes: DRIVE_READ, resource: FILE },
  { name: 'drive.files.export', provider: 'google', method: 'GET', url: `${DRIVE}/files/{fileId}/export`, scopes: DRIVE_READ, resource: FILE },
  { name: 'drive.files.create', provider: 'google', method: 'POST', url: `${DRIVE}/files`, scopes: DRIVE_WRITE },
];

const BY_NAME = new Map(OPERATION_CATALOGUE.map((op) => [op.name, op]));

export function catalogueOperation(name: string): CatalogueOperation | undefined {
  return BY_NAME.get(name);
}

/** Whether `granted` (a delegation's scopes) makes the catalogue operation available. */
export function operationGranted(op: CatalogueOperation, granted: readonly string[]): boolean {
  return op.scopes.some((required) => granted.some((scope) => (op.provider === 'google'
    ? googleScopeMatches(scope, required)
    // GitHub's `repo` includes `public_repo`.
    : scope === required || (required === 'public_repo' && scope === 'repo'))));
}

export type CapabilityProblem = { ok: false; message: string };

/**
 * Validate requested capabilities against the scopes a delegation is
 * granted. Each detail names this provider; each operation is a granted
 * scope or a catalogue operation the scopes make available; resources
 * appear only on details whose operations are all catalogue operations of
 * one resource kind, and name that kind.
 */
export function validateCapabilities(
  details: unknown,
  provider: string,
  grantedScopes: readonly string[],
): { ok: true; details: CredDelegationDetail[] } | CapabilityProblem {
  if (!Array.isArray(details) || details.length === 0) return { ok: false, message: 'authorization_details must be a non-empty array' };
  const out: CredDelegationDetail[] = [];
  let usesScopes = false;
  let usesCatalogue = false;
  for (const raw of details) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { ok: false, message: 'each authorization_details entry must be an object' };
    const { type, provider: p, operations, resources, ...rest } = raw as Record<string, unknown>;
    if (Object.keys(rest).length > 0) return { ok: false, message: `unknown member ${Object.keys(rest)[0]} in authorization_details` };
    if (type !== CRED_DELEGATION_TYPE) return { ok: false, message: `authorization_details type must be ${CRED_DELEGATION_TYPE}` };
    if (p !== provider) return { ok: false, message: `authorization_details provider must be ${provider}` };
    if (!Array.isArray(operations) || operations.length === 0 || !operations.every((o) => typeof o === 'string' && o.length > 0)) {
      return { ok: false, message: 'operations must be a non-empty array of strings' };
    }
    const ops = operations as string[];
    for (const op of ops) {
      const entry = catalogueOperation(op);
      if (entry) {
        if (entry.provider !== provider) return { ok: false, message: `operation ${op} is not a ${provider} operation` };
        if (!operationGranted(entry, grantedScopes)) return { ok: false, message: `operation ${op} needs a scope this delegation is not granted` };
      } else if (!grantedScopes.some((scope) => scope === op || scopeCoveredBy([scope], op)
        || (provider === 'google' && brokerScopeEquivalent(scope, op)))) {
        return { ok: false, message: `unknown operation ${op}: not a granted scope or a catalogue operation` };
      }
      if (entry) usesCatalogue = true;
      else usesScopes = true;
    }
    // A scope operation allows what the broker lets that scope do, which for
    // most providers is the whole API. Beside a catalogue operation it would
    // silently widen a token that looks narrowed, so a token is one or the other.
    if (usesScopes && usesCatalogue) {
      return { ok: false, message: 'authorization_details must name scopes or catalogue operations, not both: a scope operation would widen the catalogue operations beside it' };
    }
    if (resources !== undefined) {
      if (!Array.isArray(resources) || resources.length === 0 || !resources.every((r) => typeof r === 'string')) {
        return { ok: false, message: 'resources must be a non-empty array of strings' };
      }
      const kinds = new Set(ops.map((op) => catalogueOperation(op)?.resource?.kind));
      const [kind] = kinds;
      if (kinds.size !== 1 || kind === undefined) {
        return { ok: false, message: 'resources narrow catalogue operations of one resource kind; every operation in this entry must take that kind' };
      }
      for (const resource of resources as string[]) {
        if (!parseResource(resource, kind)) return { ok: false, message: `resource ${resource} is not a ${kind} resource` };
      }
    }
    out.push({
      type: CRED_DELEGATION_TYPE,
      provider,
      // A Google scope op is stored in the granted spelling, which the
      // broker's scope rules compare against.
      operations: ops.map((op) => (catalogueOperation(op) || provider !== 'google'
        ? op
        : grantedScopes.find((scope) => brokerScopeEquivalent(scope, op)) ?? op)),
      ...(resources !== undefined ? { resources: [...(resources as string[])] } : {}),
    });
  }
  return { ok: true, details: out };
}

/** `kind:value` split into the kind's template parameters, or null. */
function parseResource(resource: string, kind: string): Record<string, string> | null {
  const def = [REPO, FILE].find((k) => k.kind === kind);
  if (!def || !resource.startsWith(`${kind}:`)) return null;
  const parts = resource.slice(kind.length + 1).split('/');
  if (parts.length !== def.params.length || parts.some((part) => !/^[A-Za-z0-9._-]+$/.test(part))) return null;
  return Object.fromEntries(def.params.map((param, i) => [param, parts[i]!]));
}

/** Template parameters bound by matching `url` against `template`, or null. */
function matchTemplate(template: string, url: URL): Record<string, string> | null {
  // Split by hand: URL parsing would percent-encode the template's braces.
  const pathStart = template.indexOf('/', 'https://'.length);
  if (template.slice(0, pathStart) !== url.origin) return null;
  const tSegs = template.slice(pathStart).split('/').slice(1);
  const uSegs = url.pathname.split('/').slice(1);
  const bound: Record<string, string> = {};
  for (let i = 0; i < tSegs.length; i++) {
    const seg = tSegs[i]!;
    const rest = /^\{(\w+)\+\}$/.exec(seg);
    if (rest) {
      // `{x+}` binds the rest of the path, possibly nothing (a repository's
      // contents root), but never an empty segment.
      if (i !== tSegs.length - 1 || uSegs.slice(i).some((s) => s === '')) return null;
      bound[rest[1]!] = uSegs.slice(i).map(decodeURIComponent).join('/');
      return bound;
    }
    const value = uSegs[i];
    if (value === undefined || value === '') return null;
    const param = /^\{(\w+)\}$/.exec(seg);
    if (param) {
      const decoded = decodeURIComponent(value);
      // Issue and pull request numbers are numbers, never another endpoint.
      if (param[1] === 'number' && !/^\d+$/.test(decoded)) return null;
      bound[param[1]!] = decoded;
    } else if (seg !== value) return null;
  }
  return uSegs.length === tSegs.length ? bound : null;
}

/**
 * Whether one exercise (method and the already-resolved upstream URL) is
 * within the capabilities. A scope operation defers to the broker's scope
 * rules (`scopeAllows`); a catalogue operation must match its method and
 * template and, when the entry names resources, bind one of them.
 */
export function capabilitiesAllow(
  details: readonly CredDelegationDetail[],
  provider: string,
  method: string,
  upstreamUrl: string,
  scopeAllows: (scopes: string[]) => boolean,
): boolean {
  let url: URL;
  try {
    url = new URL(upstreamUrl);
  } catch {
    return false;
  }
  for (const detail of details) {
    if (detail.provider !== provider) continue;
    const scopeOps = detail.operations.filter((op) => !catalogueOperation(op));
    if (scopeOps.length > 0 && !detail.resources && scopeAllows(scopeOps)) return true;
    for (const name of detail.operations) {
      const op = catalogueOperation(name);
      if (!op || op.method !== method) continue;
      const bound = matchTemplate(op.url, url);
      if (!bound) continue;
      if (!detail.resources) return true;
      if (detail.resources.some((resource) => {
        const wanted = op.resource ? parseResource(resource, op.resource.kind) : null;
        // GitHub owner and repository names are case-insensitive; Drive ids are not.
        const same = op.resource?.kind === 'repo'
          ? (a: string | undefined, b: string) => a?.toLowerCase() === b.toLowerCase()
          : (a: string | undefined, b: string) => a === b;
        return wanted !== null && Object.entries(wanted).every(([k, v]) => same(bound[k], v));
      })) return true;
    }
  }
  return false;
}

/** Whether `child` is within `parent`: every child entry covered by one parent entry. */
export function capabilitiesSubsumed(parent: readonly CredDelegationDetail[], child: readonly CredDelegationDetail[]): boolean {
  const sameResource = (a: string, b: string) => (a.startsWith('repo:') ? a.toLowerCase() === b.toLowerCase() : a === b);
  return child.every((c) => parent.some((p) => p.provider === c.provider
    && c.operations.every((op) => p.operations.includes(op)
      // A parent scope operation covers a narrower scope, and a catalogue
      // operation it makes available.
      || (!p.resources && !catalogueOperation(op) && p.operations.some((po) => !catalogueOperation(po)) && scopeCoveredBy(p.operations, op))
      || (!p.resources && catalogueOperation(op) !== undefined && operationGranted(catalogueOperation(op)!, p.operations)))
    && (!p.resources || (c.resources !== undefined && c.resources.every((r) => p.resources!.some((pr) => sameResource(pr, r)))))));
}

/**
 * The page-size parameter of the catalogue operation this exercise matches,
 * if it is a listing that has one: a cap on items is then applied up front.
 */
export function matchedPageParam(
  details: readonly CredDelegationDetail[],
  provider: string,
  method: string,
  upstreamUrl: string,
): { param: string; max: number } | null {
  let url: URL;
  try {
    url = new URL(upstreamUrl);
  } catch {
    return null;
  }
  for (const detail of details) {
    if (detail.provider !== provider) continue;
    for (const name of detail.operations) {
      const op = catalogueOperation(name);
      if (op?.page && op.method === method && matchTemplate(op.url, url)) return op.page;
    }
  }
  return null;
}
