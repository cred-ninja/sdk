/**
 * Delegation-only read scopes. GitHub, Salesforce and Notion have no read-only
 * scope to ask the provider for, so a connection holding wider consent can hand
 * an agent a read-only delegation that only the broker enforces. The provider
 * token is unchanged, so these mean nothing outside the broker.
 *
 * Coverage runs one way, from the wider scope to the read. Two helpers, because
 * two kinds of list exist:
 *
 *   withDerivedScopes: a grant list (Permission, ceiling, parent delegation,
 *     capabilities). It means what it names, and an empty list stays empty.
 *   withStoredDerivedScopes: what a stored connection holds. A Notion token
 *     carries no scopes, since its capabilities are set on the integration, so an
 *     empty stored list is the whole connection.
 */
interface DerivedReadScope {
  scope: string;
  /** Grant-list scopes that cover it. */
  from: readonly string[];
  /**
   * `[narrower, wider]`: a token holding the wider scope reaches past a grant
   * that names only the narrower one, so the read may not be derived from it.
   * Naming the read itself, or the wider scope, is how an operator allows it.
   */
  outgrown: readonly [string, string];
}

const DERIVED_READ_SCOPES: Readonly<Record<string, DerivedReadScope>> = {
  github: { scope: 'github.read', from: ['repo', 'public_repo'], outgrown: ['public_repo', 'repo'] },
  salesforce: { scope: 'salesforce.read', from: ['api', 'full'], outgrown: ['api', 'full'] },
  notion: { scope: 'notion.read', from: ['content', 'read_content'], outgrown: ['read_content', 'content'] },
};

/** Cred's name for all a Notion connection can do. */
const NOTION_WHOLE_CONNECTION = 'content';

function derivedFor(service: string): DerivedReadScope | undefined {
  return Object.prototype.hasOwnProperty.call(DERIVED_READ_SCOPES, service) ? DERIVED_READ_SCOPES[service] : undefined;
}

/** A grant list plus what its scopes derive. An empty list stays empty. */
export function withDerivedScopes(service: string, scopes: readonly string[]): string[] {
  const derived = derivedFor(service);
  if (!derived || scopes.includes(derived.scope) || !derived.from.some((scope) => scopes.includes(scope))) return [...scopes];
  return [...scopes, derived.scope];
}

/**
 * A grant list plus what its scopes derive, over a token that holds `held`.
 *
 * A derived read is Cred's name for access the raw token already carries, so it
 * can only mean what the token can reach and no more than the grant names. Where
 * a narrower grant scope and a wider token scope both exist, a read backed by the
 * wider one reaches past the grant: `public_repo` cannot derive `github.read`
 * over a `repo` token, `api` cannot derive `salesforce.read` over a `full` token,
 * and `read_content` cannot derive `notion.read` over a `content` token. Naming
 * the read itself, or the wider scope, is what an operator does to allow it.
 */
export function withDerivedScopesUnder(service: string, scopes: readonly string[], held: readonly string[]): string[] {
  const derived = derivedFor(service);
  if (!derived) return [...scopes];
  // Naming the read itself is an explicit grant: it needs no source scope.
  if (scopes.includes(derived.scope)) return [...scopes];
  const [narrower, wider] = derived.outgrown;
  if (scopes.includes(narrower) && !scopes.includes(wider) && held.includes(wider)) return [...scopes];
  return withDerivedScopes(service, scopes);
}

/** Whether this service has a delegation-only read scope derived from a stored scope. */
export function hasDerivedReadScope(service: string): boolean {
  return derivedFor(service) !== undefined;
}

/**
 * Every scope a derived read can come from: what a connection whose stored
 * scopes cannot be read might hold. Nothing is derived from a narrow grant over
 * one, so an unverifiable derivation is refused rather than assumed.
 */
export function widestDerivedReadSources(): string[] {
  return [...new Set(Object.values(DERIVED_READ_SCOPES).flatMap((entry) => entry.from))];
}

/** What a stored connection covers: its scopes, what they derive, and Notion's whole-connection rule. */
export function withStoredDerivedScopes(service: string, stored: readonly string[]): string[] {
  if (service === 'notion' && stored.length === 0) return ['notion.read', NOTION_WHOLE_CONNECTION];
  return withDerivedScopes(service, stored);
}

/** Drop a derived scope whose source is also in the list: what was stored is issued, not both names. */
export function withoutRedundantDerivedScopes(service: string, scopes: readonly string[]): string[] {
  const derived = derivedFor(service);
  if (!derived) return [...scopes];
  const covered = (service === 'notion' ? [NOTION_WHOLE_CONNECTION] : derived.from).some((scope) => scopes.includes(scope));
  return covered ? scopes.filter((scope) => scope !== derived.scope) : [...scopes];
}

/** Whether a scope means anything only at the broker, so it can never describe a raw token. */
export function isBrokerOnlyScope(service: string, scope: string): boolean {
  return derivedFor(service)?.scope === scope;
}

/**
 * What to ask a provider for at consent. A derived scope is Cred's name, so a
 * provider gets the real scope it depends on. Notion takes no scopes at all: its
 * capabilities are set on the integration.
 */
export function providerScopesFor(service: string, scopes: readonly string[]): string[] {
  if (service === 'notion') return [];
  const derived = derivedFor(service);
  return [...new Set(scopes.map((scope) => (derived?.scope === scope ? derived.from[0]! : scope)))];
}
