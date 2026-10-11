/**
 * Google API families for the broker's URL check, shared by the broker
 * (server.ts resolveBrokerUrl) and Link's narrow response (which reports
 * whether the broker can enforce a narrowing). One table and one matcher,
 * so the two cannot drift.
 *
 * Enforcement is per family, not per scope: any scope of a family unlocks
 * every URL under that family's bases. Read and write scopes of one family
 * (gmail.readonly and gmail.send, calendar.readonly and calendar.events,
 * drive.file and drive, ...) are not told apart.
 */

export interface GoogleScopeFamily {
  scopes: string[];
  bases: string[];
}

export const GOOGLE_SCOPE_ENDPOINTS: readonly GoogleScopeFamily[] = [
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

/** Canonical form of a scope for the broker's comparisons (trim, one trailing slash, Google auth URL to short name). */
export function brokerCanonicalScope(scope: string): string {
  const trimmed = scope.trim().replace(/\/$/, '');
  const normalized = trimmed.toLowerCase();
  const googleAuthPrefix = 'https://www.googleapis.com/auth/';
  if (normalized.startsWith(googleAuthPrefix)) {
    return normalized.slice(googleAuthPrefix.length);
  }
  return trimmed;
}

/** Exact equality in canonical form. */
export function brokerScopeEquivalent(left: string, right: string): boolean {
  return brokerCanonicalScope(left) === brokerCanonicalScope(right);
}

/** Whether a granted scope satisfies a family's required scope (the broker's rule). */
export function googleScopeMatches(grantedScope: string, requiredScope: string): boolean {
  const normalized = grantedScope.toLowerCase().replace(/\/$/, '');
  const required = requiredScope.toLowerCase();
  return brokerScopeEquivalent(grantedScope, requiredScope) ||
    normalized.endsWith(`/${required}`) ||
    normalized.endsWith(`auth/${required}`) ||
    normalized.includes(`//${required}`);
}

/** Whether the broker lets these scopes call this (normalized) Google URL. */
export function isAllowedGoogleScopeEndpoint(normalizedUrl: string, scopes?: string[]): boolean {
  if (!scopes || scopes.length === 0) return false;
  return GOOGLE_SCOPE_ENDPOINTS.some(({ scopes: requiredScopes, bases }) => (
    bases.some((base) => normalizedUrl.startsWith(base)) &&
    requiredScopes.some((requiredScope) => scopes.some((scope) => googleScopeMatches(scope, requiredScope)))
  ));
}

/** Indexes of the families a scope unlocks (empty when it belongs to none). */
export function googleScopeFamilies(scope: string): number[] {
  const out: number[] = [];
  GOOGLE_SCOPE_ENDPOINTS.forEach(({ scopes }, index) => {
    if (scopes.some((requiredScope) => googleScopeMatches(scope, requiredScope))) out.push(index);
  });
  return out;
}

/**
 * Whether the broker refuses every Google URL that only the removed scopes
 * unlocked: each removed scope belongs to at least one family, and no scope
 * that remains unlocks any of those families. False when a removed scope
 * shares a family with a remaining scope or belongs to no family.
 */
export function googleRemovalIsBrokerEnforced(removed: readonly string[], remaining: readonly string[]): boolean {
  const kept = new Set(remaining.flatMap((scope) => googleScopeFamilies(scope)));
  return removed.every((scope) => {
    const families = googleScopeFamilies(scope);
    return families.length > 0 && families.every((family) => !kept.has(family));
  });
}
