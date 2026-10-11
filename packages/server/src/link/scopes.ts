/**
 * Cred Link server: scope catalog rules (spec 3, decision 10).
 *
 *   hidden            requested from the provider when the provider is used,
 *                     never a toggle, never in a grant; PAR naming one fails
 *   always_required   added to requested and required scopes at PAR, locked
 *   never_offer       PAR naming one fails with invalid_scope
 *   preferred_default pre-selected on the picker
 *
 * Provider scopes map one to one onto catalog scopes: the "smallest provider
 * scope set that covers the toggles" is exactly the selected provider-
 * enforced toggles plus the provider's hidden and always_required scopes.
 * No implication table is applied (for example `drive` is not treated as
 * covering `drive.readonly`), because the store only lets a grant hold a
 * provider-enforced scope the provider literally granted.
 */

import {
  LINK_SCOPE_CATALOG,
  canonicalScope,
  canonicalScopeSet,
  findScopeCatalogEntry,
  linkScopeCatalogFor,
} from '@credninja/protocol';
import type { LinkProviderSlug, ScopeCatalogEntry } from '@credninja/protocol';

const MAX_SCOPE_LENGTH = 256;
const MAX_SCOPES_PER_PROVIDER = 64;

export type ScopeListResult =
  | { ok: true; scopes: string[] }
  | { ok: false; error: 'invalid_request' | 'invalid_scope' };

/**
 * Validate one provider's scope list from a PAR body: strings, catalog
 * entries only, never hidden or never_offer. Returns canonical scopes.
 */
export function validateRequestedScopes(provider: LinkProviderSlug, value: unknown): ScopeListResult {
  if (!Array.isArray(value) || value.length > MAX_SCOPES_PER_PROVIDER) return { ok: false, error: 'invalid_request' };
  for (const scope of value) {
    if (typeof scope !== 'string' || scope.trim() === '' || scope.length > MAX_SCOPE_LENGTH) {
      return { ok: false, error: 'invalid_request' };
    }
    const entry = findScopeCatalogEntry(provider, scope);
    if (!entry) return { ok: false, error: 'invalid_scope' };
    if (entry.flags.includes('hidden') || entry.flags.includes('never_offer')) return { ok: false, error: 'invalid_scope' };
  }
  return { ok: true, scopes: canonicalScopeSet(value as string[]) };
}

function withFlag(provider: LinkProviderSlug, flag: ScopeCatalogEntry['flags'][number]): string[] {
  return canonicalScopeSet(linkScopeCatalogFor(provider).filter((e) => e.flags.includes(flag)).map((e) => e.scope));
}

/** Catalog scopes flagged always_required for a provider. */
export function alwaysRequiredScopes(provider: LinkProviderSlug): string[] {
  return withFlag(provider, 'always_required');
}

/** Catalog scopes flagged hidden for a provider. */
export function hiddenScopes(provider: LinkProviderSlug): string[] {
  return withFlag(provider, 'hidden');
}

/** True when the scope is a hidden catalog scope of the provider. */
export function isHiddenScope(provider: LinkProviderSlug, scope: string): boolean {
  return findScopeCatalogEntry(provider, scope)?.flags.includes('hidden') === true;
}

/**
 * What to send to the provider for a selection: the selected provider-
 * enforced scopes, plus hidden and always_required. Cred-enforced scopes
 * (Notion `content`) are never sent.
 */
export function providerRequestScopes(provider: LinkProviderSlug, selected: readonly string[]): string[] {
  const out = new Set<string>();
  for (const scope of canonicalScopeSet(selected)) {
    const entry = findScopeCatalogEntry(provider, scope);
    if (entry && entry.enforced_by === 'provider') out.add(entry.scope);
  }
  for (const scope of hiddenScopes(provider)) out.add(scope);
  for (const scope of alwaysRequiredScopes(provider)) out.add(scope);
  return canonicalScopeSet([...out]);
}

/**
 * Scopes a grant may hold given what the provider granted (mirrors the
 * store's own rule): non-hidden catalog scopes of the provider that are
 * Cred-enforced or literally granted.
 */
export function grantableScopes(provider: LinkProviderSlug, granted: readonly string[]): string[] {
  const g = new Set(canonicalScopeSet(granted));
  const out: string[] = [];
  for (const e of LINK_SCOPE_CATALOG) {
    if (e.provider !== provider || e.flags.includes('hidden')) continue;
    if (e.enforced_by === 'cred' || g.has(e.scope)) out.push(e.scope);
  }
  return canonicalScopeSet(out);
}

/** Split a provider `scope` value (space or comma separated) into canonical scopes. */
export function parseGrantedScopeString(value: unknown): string[] | null {
  if (Array.isArray(value)) {
    return canonicalScopeSet(value.filter((s): s is string => typeof s === 'string'));
  }
  if (typeof value !== 'string') return null;
  return canonicalScopeSet(value.split(/[\s,]+/).map((s) => canonicalScope(s)).filter(Boolean));
}

/** Catalog entry for display; null for scopes outside the catalog. */
export function catalogEntry(provider: LinkProviderSlug, scope: string): ScopeCatalogEntry | null {
  return findScopeCatalogEntry(provider, scope);
}

/** Human text for display-only catalog flags. */
export const FLAG_HINTS: Partial<Record<ScopeCatalogEntry['flags'][number], string>> = {
  includes_delete: 'Includes delete',
  over_broad: 'Broad access',
  restricted: 'Restricted scope',
  ambiguous: 'Wider than its name suggests',
  no_read_only_form: 'No read-only form',
  not_data_permission: 'Not a data permission',
};
