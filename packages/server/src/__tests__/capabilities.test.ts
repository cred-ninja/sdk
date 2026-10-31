/**
 * The operation catalogue is security-critical: a wrong template widens
 * authority. Every entry has an allow case and a deny case here.
 */
import { describe, it, expect } from 'vitest';
import {
  OPERATION_CATALOGUE,
  capabilitiesAllow,
  capabilitiesSubsumed,
  validateCapabilities,
} from '../capabilities.js';
import type { CredDelegationDetail } from '@credninja/attenuation';

const gh = (operations: string[], resources?: string[]): CredDelegationDetail =>
  ({ type: 'cred_delegation', provider: 'github', operations, ...(resources ? { resources } : {}) });
const drive = (operations: string[], resources?: string[]): CredDelegationDetail =>
  ({ type: 'cred_delegation', provider: 'google', operations, ...(resources ? { resources } : {}) });
const noScopes = () => false;

// One allowed request per catalogue entry, and a near miss it must refuse.
const CASES: Record<string, { method: string; allow: string; deny: [string, string] }> = {
  'github.user.get': { method: 'GET', allow: 'https://api.github.com/user', deny: ['GET', 'https://api.github.com/user/emails'] },
  'github.repos.get': { method: 'GET', allow: 'https://api.github.com/repos/acme/app', deny: ['DELETE', 'https://api.github.com/repos/acme/app'] },
  'github.contents.get': { method: 'GET', allow: 'https://api.github.com/repos/acme/app/contents/src/index.ts', deny: ['PUT', 'https://api.github.com/repos/acme/app/contents/src/index.ts'] },
  'github.issues.list': { method: 'GET', allow: 'https://api.github.com/repos/acme/app/issues', deny: ['POST', 'https://api.github.com/repos/acme/app/issues'] },
  'github.issues.get': { method: 'GET', allow: 'https://api.github.com/repos/acme/app/issues/7', deny: ['PATCH', 'https://api.github.com/repos/acme/app/issues/7'] },
  'github.issues.create': { method: 'POST', allow: 'https://api.github.com/repos/acme/app/issues', deny: ['POST', 'https://api.github.com/repos/acme/app/issues/7/lock'] },
  'github.issues.comment': { method: 'POST', allow: 'https://api.github.com/repos/acme/app/issues/7/comments', deny: ['DELETE', 'https://api.github.com/repos/acme/app/issues/7/comments'] },
  'github.pulls.list': { method: 'GET', allow: 'https://api.github.com/repos/acme/app/pulls', deny: ['GET', 'https://api.github.com/repos/acme/app/pulls/7/merge'] },
  'github.pulls.get': { method: 'GET', allow: 'https://api.github.com/repos/acme/app/pulls/7', deny: ['PUT', 'https://api.github.com/repos/acme/app/pulls/7/merge'] },
  'drive.files.list': { method: 'GET', allow: 'https://www.googleapis.com/drive/v3/files?q=x', deny: ['DELETE', 'https://www.googleapis.com/drive/v3/files/abc'] },
  'drive.files.get': { method: 'GET', allow: 'https://www.googleapis.com/drive/v3/files/abc', deny: ['DELETE', 'https://www.googleapis.com/drive/v3/files/abc'] },
  'drive.files.export': { method: 'GET', allow: 'https://www.googleapis.com/drive/v3/files/abc/export?mimeType=text/plain', deny: ['GET', 'https://www.googleapis.com/drive/v3/files/abc/permissions'] },
  'drive.files.create': { method: 'POST', allow: 'https://www.googleapis.com/drive/v3/files', deny: ['POST', 'https://www.googleapis.com/drive/v3/files/abc/copy'] },
};

describe('operation catalogue', () => {
  it('has an allow and a deny case for every entry', () => {
    expect(new Set(Object.keys(CASES))).toEqual(new Set(OPERATION_CATALOGUE.map((op) => op.name)));
  });

  for (const op of OPERATION_CATALOGUE) {
    it(`${op.name} allows exactly its method and template`, () => {
      const c = CASES[op.name]!;
      const details = [{ type: 'cred_delegation' as const, provider: op.provider, operations: [op.name] }];
      expect(capabilitiesAllow(details, op.provider, c.method, c.allow, noScopes)).toBe(true);
      expect(capabilitiesAllow(details, op.provider, c.deny[0], c.deny[1], noScopes)).toBe(false);
      // Another provider's entry never matches.
      expect(capabilitiesAllow(details, op.provider === 'github' ? 'google' : 'github', c.method, c.allow, noScopes)).toBe(false);
    });
  }
});

describe('resources', () => {
  it('narrow a GitHub operation to one repository, case-insensitively', () => {
    const details = [gh(['github.issues.create'], ['repo:acme/app'])];
    expect(capabilitiesAllow(details, 'github', 'POST', 'https://api.github.com/repos/Acme/App/issues', noScopes)).toBe(true);
    expect(capabilitiesAllow(details, 'github', 'POST', 'https://api.github.com/repos/acme/other/issues', noScopes)).toBe(false);
    expect(capabilitiesAllow(details, 'github', 'POST', 'https://api.github.com/repos/evil/app/issues', noScopes)).toBe(false);
  });

  it('narrow a Drive operation to one file, case-sensitively', () => {
    const details = [drive(['drive.files.get'], ['file:AbC123'])];
    expect(capabilitiesAllow(details, 'google', 'GET', 'https://www.googleapis.com/drive/v3/files/AbC123', noScopes)).toBe(true);
    expect(capabilitiesAllow(details, 'google', 'GET', 'https://www.googleapis.com/drive/v3/files/abc123', noScopes)).toBe(false);
  });

  it('do not let an encoded slash bind a different repository', () => {
    const details = [gh(['github.repos.get'], ['repo:acme/app'])];
    expect(capabilitiesAllow(details, 'github', 'GET', 'https://api.github.com/repos/acme%2Fapp/x', noScopes)).toBe(false);
  });
});

describe('template parameters', () => {
  it('bind only numbers to {number}, so issues.get never reaches another endpoint', () => {
    const details = [gh(['github.issues.get'], ['repo:acme/app'])];
    expect(capabilitiesAllow(details, 'github', 'GET', 'https://api.github.com/repos/acme/app/issues/42', noScopes)).toBe(true);
    expect(capabilitiesAllow(details, 'github', 'GET', 'https://api.github.com/repos/acme/app/issues/comments', noScopes)).toBe(false);
    expect(capabilitiesAllow(details, 'github', 'GET', 'https://api.github.com/repos/acme/app/issues/events', noScopes)).toBe(false);
  });

  it('let contents.get read a repository root', () => {
    const details = [gh(['github.contents.get'], ['repo:acme/app'])];
    expect(capabilitiesAllow(details, 'github', 'GET', 'https://api.github.com/repos/acme/app/contents', noScopes)).toBe(true);
  });
});

describe('scope operations', () => {
  it('defer to the broker scope rules, and are not narrowed by resources', () => {
    expect(capabilitiesAllow([gh(['repo'])], 'github', 'DELETE', 'https://api.github.com/repos/acme/app', () => true)).toBe(true);
    expect(capabilitiesAllow([gh(['repo'])], 'github', 'GET', 'https://api.github.com/user', () => false)).toBe(false);
  });
});

describe('validateCapabilities', () => {
  it('accepts granted scopes and catalogue operations the scopes make available', () => {
    const result = validateCapabilities([gh(['repo', 'github.issues.create'], ['repo:acme/app']).operations.length ? gh(['github.issues.create'], ['repo:acme/app']) : null], 'github', ['repo']);
    expect(result.ok).toBe(true);
    expect(validateCapabilities([gh(['repo'])], 'github', ['repo']).ok).toBe(true);
    expect(validateCapabilities([drive(['drive.files.get'], ['file:abc'])], 'google', ['https://www.googleapis.com/auth/drive.readonly']).ok).toBe(true);
  });

  it('refuses unknown operations, ungranted ones, and other providers', () => {
    expect(validateCapabilities([gh(['github.repos.delete'])], 'github', ['repo'])).toMatchObject({ ok: false, message: /unknown operation/ });
    expect(validateCapabilities([gh(['github.issues.create'])], 'github', ['read:user'])).toMatchObject({ ok: false, message: /needs a scope/ });
    expect(validateCapabilities([gh(['admin:org'])], 'github', ['repo'])).toMatchObject({ ok: false, message: /unknown operation/ });
    expect(validateCapabilities([drive(['drive.files.get'])], 'github', ['repo'])).toMatchObject({ ok: false, message: /provider/ });
  });

  it('refuses resources on scope operations, unknown kinds, and malformed values', () => {
    expect(validateCapabilities([gh(['repo'], ['repo:acme/app'])], 'github', ['repo'])).toMatchObject({ ok: false });
    expect(validateCapabilities([drive(['drive.files.list'], ['folder:abc'])], 'google', ['drive.readonly'])).toMatchObject({ ok: false });
    expect(validateCapabilities([gh(['github.repos.get'], ['repo:acme'])], 'github', ['repo'])).toMatchObject({ ok: false });
    expect(validateCapabilities([gh(['github.repos.get'], ['repo:acme/app/x'])], 'github', ['repo'])).toMatchObject({ ok: false });
    expect(validateCapabilities([gh(['github.repos.get', 'github.user.get'], ['repo:acme/app'])], 'github', ['repo', 'read:user'])).toMatchObject({ ok: false });
  });

  it('refuses scope operations beside catalogue operations, which would widen them', () => {
    // A GitHub scope operation allows the whole API: beside a narrowed entry it
    // would turn a token that looks narrow into a broad one.
    expect(validateCapabilities([gh(['github.issues.list'], ['repo:a/b']), gh(['read:user'])], 'github', ['repo', 'read:user']))
      .toMatchObject({ ok: false, message: /not both/ });
    expect(validateCapabilities([gh(['repo', 'github.issues.list'])], 'github', ['repo'])).toMatchObject({ ok: false, message: /not both/ });
  });

  it('accepts a Google scope operation in the short form, stored in the granted spelling', () => {
    const result = validateCapabilities([drive(['drive.readonly'])], 'google', ['https://www.googleapis.com/auth/drive.readonly']);
    expect(result).toMatchObject({ ok: true, details: [{ operations: ['https://www.googleapis.com/auth/drive.readonly'] }] });
  });

  it('refuses unknown members and the wrong type', () => {
    expect(validateCapabilities([{ ...gh(['repo']), actions: ['x'] }], 'github', ['repo'])).toMatchObject({ ok: false });
    expect(validateCapabilities([{ ...gh(['repo']), type: 'agent_delegation' }], 'github', ['repo'])).toMatchObject({ ok: false });
    expect(validateCapabilities([], 'github', ['repo'])).toMatchObject({ ok: false });
  });
});

describe('capabilitiesSubsumed', () => {
  it('accepts equal or narrower children', () => {
    expect(capabilitiesSubsumed([gh(['repo'])], [gh(['github.issues.create'], ['repo:acme/app'])])).toBe(true);
    expect(capabilitiesSubsumed([gh(['github.issues.create', 'github.issues.list'], ['repo:acme/app', 'repo:acme/web'])],
      [gh(['github.issues.list'], ['repo:acme/web'])])).toBe(true);
  });

  it('accepts a narrower scope under a wildcard scope, and a repository named in another case', () => {
    expect(capabilitiesSubsumed([gh(['repo.*'])], [gh(['repo.read'])])).toBe(true);
    expect(capabilitiesSubsumed([gh(['github.issues.list'], ['repo:acme/app'])], [gh(['github.issues.list'], ['repo:Acme/App'])])).toBe(true);
  });

  it('refuses wider children', () => {
    expect(capabilitiesSubsumed([gh(['github.issues.list'], ['repo:acme/app'])], [gh(['github.issues.list'])])).toBe(false);
    expect(capabilitiesSubsumed([gh(['github.issues.list'], ['repo:acme/app'])], [gh(['github.issues.list'], ['repo:acme/other'])])).toBe(false);
    expect(capabilitiesSubsumed([gh(['github.issues.list'])], [gh(['github.issues.create'])])).toBe(false);
    expect(capabilitiesSubsumed([gh(['github.issues.list'])], [gh(['repo'])])).toBe(false);
    expect(capabilitiesSubsumed([gh(['repo'])], [drive(['drive.files.get'])])).toBe(false);
  });
});
