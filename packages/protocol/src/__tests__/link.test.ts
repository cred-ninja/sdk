import { describe, expect, it } from 'vitest';
import * as protocol from '../index.js';
import {
  LINK_API_ERROR_CODES,
  LINK_API_ERROR_STATUS,
  LINK_CONNECTION_STATUSES,
  LINK_ERROR_CODES,
  LINK_GRANT_STATUSES,
  LINK_GRANT_STATUS_FOR_CONNECTION_STATUS,
  LINK_MACHINE_CODE_FOR_CONNECTION_STATUS,
  LINK_MACHINE_CODE_FOR_GRANT_STATUS,
  LINK_MACHINE_ERROR_CODES,
  LINK_MACHINE_ERROR_STATUS,
  LINK_OPAQUE_FAILURE_BODY,
  LINK_OPAQUE_FAILURE_STATUS,
  LINK_PATHS,
  LINK_PROVIDERS,
  LINK_SCOPE_CATALOG,
  LINK_STEPS,
  LINK_STEP_TRANSITIONS,
  appendLinkRedirectResult,
  buildLinkAuthorizeQuery,
  canonicalScope,
  canonicalScopeSet,
  decodeLinkEnvelope,
  encodeLinkEnvelope,
  encodeLinkRedirectResult,
  fillLinkPath,
  findScopeCatalogEntry,
  intersectScopes,
  isConnectionId,
  isGrantId,
  isLinkActivationCode,
  isLinkClientId,
  isLinkHandle,
  isLinkMachineErrorCode,
  isLinkProviderSlug,
  isLinkRequestUri,
  isLinkStepTransitionAllowed,
  isOrgId,
  isScopeSubset,
  isTransactionId,
  linkAudienceFor,
  linkResultMessage,
  linkScopeCatalogFor,
  parseLinkAuthorizeQuery,
  parseLinkMessage,
  parseLinkRedirectResult,
  sanitizeLinkTheme,
  scopeDifference,
  scopeSetsEqual,
  scopesEquivalent,
  unionScopes,
  type LinkEnvelope,
  type LinkResult,
} from '../index.js';

const HANDLE = 'A'.repeat(42) + 'g'; // 43 base64url chars
const HANDLE2 = 'abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE';
const TID = 'ltx_0123456789abcdef0123456789abcdef' as const;
const ENV: LinkEnvelope = { h: HANDLE2, tid: TID, cid: 'acme-app' };
const REQUEST_URI = `urn:cred:link:${HANDLE2}`;
const CODE = `cred_lac_${HANDLE2}`;

/** Independent base64url encoder for building hostile inputs (Node-only, test code). */
function b64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('index re-exports', () => {
  it('exposes the Link contracts alongside the existing protocol constants', () => {
    expect(protocol.CRED_PROTOCOL_VERSION).toBe('0.1.0');
    expect(protocol.LINK_PROVIDERS).toBe(LINK_PROVIDERS);
    expect(typeof protocol.decodeLinkEnvelope).toBe('function');
  });
});

describe('enums and error codes', () => {
  it('lists exactly the seven Link providers', () => {
    expect([...LINK_PROVIDERS]).toEqual(['google', 'github', 'slack', 'notion', 'salesforce', 'linear', 'hubspot']);
    expect(isLinkProviderSlug('google')).toBe(true);
    expect(isLinkProviderSlug('salesforce-sandbox')).toBe(false);
    expect(isLinkProviderSlug(42)).toBe(false);
  });

  it('has the spec 1 widget codes and the spec 5 machine codes', () => {
    expect([...LINK_ERROR_CODES]).toEqual([
      'access_denied', 'invalid_scope', 'required_scope_declined',
      'provider_error', 'temporarily_unavailable', 'server_error',
    ]);
    for (const code of [
      'grant_revoked', 'grant_expired', 'grant_reuse_detected', 'subject_disabled', 'reauth_required',
      'provider_scope_changed', 'insufficient_scope', 'permission_required', 'consent_required',
      'scope_escalation_denied',
    ]) {
      expect(isLinkMachineErrorCode(code)).toBe(true);
    }
    expect(LINK_MACHINE_ERROR_CODES).toHaveLength(10);
  });

  it('has a status for every machine and API code', () => {
    for (const code of LINK_MACHINE_ERROR_CODES) expect(LINK_MACHINE_ERROR_STATUS[code]).toBe(403);
    for (const code of LINK_API_ERROR_CODES) expect(LINK_API_ERROR_STATUS[code]).toBeGreaterThanOrEqual(400);
  });

  it('freezes the opaque failure body to exactly {"error":"access_denied"}', () => {
    expect(JSON.stringify(LINK_OPAQUE_FAILURE_BODY)).toBe('{"error":"access_denied"}');
    expect(LINK_OPAQUE_FAILURE_STATUS).toBe(401);
    expect(Object.isFrozen(LINK_OPAQUE_FAILURE_BODY)).toBe(true);
  });

  it('maps every status to a grant status and a machine code', () => {
    for (const s of LINK_CONNECTION_STATUSES) {
      expect(LINK_GRANT_STATUSES).toContain(LINK_GRANT_STATUS_FOR_CONNECTION_STATUS[s]);
      expect(s in LINK_MACHINE_CODE_FOR_CONNECTION_STATUS).toBe(true);
    }
    for (const s of LINK_GRANT_STATUSES) expect(s in LINK_MACHINE_CODE_FOR_GRANT_STATUS).toBe(true);
    expect(LINK_MACHINE_CODE_FOR_CONNECTION_STATUS.active).toBeNull();
    expect(LINK_MACHINE_CODE_FOR_GRANT_STATUS.active).toBeNull();
    expect(LINK_MACHINE_CODE_FOR_GRANT_STATUS.expired).toBe('grant_expired');
  });

  it('allows only the documented step transitions', () => {
    for (const from of LINK_STEPS) {
      for (const to of LINK_STEPS) {
        expect(isLinkStepTransitionAllowed(from, to)).toBe(LINK_STEP_TRANSITIONS[from].includes(to));
      }
    }
    expect(isLinkStepTransitionAllowed('confirm', 'provider')).toBe(true);
    expect(isLinkStepTransitionAllowed('picker', 'confirm')).toBe(false);
    expect(isLinkStepTransitionAllowed('done', 'picker')).toBe(false);
  });
});

describe('id and secret type guards', () => {
  it('checks prefixes and bodies', () => {
    expect(isConnectionId('conn_abc123')).toBe(true);
    expect(isConnectionId('conn_')).toBe(false);
    expect(isConnectionId('conn_a-b')).toBe(false);
    expect(isConnectionId('grt_abc')).toBe(false);
    expect(isGrantId('grt_abc')).toBe(true);
    expect(isOrgId(protocol.LINK_DEFAULT_ORG_ID)).toBe(true);
    expect(isTransactionId(TID)).toBe(true);
    expect(isLinkClientId('local')).toBe(true);
    expect(isLinkClientId('-bad')).toBe(false);
    expect(isLinkClientId('a'.repeat(129))).toBe(false);
  });

  it('checks 256-bit secrets', () => {
    expect(isLinkHandle(HANDLE)).toBe(true);
    expect(isLinkHandle(HANDLE + 'A')).toBe(false);
    expect(isLinkHandle(HANDLE.slice(1) + '=')).toBe(false);
    expect(isLinkRequestUri(REQUEST_URI)).toBe(true);
    expect(isLinkRequestUri(HANDLE)).toBe(false);
    expect(isLinkActivationCode(CODE)).toBe(true);
    expect(isLinkActivationCode(HANDLE)).toBe(false);
  });
});

describe('envelope', () => {
  it('round-trips', () => {
    const encoded = encodeLinkEnvelope(ENV);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeLinkEnvelope(encoded)).toEqual(ENV);
  });

  it('encodes the documented JSON in key order h, tid, cid', () => {
    const encoded = encodeLinkEnvelope(ENV);
    expect(encoded).toBe(b64url(`{"h":"${ENV.h}","tid":"${ENV.tid}","cid":"${ENV.cid}"}`));
  });

  it('round-trips every length remainder', () => {
    for (const cid of ['a', 'ab', 'abc', 'abcd']) {
      const env = { ...ENV, cid };
      expect(decodeLinkEnvelope(encodeLinkEnvelope(env))).toEqual(env);
    }
  });

  it('throws on encoding invalid fields', () => {
    expect(() => encodeLinkEnvelope({ ...ENV, h: 'short' })).toThrow(TypeError);
    expect(() => encodeLinkEnvelope({ ...ENV, tid: 'conn_abc' as never })).toThrow(TypeError);
    expect(() => encodeLinkEnvelope({ ...ENV, cid: 'bad id' })).toThrow(TypeError);
  });

  it('returns null, never throws, on malformed input', () => {
    const good = encodeLinkEnvelope(ENV);
    const json = `{"h":"${ENV.h}","tid":"${ENV.tid}","cid":"${ENV.cid}"}`;
    const bad: unknown[] = [
      undefined, null, 42, {}, '', 'x',
      good + '=',                                  // padding
      good.replace(/.$/, '!'),                     // bad alphabet
      Buffer.from(json).toString('base64'),        // standard base64 with + or / or =
      b64url(`{"tid":"${ENV.tid}","h":"${ENV.h}","cid":"${ENV.cid}"}`), // reordered keys
      b64url(`{"h":"${ENV.h}", "tid":"${ENV.tid}","cid":"${ENV.cid}"}`), // whitespace
      b64url(`{"h":"x","h":"${ENV.h}","tid":"${ENV.tid}","cid":"${ENV.cid}"}`), // duplicate key
      b64url(`{"h":"${ENV.h}","tid":"${ENV.tid}","cid":"${ENV.cid}","x":1}`), // extra key
      b64url(`{"h":"${ENV.h}","tid":"${ENV.tid}"}`), // missing key
      b64url(`{"h":"short","tid":"${ENV.tid}","cid":"${ENV.cid}"}`),
      b64url(`{"h":"${ENV.h}","tid":"conn_abc","cid":"${ENV.cid}"}`),
      b64url(`{"h":"${ENV.h}","tid":"${ENV.tid}","cid":1}`),
      b64url(`["${ENV.h}","${ENV.tid}","${ENV.cid}"]`),
      b64url('not json'),
      b64url(json.replace('acme-app', 'acmé')), // non-ASCII
      b64url(json + '\n'),                          // control character
      'A'.repeat(protocol.LINK_ENVELOPE_MAX_LENGTH + 4),
      'AAAAA',                                       // length % 4 === 1
    ];
    for (const input of bad) {
      expect(() => decodeLinkEnvelope(input)).not.toThrow();
      expect(decodeLinkEnvelope(input)).toBeNull();
    }
  });

  it('rejects non-canonical trailing bits', () => {
    const good = encodeLinkEnvelope({ ...ENV, cid: 'ab' }); // remainder leaves spare bits
    const last = good[good.length - 1];
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const tweaked = good.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1];
    expect(decodeLinkEnvelope(tweaked)).toBeNull();
  });
});

describe('scope helpers', () => {
  it('matches the server canonicalScope rule', () => {
    const cases: Array<[string, string]> = [
      ['calendar.readonly', 'calendar.readonly'],
      ['https://www.googleapis.com/auth/calendar.readonly', 'calendar.readonly'],
      ['HTTPS://WWW.GOOGLEAPIS.COM/AUTH/Drive.File', 'drive.file'],
      ['https://www.googleapis.com/auth/drive/', 'drive'],
      ['  gmail.send  ', 'gmail.send'],
      ['openid', 'openid'],
      ['repo/', 'repo'],
      ['Read:User', 'Read:User'],
      ['https://example.com/auth/x', 'https://example.com/auth/x'],
      ['', ''],
    ];
    for (const [input, expected] of cases) expect(canonicalScope(input)).toBe(expected);
    expect(scopesEquivalent('https://www.googleapis.com/auth/gmail.send', 'gmail.send')).toBe(true);
  });

  it('builds a canonical set: deduplicated, sorted, empties dropped', () => {
    expect(canonicalScopeSet([
      'https://www.googleapis.com/auth/gmail.send', 'calendar.readonly', 'gmail.send', ' ', '',
    ])).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('computes subset, intersection, union, difference and equality', () => {
    const grant = ['calendar.readonly', 'https://www.googleapis.com/auth/gmail.send'];
    expect(isScopeSubset([], grant)).toBe(true);
    expect(isScopeSubset(['gmail.send'], grant)).toBe(true);
    expect(isScopeSubset(['gmail.send', 'drive'], grant)).toBe(false);
    expect(intersectScopes(['gmail.send', 'drive'], grant)).toEqual(['gmail.send']);
    expect(unionScopes(['drive'], grant)).toEqual(['calendar.readonly', 'drive', 'gmail.send']);
    expect(scopeDifference(['gmail.send', 'drive'], grant)).toEqual(['drive']);
    expect(scopeSetsEqual(grant, ['gmail.send', 'calendar.readonly', 'gmail.send'])).toBe(true);
    expect(scopeSetsEqual(grant, ['gmail.send'])).toBe(false);
  });

  it('does not treat wildcards specially', () => {
    expect(isScopeSubset(['crm.read'], ['crm.*'])).toBe(false);
  });
});

describe('scope catalog', () => {
  it('has canonical, unique entries for Link providers only', () => {
    const seen = new Set<string>();
    for (const e of LINK_SCOPE_CATALOG) {
      expect(isLinkProviderSlug(e.provider)).toBe(true);
      expect(canonicalScope(e.scope)).toBe(e.scope);
      expect(e.scope).not.toBe('');
      const key = `${e.provider} ${e.scope}`;
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
    for (const p of LINK_PROVIDERS) expect(linkScopeCatalogFor(p).length).toBeGreaterThan(0);
  });

  it('carries the spec 3 flags that change behavior', () => {
    expect(findScopeCatalogEntry('salesforce', 'refresh_token')?.flags).toContain('hidden');
    expect(findScopeCatalogEntry('linear', 'read')?.flags).toContain('always_required');
    expect(findScopeCatalogEntry('linear', 'admin')?.flags).toContain('never_offer');
    expect(findScopeCatalogEntry('notion', 'content')?.enforced_by).toBe('cred');
    expect(findScopeCatalogEntry('google', 'https://www.googleapis.com/auth/drive.file')?.flags).toContain('preferred_default');
    expect(findScopeCatalogEntry('google', 'gmail.modify')).toBeNull();
    expect(findScopeCatalogEntry('google', 'openid')?.flags).toContain('hidden');
    expect(findScopeCatalogEntry('google', 'https://www.googleapis.com/auth/userinfo.email')?.flags).toContain('hidden');
    expect(findScopeCatalogEntry('hubspot', 'oauth')?.flags).toContain('hidden');
    expect(findScopeCatalogEntry('google', 'gmail.compose')?.flags).toContain('restricted');
    expect(findScopeCatalogEntry('google', 'spreadsheets.readonly')?.access).toBe('read');
  });
});

describe('audience', () => {
  it('uses fixed origins and pins Salesforce to the instance host', () => {
    expect(linkAudienceFor('github')).toBe('https://api.github.com');
    expect(linkAudienceFor('salesforce')).toBeNull();
    expect(linkAudienceFor('salesforce', 'https://Acme.my.salesforce.com/')).toBe('https://acme.my.salesforce.com');
    expect(linkAudienceFor('salesforce', 'http://acme.my.salesforce.com')).toBeNull();
    expect(linkAudienceFor('salesforce', 'https://evil.example.com')).toBeNull();
    expect(linkAudienceFor('salesforce', 'https://acme.my.salesforce.com/path')).toBeNull();
    expect(linkAudienceFor('salesforce', 'https://user@acme.my.salesforce.com')).toBeNull();
    expect(linkAudienceFor('salesforce', 'https://10.0.0.1.salesforce.com')).toBeNull();
  });
});

describe('paths', () => {
  it('fills parameters with encoding', () => {
    expect(fillLinkPath(LINK_PATHS.activate, { id: 'conn_abc' })).toBe('/link/v1/connections/conn_abc/activate');
    expect(fillLinkPath(LINK_PATHS.callback, { provider: 'google' })).toBe('/link/v1/callback/google');
    expect(fillLinkPath(LINK_PATHS.connection, { id: 'a/b' })).toBe('/link/v1/connections/a%2Fb');
    expect(fillLinkPath(LINK_PATHS.par)).toBe('/link/v1/par');
    expect(() => fillLinkPath(LINK_PATHS.connection)).toThrow(TypeError);
  });
});

describe('authorize query', () => {
  it('round-trips through build and parse', () => {
    const query = {
      request_uri: REQUEST_URI,
      client_id: 'acme-app',
      mode: 'embedded' as const,
      providers: ['google' as const, 'slack' as const],
      scopes: { google: ['calendar.readonly'] },
      theme: { accent: '#ff00aa', radius: 8, colorScheme: 'dark' as const },
    };
    const qs = buildLinkAuthorizeQuery(query);
    expect(parseLinkAuthorizeQuery(qs)).toEqual(query);
    expect(parseLinkAuthorizeQuery('?' + qs)).toEqual(query);
  });

  it('defaults mode to popup and accepts parsed objects', () => {
    expect(parseLinkAuthorizeQuery({ request_uri: REQUEST_URI })).toEqual({ request_uri: REQUEST_URI, mode: 'popup' });
  });

  it('canonicalizes narrowing scopes', () => {
    const parsed = parseLinkAuthorizeQuery({
      request_uri: REQUEST_URI,
      scopes: JSON.stringify({ google: ['https://www.googleapis.com/auth/gmail.send', 'gmail.send'] }),
    });
    expect(parsed?.scopes).toEqual({ google: ['gmail.send'] });
  });

  it('rejects malformed or repeated security parameters', () => {
    const bad: Array<string | Record<string, unknown>> = [
      {},
      { request_uri: 'urn:cred:link:short' },
      { request_uri: [REQUEST_URI, REQUEST_URI] },
      `request_uri=${encodeURIComponent(REQUEST_URI)}&request_uri=${encodeURIComponent(REQUEST_URI)}`,
      { request_uri: REQUEST_URI, mode: 'iframe' },
      { request_uri: REQUEST_URI, client_id: 'bad id' },
      { request_uri: REQUEST_URI, providers: 'google,dropbox' },
      { request_uri: REQUEST_URI, providers: '' },
      { request_uri: REQUEST_URI, scopes: '{"dropbox":["x"]}' },
      { request_uri: REQUEST_URI, scopes: '{"google":"x"}' },
      { request_uri: REQUEST_URI, scopes: 'not json' },
      { request_uri: REQUEST_URI, scopes: { google: ['x'] } },
      'request_uri=%E0%A4%A',
    ];
    for (const input of bad) expect(parseLinkAuthorizeQuery(input)).toBeNull();
  });

  it('drops invalid theme fields instead of failing', () => {
    const parsed = parseLinkAuthorizeQuery({
      request_uri: REQUEST_URI,
      accent: 'red;}body{',
      radius: '99',
      logo_url: 'javascript:alert(1)',
      font: 'Inter',
    });
    expect(parsed?.theme).toEqual({ font: 'Inter' });
  });

  it('never carries the app name or logo through the authorize query', () => {
    const qs = buildLinkAuthorizeQuery({
      request_uri: REQUEST_URI,
      mode: 'popup',
      theme: { appName: 'Google Security', logoUrl: 'https://evil.example/logo.png', accent: '#112233' },
    });
    expect(qs).not.toContain('app_name');
    expect(qs).not.toContain('logo_url');
    expect(qs).not.toContain('Google');
    const parsed = parseLinkAuthorizeQuery(
      `request_uri=${encodeURIComponent(REQUEST_URI)}&app_name=Google%20Security&logo_url=${encodeURIComponent('https://evil.example/l.png')}&accent=%23112233`,
    );
    expect(parsed?.theme).toEqual({ accent: '#112233' });
  });

  it('rejects display names with invisible or bidirectional formatting characters', () => {
    expect(sanitizeLinkTheme({ appName: 'Acme \u202eelgoog\u202c' })).toEqual({});
    expect(sanitizeLinkTheme({ appName: 'Ac\u200bme' })).toEqual({});
    expect(sanitizeLinkTheme({ appName: '\ufeffAcme' })).toEqual({});
    expect(sanitizeLinkTheme({ appName: 'Acme' })).toEqual({ appName: 'Acme' });
  });

  it.each([
    ['soft hyphen', 'Goo\u00adgle'],
    ['Hangul filler', 'Acme\u3164Google'],
    ['tag characters', 'Acme\u{E0041}\u{E0042}'],
    ['variation selector', 'Acme\ufe0f'],
    ['combining grapheme joiner', 'Ac\u034fme'],
    ['private use', 'Acme\ue000'],
    ['lone surrogate', 'Acme\ud800'],
  ])('rejects a display name containing a %s', (_label, name) => {
    expect(sanitizeLinkTheme({ appName: name })).toEqual({});
  });

  it('keeps ordinary non-ASCII display names and normalizes them to NFC', () => {
    expect(sanitizeLinkTheme({ appName: 'Caf\u00e9 M\u00fcnchen' })).toEqual({ appName: 'Caf\u00e9 M\u00fcnchen' });
    expect(sanitizeLinkTheme({ appName: 'Cafe\u0301' })).toEqual({ appName: 'Caf\u00e9' });
    expect(sanitizeLinkTheme({ appName: '\u65e5\u672c\u8a9e\u30a2\u30d7\u30ea' })).toEqual({ appName: '\u65e5\u672c\u8a9e\u30a2\u30d7\u30ea' });
  });
});

describe('sanitizeLinkTheme', () => {
  it('keeps valid fields and drops the rest', () => {
    expect(sanitizeLinkTheme({
      appName: '  Acme  ',
      logoUrl: 'https://cdn.example.com/logo.png',
      accent: '#abc',
      radius: 24,
      font: 'IBM Plex Sans',
      colorScheme: 'auto',
    })).toEqual({
      appName: 'Acme',
      logoUrl: 'https://cdn.example.com/logo.png',
      accent: '#abc',
      radius: 24,
      font: 'IBM Plex Sans',
      colorScheme: 'auto',
    });
    expect(sanitizeLinkTheme({
      appName: 'a\nb',
      logoUrl: 'http://cdn.example.com/logo.png',
      accent: 'blue',
      radius: 1.5,
      font: "Inter'; }",
      colorScheme: 'sepia',
    })).toEqual({});
    expect(sanitizeLinkTheme(null)).toEqual({});
    expect(sanitizeLinkTheme({ logoUrl: 'https://x.example/"onerror' })).toEqual({});
  });
});

const SUCCESS: LinkResult = {
  outcome: 'success',
  connection_id: 'conn_abc123',
  code: CODE,
  grant_id: 'grt_abc123',
  provider: 'google',
  scopes: ['calendar.readonly', 'gmail.send'],
  state: 'csrf value&x=1',
};
const ERROR: LinkResult = { outcome: 'error', error: 'required_scope_declined', request_id: 'req_abc', state: 's' };
const EXIT: LinkResult = { outcome: 'exit', step: 'confirm', provider: 'slack' };

describe('postMessage payloads', () => {
  it('round-trips result messages', () => {
    for (const r of [SUCCESS, ERROR, EXIT]) {
      const msg = linkResultMessage(r);
      expect(msg.type).toBe('cred.link.result');
      expect(msg.v).toBe(1);
      expect(parseLinkMessage(JSON.parse(JSON.stringify(msg)))).toEqual(msg);
    }
  });

  it('parses step and resize messages', () => {
    expect(parseLinkMessage({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'github' }))
      .toEqual({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'github' });
    expect(parseLinkMessage({ type: 'cred.link.resize', v: 1, height: 420 }))
      .toEqual({ type: 'cred.link.resize', v: 1, height: 420 });
  });

  it('strips unknown fields', () => {
    const parsed = parseLinkMessage({ ...linkResultMessage(EXIT), extra: '<script>' });
    expect(parsed).toEqual(linkResultMessage(EXIT));
  });

  it('rejects malformed messages', () => {
    const bad: unknown[] = [
      null, 'cred.link.result', [],
      { type: 'cred.link.result', v: 2, outcome: 'exit', step: 'picker' },
      { type: 'cred.link.result', v: 1, outcome: 'exit', step: 'done' },
      { type: 'cred.link.result', v: 1, outcome: 'nope' },
      { type: 'cred.link.result', v: 1, outcome: 'error', error: 'grant_revoked', request_id: 'req_1' },
      { type: 'cred.link.result', v: 1, outcome: 'error', error: 'access_denied', request_id: '' },
      { ...linkResultMessage(SUCCESS), code: 'abc' },
      { ...linkResultMessage(SUCCESS), connection_id: 'grt_abc' },
      { ...linkResultMessage(SUCCESS), scopes: 'calendar.readonly' },
      { ...linkResultMessage(SUCCESS), state: 1 },
      { type: 'cred.link.step', v: 1, step: 'picker', provider: 'dropbox' },
      { type: 'cred.link.resize', v: 1, height: -1 },
      { type: 'cred.link.resize', v: 1, height: Number.NaN },
      { type: 'cred.link.other', v: 1 },
    ];
    for (const m of bad) expect(parseLinkMessage(m)).toBeNull();
  });
});

describe('redirect-mode results', () => {
  it('round-trips every outcome', () => {
    for (const r of [SUCCESS, ERROR, EXIT]) {
      expect(parseLinkRedirectResult(encodeLinkRedirectResult(r))).toEqual(r);
    }
  });

  it('round-trips an empty scope list', () => {
    const r: LinkResult = { ...SUCCESS, scopes: [] } as LinkResult;
    expect(parseLinkRedirectResult(encodeLinkRedirectResult(r))).toEqual(r);
  });

  it('appends to registered redirect URIs', () => {
    const url = appendLinkRedirectResult('https://app.example.com/cred/return', EXIT);
    expect(url).toBe('https://app.example.com/cred/return?cred_link=exit&step=confirm&provider=slack');
    const withQuery = appendLinkRedirectResult('https://app.example.com/r?tab=1', ERROR);
    expect(withQuery.startsWith('https://app.example.com/r?tab=1&cred_link=error&')).toBe(true);
    expect(parseLinkRedirectResult(withQuery.slice(withQuery.indexOf('?')))).toEqual(ERROR);
    expect(() => appendLinkRedirectResult('https://app.example.com/r#x', EXIT)).toThrow(TypeError);
  });

  it('ignores the developer\'s own parameters and accepts parsed objects', () => {
    expect(parseLinkRedirectResult({ cred_link: 'exit', step: 'picker', foo: ['1', '2'] }))
      .toEqual({ outcome: 'exit', step: 'picker' });
  });

  it('rejects absent, malformed or repeated Link parameters', () => {
    const bad = [
      '',
      'foo=bar',
      'cred_link=success&connection_id=conn_a&code=nope&grant_id=grt_a&provider=google&scope=x',
      'cred_link=success&connection_id=conn_a&code=' + CODE + '&grant_id=grt_a&provider=google',
      'cred_link=success&connection_id=conn_a&code=' + CODE + '&grant_id=grt_a&provider=google&scope=a%20%20b',
      'cred_link=error&error=access_denied',
      'cred_link=exit&step=picker&step=confirm',
      'cred_link=exit&cred_link=error&step=picker',
      'cred_link=exit&step=%E0%A4%A',
    ];
    for (const q of bad) expect(parseLinkRedirectResult(q)).toBeNull();
  });
});

describe('polish: narrow path, ack handshake, handoff, redirect via', () => {
  it('exposes the narrow path', () => {
    expect(protocol.fillLinkPath(protocol.LINK_PATHS.narrow, { id: 'conn_abc' })).toBe('/link/v1/connections/conn_abc/narrow');
  });

  it('builds and recognizes the ack message only', () => {
    expect(protocol.linkAckMessage()).toEqual({ type: 'cred.link.ack', v: 1 });
    expect(protocol.isLinkAckMessage(protocol.linkAckMessage())).toBe(true);
    expect(protocol.isLinkAckMessage({ type: 'cred.link.ack', v: 2 })).toBe(false);
    expect(protocol.isLinkAckMessage({ type: 'cred.link.result', v: 1 })).toBe(false);
    expect(protocol.isLinkAckMessage(null)).toBe(false);
    // The widget never accepts an ack as a page message.
    expect(protocol.parseLinkMessage(protocol.linkAckMessage())).toBeNull();
  });

  it('accepts a redirect handoff only on the provider step with a provider', () => {
    expect(protocol.parseLinkMessage({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google', handoff: 'redirect' }))
      .toEqual({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google', handoff: 'redirect' });
    expect(protocol.parseLinkMessage({ type: 'cred.link.step', v: 1, step: 'provider', handoff: 'redirect' })).toBeNull();
    expect(protocol.parseLinkMessage({ type: 'cred.link.step', v: 1, step: 'picker', provider: 'google', handoff: 'redirect' })).toBeNull();
    expect(protocol.parseLinkMessage({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google', handoff: 'popup' })).toBeNull();
  });

  it('marks and reads a popup fallback without changing the parsed result', () => {
    const result = {
      outcome: 'exit' as const,
      step: 'confirm' as const,
      state: 's1',
    };
    const plain = protocol.appendLinkRedirectResult('https://app.example.com/return', result);
    const via = protocol.appendLinkRedirectResult('https://app.example.com/return', result, { via: 'popup' });
    expect(plain).not.toContain('cred_link_via');
    expect(via.endsWith('&cred_link_via=popup')).toBe(true);
    const q = via.slice(via.indexOf('?'));
    expect(protocol.parseLinkRedirectResult(q)).toEqual(protocol.parseLinkRedirectResult(plain.slice(plain.indexOf('?'))));
    expect(protocol.parseLinkRedirectVia(q)).toBe('popup');
    expect(protocol.parseLinkRedirectVia(plain.slice(plain.indexOf('?')))).toBeNull();
    // Malformed or repeated markers fail closed.
    expect(protocol.parseLinkRedirectVia(q + '&cred_link_via=popup')).toBeNull();
    expect(protocol.parseLinkRedirectResult(q.replace('cred_link_via=popup', 'cred_link_via=other'))).toBeNull();
    expect(protocol.parseLinkRedirectResult(q + '&cred_link_via=popup')).toBeNull();
  });
});

describe('polish: relay flow id and narrow enforcement', () => {
  const flow = 'a'.repeat(64);
  const result = { outcome: 'exit' as const, step: 'confirm' as const };

  it('appends a flow id only with the via marker and reads it back', () => {
    const url = protocol.appendLinkRedirectResult('https://app.example.com/r', result, { via: 'popup', flow_id: flow });
    const q = url.slice(url.indexOf('?'));
    expect(url.endsWith(`&cred_link_via=popup&cred_link_flow=${flow}`)).toBe(true);
    expect(protocol.parseLinkRedirectFlowId(q)).toBe(flow);
    expect(protocol.parseLinkRedirectVia(q)).toBe('popup');
    expect(protocol.parseLinkRedirectResult(q)).toEqual(result);
    expect(() => protocol.appendLinkRedirectResult('https://app.example.com/r', result, { flow_id: flow })).toThrow(TypeError);
    expect(() => protocol.appendLinkRedirectResult('https://app.example.com/r', result, { via: 'popup', flow_id: 'ABC' })).toThrow(TypeError);
  });

  it('fails closed on a stray, malformed or repeated flow id', () => {
    const base = 'cred_link=exit&step=confirm';
    expect(protocol.parseLinkRedirectFlowId(`${base}&cred_link_flow=${flow}`)).toBeNull();
    expect(protocol.parseLinkRedirectResult(`${base}&cred_link_flow=${flow}`)).toBeNull();
    expect(protocol.parseLinkRedirectResult(`${base}&cred_link_via=popup&cred_link_flow=${flow.toUpperCase()}`)).toBeNull();
    expect(protocol.parseLinkRedirectResult(`${base}&cred_link_via=popup&cred_link_flow=${flow}&cred_link_flow=${flow}`)).toBeNull();
    expect(protocol.parseLinkRedirectFlowId(`${base}&cred_link_via=popup`)).toBeNull();
    expect(protocol.parseLinkRedirectResult(`${base}&cred_link_via=popup`)).toEqual(result);
  });

  it('reports broker enforcement for Google only', () => {
    expect(protocol.linkNarrowEnforcementFor('google')).toBe('broker');
    for (const p of protocol.LINK_PROVIDERS) {
      if (p !== 'google') expect(protocol.linkNarrowEnforcementFor(p)).toBe('record');
    }
  });
});

