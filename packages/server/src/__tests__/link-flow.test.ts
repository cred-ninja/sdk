import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import crypto from 'crypto';
import { computeChallenge } from '@credninja/oauth';
import { decodeLinkEnvelope, LINK_OPAQUE_FAILURE_BODY } from '@credninja/protocol';
import {
  ADMIN_TOKEN,
  APP_ORIGIN,
  APP_REDIRECT,
  BASE,
  Browser,
  CALENDAR_URL,
  activate,
  authorizePath,
  callback,
  confirm,
  connectAndActivate,
  connectFlow,
  delegate,
  envelopeOf,
  makeHarness,
  pageConfig,
  par,
  parBody,
  registerClient,
  resultOf,
  toProvider,
  use,
} from './link-harness.js';
import type { Harness } from './link-harness.js';

let h: Harness;

beforeEach(async () => {
  h = await makeHarness();
});

afterEach(() => {
  h.close();
});

function cspOf(res: request.Response): string {
  return String(res.headers['content-security-policy'] ?? '');
}

describe('Cred Link end to end (redirect mode)', () => {
  it('registers a client, pushes, authorizes, picks, exchanges, confirms, activates, delegates and uses', async () => {
    // Client registration: the secret is returned once and only its hash is stored.
    const reg = await request(h.app)
      .post('/admin/link/clients')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ name: 'Acme', redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN] });
    expect(reg.status).toBe(201);
    expect(reg.body.client_secret).toMatch(/^cred_lcs_/);
    expect(JSON.stringify(reg.body.client)).not.toContain(reg.body.client_secret);
    const list = await request(h.app).get('/admin/link/clients').set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    expect(list.status).toBe(200);
    expect(list.body.clients.map((c: any) => c.client_id)).toContain(reg.body.client.client_id);
    expect(JSON.stringify(list.body)).not.toContain('client_secret_hash');
    const stored = await h.server.link!.context.store.getClient(reg.body.client.client_id);
    expect(stored && 'client_secret_hash' in stored ? stored.client_secret_hash : '').toBe(
      crypto.createHash('sha256').update(reg.body.client_secret).digest('hex'),
    );
    const client = { client_id: reg.body.client.client_id, client_secret: reg.body.client_secret, auth: `Basic ${Buffer.from(`${reg.body.client.client_id}:${reg.body.client_secret}`).toString('base64')}` };

    // PAR.
    const parRes = await request(h.app).post('/link/v1/par').set('Authorization', client.auth).send(parBody());
    expect(parRes.status).toBe(201);
    expect(parRes.body.expires_in).toBe(600);
    expect(parRes.body.request_uri).toMatch(/^urn:cred:link:[A-Za-z0-9_-]{43}$/);
    expect(parRes.headers['cred-request-id']).toMatch(/^req_/);

    // Authorize: the picker, the binding cookie.
    const browser = new Browser();
    const picker = await browser.get(h.app, authorizePath(parRes.body.request_uri, 'redirect'));
    expect(picker.status).toBe(200);
    expect(browser.cookie).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const setCookie = String((picker.headers['set-cookie'] as unknown as string[])[0]);
    expect(setCookie).toMatch(/^__Host-cred_link_tx=/);
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('Secure');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toContain('Path=/');
    expect(setCookie).not.toContain('Domain=');
    expect(picker.text).toContain('See all your calendars and events');
    // Required scope is locked, preferred defaults only are pre-selected.
    expect(picker.text).toMatch(/type="checkbox" checked disabled><input type="hidden" name="scope" value="calendar.readonly"/);
    expect(picker.text).toMatch(/<input type="checkbox" name="scope" value="gmail.send">/);

    // Picker: smallest provider scope set, state envelope, PKCE.
    const envelope = envelopeOf(picker.text);
    const pickerRes = await browser.post(h.app, '/link/v1/picker', [
      ['e', envelope], ['action', 'continue'], ['provider', 'google'], ['scope', 'gmail.send'],
    ]);
    expect(pickerRes.status).toBe(303);
    const providerUrl = new URL(pickerRes.headers.location);
    expect(providerUrl.origin).toBe('https://accounts.google.com');
    expect(providerUrl.searchParams.get('redirect_uri')).toBe(`${BASE}/link/v1/callback/google`);
    const scope = providerUrl.searchParams.get('scope') ?? '';
    expect(scope.split(' ').sort()).toEqual([
      'email',
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/userinfo.email',
      'openid',
    ].sort());
    const state = decodeLinkEnvelope(providerUrl.searchParams.get('state'));
    expect(state).not.toBeNull();
    expect(state!.cid).toBe(client.client_id);
    expect(state!.tid).toMatch(/^ltx_/);
    expect(providerUrl.searchParams.get('code_challenge_method')).toBe('S256');
    const tx = await h.server.link!.context.store.getTransaction(state!.tid);
    expect(tx!.pkce_verifier).toBeTruthy();
    expect(providerUrl.searchParams.get('code_challenge')).toBe(computeChallenge(tx!.pkce_verifier!));
    // Nothing about the transaction travels in the browser except the envelope.
    expect(pickerRes.headers.location).not.toContain('dev-state-1');
    expect(pickerRes.headers.location).not.toContain('user-a');

    // Callback: exchange with the PKCE verifier, identity lookup, confirm page.
    const confirmPage = await callback(h.app, browser, providerUrl);
    expect(confirmPage.status).toBe(200);
    expect(h.fake.exchanges).toHaveLength(1);
    expect(h.fake.exchanges[0].params.code_verifier).toBe(tx!.pkce_verifier);
    expect(confirmPage.text).toContain('alice@example.com');
    const afterExchange = await h.server.link!.context.store.getTransaction(state!.tid);
    expect(afterExchange!.pkce_verifier).toBeUndefined();
    expect(afterExchange!.provider_account_id).toBe('google-sub-alice');

    // Confirm: redirect-mode result to the registered redirect_uri with state.
    const confirmed = await confirm(h.app, browser, confirmPage.text, ['calendar.readonly', 'gmail.send']);
    expect(confirmed.status).toBe(303);
    expect(confirmed.headers.location.startsWith(`${APP_REDIRECT}?cred_link=success`)).toBe(true);
    const result = resultOf(confirmed);
    expect(result.outcome).toBe('success');
    if (result.outcome !== 'success') return;
    expect(result.state).toBe('dev-state-1');
    expect(result.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    expect(result.code).toMatch(/^cred_lac_/);

    // Pending until activated: delegate is refused.
    const early = await delegate(h.app, { connection_id: result.connection_id });
    expect(early.status).toBe(403);
    expect(early.body.error).toBe('consent_required');

    // Activate.
    const act = await activate(h.app, client, result.connection_id, result.code);
    expect(act.status).toBe(200);
    expect(act.body.status).toBe('active');
    expect(act.body.grant.scopes).toEqual(['calendar.readonly', 'gmail.send']);

    // Delegate with connection_id: a Delegation Token by default, bound to
    // the agent's key, for exactly the effective scopes.
    const del = await delegate(h.app, { connection_id: result.connection_id, scopes: ['calendar.readonly'] });
    expect(del.status).toBe(200);
    expect(del.body.token_type).toBe('DPoP');
    expect(del.body.cnf.jkt).toEqual(expect.any(String));
    expect(del.body.user_id).toBeUndefined();
    expect(del.body.scopes).toEqual(['calendar.readonly']);
    expect(del.body.grant_id).toBe(result.grant_id);
    expect(JSON.stringify(del.body)).not.toContain('ya29');

    // Use: the broker injects the current provider token.
    const used = await use(h.app, { delegation_id: del.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(used.status).toBe(200);
    expect(h.fake.upstream).toHaveLength(1);
    expect(h.fake.upstream[0].authorization).toBe('Bearer ya29.access-1');
  });

  it('delivers a popup-mode result page that posts to the opener with the registered origin', async () => {
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const providerUrl = await toProvider(h.app, browser, requestUri, { mode: 'popup' });
    const confirmPage = await callback(h.app, browser, providerUrl);
    const res = await confirm(h.app, browser, confirmPage.text, ['calendar.readonly']);
    expect(res.status).toBe(200);
    const cfg = pageConfig(res.text);
    expect(cfg.context).toBe('top');
    expect(cfg.target).toBe(APP_ORIGIN);
    expect(cfg.result.type).toBe('cred.link.result');
    expect(cfg.result.v).toBe(1);
    expect(cfg.result.outcome).toBe('success');
    expect(cfg.result.state).toBe('dev-state-1');
    expect(res.text).toContain('t.postMessage(msg, c.target)');
    expect(cspOf(res)).toContain("frame-ancestors 'none'");
    expect(res.headers['cross-origin-opener-policy']).toBeUndefined();
  });

  it('authenticates PAR with private_key_jwt (Bearer and body) and rejects a replayed jti', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid: 'k1', alg: 'EdDSA', use: 'sig' };
    const reg = await request(h.app)
      .post('/admin/link/clients')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ name: 'JWT app', redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN], token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [jwk] } });
    expect(reg.status).toBe(201);
    expect(reg.body.client_secret).toBeUndefined();
    const clientId = reg.body.client.client_id as string;

    const assertion = (overrides: Record<string, unknown> = {}) => {
      const now = Math.floor(Date.now() / 1000);
      const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'k1', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ iss: clientId, sub: clientId, aud: BASE, iat: now, exp: now + 60, jti: crypto.randomUUID(), ...overrides })).toString('base64url');
      const sig = crypto.sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString('base64url');
      return `${header}.${payload}.${sig}`;
    };

    const jwt = assertion();
    const ok = await request(h.app).post('/link/v1/par').set('Authorization', `Bearer ${jwt}`).send(parBody());
    expect(ok.status).toBe(201);
    const replay = await request(h.app).post('/link/v1/par').set('Authorization', `Bearer ${jwt}`).send(parBody());
    expect(replay.status).toBe(401);
    expect(replay.body).toEqual(LINK_OPAQUE_FAILURE_BODY);

    const inBody = await request(h.app).post('/link/v1/par').send({
      ...parBody(),
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion(),
    });
    expect(inBody.status).toBe(201);

    for (const bad of [
      assertion({ aud: 'https://elsewhere.example' }),
      assertion({ exp: Math.floor(Date.now() / 1000) + 3600 }),
      assertion({ exp: Math.floor(Date.now() / 1000) - 120, iat: Math.floor(Date.now() / 1000) - 180 }),
      assertion({ sub: 'someone-else' }),
      assertion({ jti: undefined }),
    ]) {
      const res = await request(h.app).post('/link/v1/par').set('Authorization', `Bearer ${bad}`).send(parBody());
      expect(res.status).toBe(401);
    }
    // A bodyless route takes the assertion as a Bearer token too.
    const listed = await request(h.app).get('/link/v1/connections?subject=user-a').set('Authorization', `Bearer ${assertion()}`);
    expect(listed.status).toBe(200);
    expect(listed.body.connections).toEqual([]);
  });

  it('rejects unsafe client registrations', async () => {
    const bad = async (body: Record<string, unknown>) => {
      const res = await request(h.app)
        .post('/admin/link/clients')
        .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
        .send({ name: 'x', redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN], ...body });
      expect(res.status).toBe(400);
    };
    await bad({ redirect_uris: ['http://app.example.com/cb'] });
    await bad({ redirect_uris: ['https://app.example.com/cb#frag'] });
    await bad({ redirect_uris: ['https://app.example.com/cb?code=1'] });
    await bad({ redirect_uris: ['https://app.example.com/cb?cred_link=x'] });
    await bad({ origins: ['http://app.example.com'] });
    await bad({ origins: ['https://app.example.com/path'] });
    await bad({ token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [{ kty: 'oct', k: 'secret' }] } });
    const loopback = await request(h.app)
      .post('/admin/link/clients')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ name: 'dev', redirect_uris: ['http://localhost:5173/cb'], origins: ['http://localhost:5173'] });
    expect(loopback.status).toBe(201);
    const unauth = await request(h.app).post('/admin/link/clients').send({ name: 'x', redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN] });
    expect(unauth.status).toBe(401);
  });

  it('disabling a client makes its credentials fail with the opaque failure', async () => {
    const client = await registerClient(h.app);
    const dis = await request(h.app).post(`/admin/link/clients/${client.client_id}/disable`).set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    expect(dis.status).toBe(200);
    expect(dis.body.client.status).toBe('disabled');
    const res = await request(h.app).post('/link/v1/par').set('Authorization', client.auth).send(parBody());
    expect(res.status).toBe(401);
    expect(res.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
  });
});

describe('PAR validation (decision 10)', () => {
  it('rejects never_offer, out-of-catalog and hidden scopes, and required outside scopes', async () => {
    const client = await registerClient(h.app);
    const post = (overrides: Record<string, unknown>) => request(h.app).post('/link/v1/par').set('Authorization', client.auth).send(parBody(overrides));
    const neverOffer = await post({ providers: ['linear'], scopes: { linear: ['admin'] }, required_scopes: {} });
    expect(neverOffer.status).toBe(400);
    expect(neverOffer.body.error).toBe('invalid_scope');
    const outside = await post({ scopes: { google: ['calendar.readonly', 'https://mail.google.com/'] } });
    expect(outside.body.error).toBe('invalid_scope');
    const hidden = await post({ scopes: { google: ['openid'] }, required_scopes: {} });
    expect(hidden.body.error).toBe('invalid_scope');
    const requiredOutside = await post({ scopes: { google: ['gmail.send'] }, required_scopes: { google: ['calendar.readonly'] } });
    expect(requiredOutside.status).toBe(400);
    expect(requiredOutside.body.error).toBe('invalid_request');
    const unregistered = await post({ redirect_uri: 'https://evil.example/cb' });
    expect(unregistered.body.error).toBe('invalid_request');
    const badOrigin = await post({ origin: 'https://evil.example' });
    expect(badOrigin.body.error).toBe('invalid_request');
    expect(badOrigin.body.request_id).toMatch(/^req_/);
  });

  it('adds always_required scopes as locked and never sends hidden or Cred scopes as toggles', async () => {
    const client = await registerClient(h.app);
    const requestUri = await par(h.app, client, { providers: ['linear'], scopes: { linear: ['issues:create'] }, required_scopes: {} });
    const browser = new Browser();
    const picker = await browser.get(h.app, authorizePath(requestUri));
    expect(picker.text).toMatch(/checked disabled><input type="hidden" name="scope" value="read"/);
    expect(picker.text).not.toContain('value="admin"');
  });
});

describe('Hosted flow invariants', () => {
  it('request_uri is single use: a second authorize from another browser gets the local error page', async () => {
    const client = await registerClient(h.app);
    const requestUri = await par(h.app, client);
    const first = await new Browser().get(h.app, authorizePath(requestUri));
    expect(first.status).toBe(200);
    const second = await new Browser().get(h.app, authorizePath(requestUri));
    expect(second.status).toBe(400);
    expect(second.text).toContain('Request ID:');
    expect(second.text).not.toContain('name="e"');
  });

  it('the same browser re-entering authorize sees its picker again with a fresh handle', async () => {
    const client = await registerClient(h.app);
    const requestUri = await par(h.app, client);
    const browser = new Browser();
    const first = await browser.get(h.app, authorizePath(requestUri, 'popup'));
    const again = await browser.get(h.app, authorizePath(requestUri, 'popup'));
    expect(again.status).toBe(200);
    expect(envelopeOf(again.text)).not.toBe(envelopeOf(first.text));
    // The outstanding handle moved: the first page's handle is now stale but
    // the same browser re-enters instead of failing.
    const stale = await browser.post(h.app, '/link/v1/picker', [['e', envelopeOf(first.text)], ['action', 'continue'], ['provider', 'google']]);
    expect(stale.status).toBe(200);
    expect(stale.text).toContain('Connect an account');
  });

  it('a handle replayed without the cookie renders the local error and leaves the flow usable by the right browser', async () => {
    const client = await registerClient(h.app);
    const requestUri = await par(h.app, client);
    const victim = new Browser();
    const picker = await victim.get(h.app, authorizePath(requestUri));
    const envelope = envelopeOf(picker.text);
    const attacker = new Browser();
    const replay = await attacker.post(h.app, '/link/v1/picker', [['e', envelope], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly']]);
    expect(replay.status).toBe(400);
    expect(replay.text).toContain('Request ID:');
    // The right browser continues with the very same envelope.
    const ok = await victim.post(h.app, '/link/v1/picker', [['e', envelope], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly']]);
    expect(ok.status).toBe(303);
    expect(new URL(ok.headers.location).origin).toBe('https://accounts.google.com');
  });

  it('back and double submit re-enter the current step without repeating effects', async () => {
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const picker = await browser.get(h.app, authorizePath(requestUri));
    const envelope = envelopeOf(picker.text);
    const form: Array<[string, string]> = [['e', envelope], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly']];
    const first = await browser.post(h.app, '/link/v1/picker', form);
    expect(first.status).toBe(303);
    // Double submit of the picker: the current step (provider) is re-rendered
    // as a provider redirect with a new state, with the same PKCE challenge.
    const second = await browser.post(h.app, '/link/v1/picker', form);
    expect(second.status).toBe(303);
    const u1 = new URL(first.headers.location);
    const u2 = new URL(second.headers.location);
    expect(u2.searchParams.get('state')).not.toBe(u1.searchParams.get('state'));
    expect(u2.searchParams.get('code_challenge')).toBe(u1.searchParams.get('code_challenge'));
    const tx = await h.server.link!.context.store.getTransaction(decodeLinkEnvelope(u2.searchParams.get('state'))!.tid);
    expect(tx!.provider_attempt).toBe(1);

    // The callback with the stale state from the first redirect re-enters too:
    // nothing is exchanged, the browser is sent to the provider again.
    const stale = await callback(h.app, browser, u1);
    expect(stale.status).toBe(303);
    expect(h.fake.exchanges).toHaveLength(0);

    // Complete with the current state; then "back" from confirm restarts the
    // provider hop with a new PKCE pair and drops the staged tokens.
    const current = new URL(stale.headers.location);
    const confirmPage = await callback(h.app, browser, current);
    expect(confirmPage.status).toBe(200);
    const back = await confirm(h.app, browser, confirmPage.text, [], 'back');
    expect(back.status).toBe(303);
    const u3 = new URL(back.headers.location);
    expect(u3.searchParams.get('code_challenge')).not.toBe(u1.searchParams.get('code_challenge'));
    const txBack = await h.server.link!.context.store.getTransaction(tx!.tid);
    expect(txBack!.step).toBe('provider');
    expect(txBack!.provider_attempt).toBe(2);
    expect(await h.server.link!.context.secrets.getStaged(tx!.tid)).toBeNull();
    expect(h.fake.revocations).toHaveLength(1);
  });

  it('exchanges exactly once and confirms exactly once', async () => {
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const providerUrl = await toProvider(h.app, browser, requestUri);
    const [a, b] = await Promise.all([callback(h.app, browser, providerUrl), callback(h.app, browser, providerUrl)]);
    expect(h.fake.exchanges).toHaveLength(1);
    // One request did the exchange; the other re-entered (no error for the same browser).
    for (const r of [a, b]) expect([200, 303]).toContain(r.status);
    // The same browser coming back (refresh) re-enters at the confirm step
    // with a fresh handle; still exactly one exchange.
    const confirmPage = await callback(h.app, browser, providerUrl);
    expect(confirmPage.status).toBe(200);
    expect(confirmPage.text).toContain('Confirm permissions');
    expect(h.fake.exchanges).toHaveLength(1);

    const first = await confirm(h.app, browser, confirmPage.text, ['calendar.readonly']);
    const second = await confirm(h.app, browser, confirmPage.text, ['calendar.readonly', 'gmail.send']);
    const r1 = resultOf(first);
    const r2 = resultOf(second);
    expect(r1.outcome).toBe('success');
    expect(r2.outcome).toBe('success');
    if (r1.outcome !== 'success' || r2.outcome !== 'success') return;
    // The repeat returns the first result (same connection, grant and scopes);
    // only the code is replaced, since only its hash is stored.
    expect(r2.connection_id).toBe(r1.connection_id);
    expect(r2.grant_id).toBe(r1.grant_id);
    expect(r2.scopes).toEqual(['calendar.readonly']);
    const conns = await h.server.link!.context.store.listConnections({ client_id: client.client_id, subject: 'user-a' });
    expect(conns).toHaveLength(1);
    expect((await activate(h.app, client, r1.connection_id, r1.code)).status).toBe(401);
    expect((await activate(h.app, client, r2.connection_id, r2.code)).status).toBe(200);
  });

  it('a confirm that drops a required scope ends with required_scope_declined and revokes the pending tokens', async () => {
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const providerUrl = await toProvider(h.app, browser, requestUri);
    const confirmPage = await callback(h.app, browser, providerUrl);
    const tid = decodeLinkEnvelope(envelopeOf(confirmPage.text))!.tid;
    const res = await confirm(h.app, browser, confirmPage.text, ['gmail.send']);
    const result = resultOf(res);
    expect(result).toMatchObject({ outcome: 'error', error: 'required_scope_declined', state: 'dev-state-1' });
    expect(h.fake.revocations.map((r) => r.token)).toEqual(['rt-1']);
    expect(await h.server.link!.context.secrets.getStaged(tid)).toBeNull();
  });

  it('a provider that withholds a required scope ends with required_scope_declined', async () => {
    h.fake.googleScope = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/gmail.send';
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const providerUrl = await toProvider(h.app, browser, requestUri);
    const res = await callback(h.app, browser, providerUrl);
    expect(resultOf(res)).toMatchObject({ outcome: 'error', error: 'required_scope_declined' });
    expect(h.fake.revocations).toHaveLength(1);
  });

  it('a submission outside the transaction is refused even though the page only offers valid toggles', async () => {
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const picker = await browser.get(h.app, authorizePath(requestUri));
    const res = await browser.post(h.app, '/link/v1/picker', [['e', envelopeOf(picker.text)], ['action', 'continue'], ['provider', 'google'], ['scope', 'drive']]);
    expect(resultOf(res)).toMatchObject({ outcome: 'error', error: 'invalid_scope', state: 'dev-state-1' });
  });

  it('provider errors go back to the client as typed codes, never as text', async () => {
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const providerUrl = await toProvider(h.app, browser, requestUri, { mode: 'popup' });
    const state = providerUrl.searchParams.get('state')!;
    const res = await browser.get(h.app, `/link/v1/callback/google?error=access_denied&error_description=${encodeURIComponent('<b>PROVIDER-SECRET-ERROR-TEXT</b>')}&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(200);
    expect(res.text).not.toContain('PROVIDER-SECRET-ERROR-TEXT');
    expect(pageConfig(res.text).result).toMatchObject({ outcome: 'error', error: 'access_denied', state: 'dev-state-1' });
  });

  it('cancel on the picker and on the confirm screen reports an exit with state', async () => {
    const client = await registerClient(h.app);
    const b1 = new Browser();
    const picker = await b1.get(h.app, authorizePath(await par(h.app, client)));
    const exit1 = await b1.post(h.app, '/link/v1/picker', [['e', envelopeOf(picker.text)], ['action', 'cancel']]);
    expect(resultOf(exit1)).toEqual({ outcome: 'exit', step: 'picker', state: 'dev-state-1' });

    const b2 = new Browser();
    const providerUrl = await toProvider(h.app, b2, await par(h.app, client));
    const confirmPage = await callback(h.app, b2, providerUrl);
    const exit2 = await confirm(h.app, b2, confirmPage.text, [], 'cancel');
    expect(resultOf(exit2)).toEqual({ outcome: 'exit', step: 'confirm', provider: 'google', state: 'dev-state-1' });
    expect(h.fake.revocations).toHaveLength(1);
  });

  it('unknown or malformed state on the callback renders the local error page', async () => {
    const res = await new Browser().get(h.app, '/link/v1/callback/google?code=x&state=not-an-envelope');
    expect(res.status).toBe(400);
    expect(res.text).toContain('Request ID:');
    const bogus = Buffer.from(JSON.stringify({ h: 'A'.repeat(43), tid: 'ltx_abc', cid: 'nobody' })).toString('base64url');
    const res2 = await new Browser().get(h.app, `/link/v1/callback/google?code=x&state=${bogus}`);
    expect(res2.status).toBe(400);
  });

  it('client_id mismatch at authorize renders the local error page', async () => {
    const client = await registerClient(h.app);
    const other = await registerClient(h.app);
    const requestUri = await par(h.app, client);
    const res = await new Browser().get(h.app, authorizePath(requestUri, 'redirect', other.client_id));
    expect(res.status).toBe(400);
  });
});

describe('Activation (spec 2)', () => {
  it('requires the one-time code and the matching subject; codes are single use', async () => {
    const client = await registerClient(h.app);
    const result = await connectFlow(h.app, client);
    const wrongCode = await activate(h.app, client, result.connection_id, `cred_lac_${'A'.repeat(43)}`);
    expect(wrongCode.status).toBe(401);
    expect(wrongCode.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
    const ok = await activate(h.app, client, result.connection_id, result.code);
    expect(ok.status).toBe(200);
    const reuse = await activate(h.app, client, result.connection_id, result.code);
    expect(reuse.status).toBe(401);
    expect(reuse.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
  });

  it('a subject mismatch on connect answers opaque and revokes the pending connection and tokens', async () => {
    const client = await registerClient(h.app);
    const result = await connectFlow(h.app, client);
    const res = await activate(h.app, client, result.connection_id, result.code, 'user-b');
    expect(res.status).toBe(401);
    expect(res.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
    const conn = await h.server.link!.context.store.getConnection(result.connection_id);
    expect(conn!.status).toBe('revoked');
    expect(h.fake.revocations.map((r) => r.token)).toEqual(['rt-1']);
    // The right subject cannot activate afterwards either.
    expect((await activate(h.app, client, result.connection_id, result.code, 'user-a')).status).toBe(401);
  });

  it('consent phishing: a flow started for subject A cannot be activated in a session of subject B', async () => {
    const client = await registerClient(h.app);
    // Attacker pushes under their own subject and sends the hosted URL to a victim.
    const requestUri = await par(h.app, client, { subject: 'attacker', state: 'attacker-state' });
    const victimBrowser = new Browser();
    const providerUrl = await toProvider(h.app, victimBrowser, requestUri);
    const confirmPage = await callback(h.app, victimBrowser, providerUrl);
    const result = resultOf(await confirm(h.app, victimBrowser, confirmPage.text, ['calendar.readonly']));
    expect(result.outcome).toBe('success');
    if (result.outcome !== 'success') return;
    // The developer backend activates with the subject of its own current session: the victim.
    const res = await activate(h.app, client, result.connection_id, result.code, 'victim');
    expect(res.status).toBe(401);
    expect((await h.server.link!.context.store.getConnection(result.connection_id))!.status).toBe('revoked');
    // Nothing usable landed under the attacker's subject.
    const del = await delegate(h.app, { connection_id: result.connection_id });
    expect(del.status).toBe(403);
    expect(del.body.error).toBe('grant_revoked');
  });
});

describe('Update and reauth ownership (spec 6)', () => {
  it('rejects a connection outside (client, subject) with the opaque failure', async () => {
    const client = await registerClient(h.app);
    const other = await registerClient(h.app);
    const connectionId = await connectAndActivate(h.app, client);
    const foreignSubject = await request(h.app).post('/link/v1/par').set('Authorization', client.auth)
      .send(parBody({ intent: 'update', subject: 'user-b', connection_id: connectionId, scopes: { google: ['gmail.send'] }, required_scopes: {} }));
    expect(foreignSubject.status).toBe(401);
    expect(foreignSubject.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
    const foreignClient = await request(h.app).post('/link/v1/par').set('Authorization', other.auth)
      .send(parBody({ intent: 'reauth', connection_id: connectionId, scopes: undefined, required_scopes: {} }));
    expect(foreignClient.status).toBe(401);
    expect(foreignClient.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
    const reauthRoute = await request(h.app).post(`/link/v1/connections/${connectionId}/reauth`).set('Authorization', client.auth).send({ subject: 'user-b' });
    expect(reauthRoute.status).toBe(401);
    expect(reauthRoute.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
  });

  it('an account switch during reauth ends with access_denied and changes nothing', async () => {
    const client = await registerClient(h.app);
    const connectionId = await connectAndActivate(h.app, client);
    const before = await h.server.link!.context.store.getConnection(connectionId);
    const tokensBefore = await h.server.link!.context.secrets.get(connectionId as any);

    const reauth = await request(h.app).post(`/link/v1/connections/${connectionId}/reauth`).set('Authorization', client.auth).send({ subject: 'user-a', state: 'reauth-state' });
    expect(reauth.status).toBe(201);
    h.fake.googleSub = 'google-sub-mallory';
    const browser = new Browser();
    const providerUrl = await toProvider(h.app, browser, reauth.body.request_uri, { scopes: ['calendar.readonly', 'gmail.send'] });
    const res = await callback(h.app, browser, providerUrl);
    expect(resultOf(res)).toMatchObject({ outcome: 'error', error: 'access_denied', state: 'reauth-state' });
    const after = await h.server.link!.context.store.getConnection(connectionId);
    expect(after).toEqual(before);
    expect(await h.server.link!.context.secrets.get(connectionId as any)).toEqual(tokensBefore);
  });

  it('update widens the grant in place only after activation, same connection and grant', async () => {
    const client = await registerClient(h.app);
    const connectionId = await connectAndActivate(h.app, client, { scopes: ['calendar.readonly'], confirmScopes: ['calendar.readonly'] });
    const grantBefore = await h.server.link!.context.store.getGrantForConnection(connectionId);
    expect(grantBefore!.scopes).toEqual(['calendar.readonly']);
    const requestUri = await par(h.app, client, { intent: 'update', connection_id: connectionId, providers: undefined, scopes: { google: ['gmail.send'] }, required_scopes: {} });
    const browser = new Browser();
    const providerUrl = await toProvider(h.app, browser, requestUri, { scopes: ['calendar.readonly', 'gmail.send'] });
    const confirmPage = await callback(h.app, browser, providerUrl);
    const result = resultOf(await confirm(h.app, browser, confirmPage.text, ['calendar.readonly', 'gmail.send']));
    expect(result).toMatchObject({ outcome: 'success', connection_id: connectionId, grant_id: grantBefore!.id });
    if (result.outcome !== 'success') return;
    // Staged until activation.
    expect((await h.server.link!.context.store.getGrantForConnection(connectionId))!.scopes).toEqual(['calendar.readonly']);
    expect((await activate(h.app, client, connectionId, result.code)).status).toBe(200);
    const grantAfter = await h.server.link!.context.store.getGrantForConnection(connectionId);
    expect(grantAfter!.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    expect(grantAfter!.version).toBeGreaterThan(grantBefore!.version);
  });
});

describe('Hosted page headers', () => {
  it('sends a strict CSP with a nonce, no-store and frame-ancestors per page', async () => {
    const client = await registerClient(h.app);
    const browser = new Browser();
    const requestUri = await par(h.app, client);
    const picker = await browser.get(h.app, authorizePath(requestUri, 'popup'));
    const csp = cspOf(picker);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toMatch(/script-src 'nonce-[A-Za-z0-9+/=]+'/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self' https://accounts.google.com");
    expect(csp).toContain("base-uri 'none'");
    expect(picker.headers['cache-control']).toBe('no-store');
    expect(picker.headers['referrer-policy']).toBe('no-referrer');
    expect(picker.headers['x-content-type-options']).toBe('nosniff');
    expect(picker.headers['x-frame-options']).toBe('DENY');
    expect(picker.headers['cross-origin-opener-policy']).toBeUndefined();
    const nonce = /'nonce-([^']+)'/.exec(csp)![1];
    expect(picker.text).toContain(`<script nonce="${nonce}">`);

    // A provider callback arriving in a different browser than the one bound
    // to the transaction is refused with the local error page.
    const providerUrl = await toProvider(h.app, new Browser(), await par(h.app, client), { mode: 'popup' });
    const otherBrowser = await callback(h.app, new Browser(), providerUrl);
    expect(otherBrowser.status).toBe(400);
    expect(h.fake.exchanges).toHaveLength(0);

    const error = await new Browser().get(h.app, '/link/v1/authorize?request_uri=bogus');
    expect(cspOf(error)).toContain("frame-ancestors 'none'");
    expect(cspOf(error)).toContain("form-action 'none'");
    expect(error.headers['cache-control']).toBe('no-store');
  });

  it('the embedded picker is framable only by the registered origin and relays to the parent', async () => {
    const client = await registerClient(h.app);
    const requestUri = await par(h.app, client);
    const iframe = new Browser();
    const picker = await iframe.get(h.app, authorizePath(requestUri, 'embedded'));
    expect(picker.status).toBe(200);
    // No binding cookie from inside a third-party iframe.
    expect(iframe.cookie).toBeNull();
    expect(cspOf(picker)).toContain(`frame-ancestors ${APP_ORIGIN}`);
    expect(picker.headers['x-frame-options']).toBeUndefined();
    expect(picker.text).toContain('target="_blank" rel="opener"');
    const cfg = pageConfig(picker.text);
    expect(cfg).toMatchObject({ context: 'iframe', target: APP_ORIGIN, parent_origin: APP_ORIGIN, self_origin: BASE, step: 'picker' });

    // The picker submits into a new top-level window, which gets the cookie.
    const top = new Browser();
    const res = await top.post(h.app, '/link/v1/picker', [['e', envelopeOf(picker.text)], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly']]);
    expect(res.status).toBe(303);
    expect(top.cookie).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const confirmPage = await callback(h.app, top, new URL(res.headers.location));
    expect(cspOf(confirmPage)).toContain("frame-ancestors 'none'");
    // Top-level pages of an embedded flow post to the iframe (their opener) on Link's own origin.
    expect(pageConfig(confirmPage.text)).toMatchObject({ context: 'top', target: BASE, step: 'confirm', provider: 'google' });
    const done = await confirm(h.app, top, confirmPage.text, ['calendar.readonly']);
    expect(pageConfig(done.text)).toMatchObject({ context: 'top', target: BASE });
    expect(cspOf(done)).toContain("frame-ancestors 'none'");
  });

  it('the embedded picker cancel answers inside the iframe, posting to the parent', async () => {
    const client = await registerClient(h.app);
    const picker = await new Browser().get(h.app, authorizePath(await par(h.app, client), 'embedded'));
    const res = await new Browser().post(h.app, '/link/v1/picker?frame=iframe', [['e', envelopeOf(picker.text)], ['action', 'cancel']]);
    expect(res.status).toBe(200);
    expect(pageConfig(res.text)).toMatchObject({ context: 'iframe', target: APP_ORIGIN, result: { outcome: 'exit', step: 'picker', state: 'dev-state-1' } });
    expect(cspOf(res)).toContain(`frame-ancestors ${APP_ORIGIN}`);
    expect(cspOf(res)).toContain("form-action 'none'");
  });

  it("no page script ever posts with targetOrigin '*'", async () => {
    const client = await registerClient(h.app);
    const pages: string[] = [];
    for (const mode of ['popup', 'embedded', 'redirect'] as const) {
      const b = new Browser();
      const requestUri = await par(h.app, client);
      const picker = await b.get(h.app, authorizePath(requestUri, mode));
      pages.push(picker.text);
      const top = mode === 'embedded' ? new Browser() : b;
      const res = await top.post(h.app, '/link/v1/picker', [['e', envelopeOf(picker.text)], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly']]);
      const confirmPage = await callback(h.app, top, new URL(res.headers.location));
      pages.push(confirmPage.text);
      const done = await confirm(h.app, top, confirmPage.text, ['calendar.readonly']);
      if (done.status === 200) pages.push(done.text);
    }
    for (const html of pages) {
      expect(html).not.toMatch(/postMessage\([^)]*['"]\*['"]/);
      const cfg = pageConfig(html);
      expect(cfg.target).not.toBe('*');
      expect([APP_ORIGIN, BASE]).toContain(cfg.target);
    }
  });

  it('no provider error text or exception message appears in any HTML response', async () => {
    h.fake.googleExchangeStatus = 400;
    const client = await registerClient(h.app);
    const browser = new Browser();
    const providerUrl = await toProvider(h.app, browser, await par(h.app, client), { mode: 'popup' });
    const res = await callback(h.app, browser, providerUrl);
    expect(res.status).toBe(200);
    expect(res.text).not.toContain('PROVIDER-SECRET-ERROR-TEXT');
    expect(res.text).not.toContain('invalid_grant');
    expect(res.text).not.toContain('Token exchange failed');
    expect(pageConfig(res.text).result).toMatchObject({ outcome: 'error', error: 'provider_error' });

    // A thrown store error on a hosted page shows the generic page only.
    const store = h.server.link!.context.store;
    const original = store.enterByRequestUri.bind(store);
    store.enterByRequestUri = async () => { throw new Error('SQLITE-EXCEPTION-DETAIL'); };
    try {
      const err = await new Browser().get(h.app, authorizePath(await par(h.app, client)));
      expect(err.status).toBe(500);
      expect(err.text).not.toContain('SQLITE-EXCEPTION-DETAIL');
      expect(err.text).toContain('Request ID:');
    } finally {
      store.enterByRequestUri = original;
    }
  });
});

describe('Connection management API', () => {
  it('lists, reads, refreshes and revokes connections of the authenticated client', async () => {
    const client = await registerClient(h.app);
    const connectionId = await connectAndActivate(h.app, client);
    const list = await request(h.app).get('/link/v1/connections?subject=user-a').set('Authorization', client.auth);
    expect(list.status).toBe(200);
    expect(list.body.connections).toHaveLength(1);
    expect(list.body.connections[0]).toMatchObject({ connection_id: connectionId, provider: 'google', status: 'active', account_label: 'alice@example.com' });
    const one = await request(h.app).get(`/link/v1/connections/${connectionId}`).set('Authorization', client.auth);
    expect(one.body.grant.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    expect(JSON.stringify(one.body)).not.toContain('ya29');

    const refreshed = await request(h.app).post(`/link/v1/connections/${connectionId}/refresh`).set('Authorization', client.auth);
    expect(refreshed.status).toBe(200);
    expect(refreshed.body).toEqual({ connection_id: connectionId, status: 'active' });
    expect(h.fake.refreshCalls).toBe(1);

    const revoked = await request(h.app).delete(`/link/v1/connections/${connectionId}`).set('Authorization', client.auth);
    expect(revoked.status).toBe(200);
    expect(revoked.body).toEqual({ connection_id: connectionId, status: 'revoked', provider_revoked: true });
    expect(h.fake.revocations).toHaveLength(1);
    expect(await h.server.link!.context.secrets.get(connectionId as any)).toBeNull();
    const audit = h.server.vault.queryAuditEvents({ limit: 50 }).filter((e) => e.resource.type === 'grant');
    expect(audit.map((e) => e.action)).toEqual(expect.arrayContaining(['create', 'update', 'revoke']));
  });
});
