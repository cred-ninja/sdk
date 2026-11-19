import { afterEach, describe, expect, it } from 'vitest';
import { sign } from 'node:crypto';
import { createInMemorySharedReplayStore, createReplayCache } from '../identity/types.js';
import { createWimseIdentitySource } from '../identity/wimse.js';
import {
  selectWimseSignature, signatureBase, signWimseRequest, signWimseResponse,
  verifyWimseRequestSignature, verifyWimseResponseSignature,
} from '../identity/http-signature.js';
import { serializeInnerList } from '../identity/structured-fields.js';
import { BASE, cleanupDirs, trustDomain, wptHeaders } from './wimse-fixture.js';

afterEach(cleanupDirs);

describe('explicit replay deployment choice', () => {
  it('refuses startup when neither a shared store nor single-process mode is chosen', () => {
    const domain = trustDomain('domain-b.example');
    expect(() => createWimseIdentitySource({
      trustDomains: { [domain.name]: domain.anchors }, replay: createReplayCache(),
    })).toThrow(/sharedReplay|single-process/);
  });

  it('accepts a shared store without requiring a single-process opt-in', async () => {
    const domain = trustDomain('domain-b.example');
    const workload = domain.workload();
    const source = createWimseIdentitySource({
      trustDomains: { [domain.name]: domain.anchors }, replay: createReplayCache(),
      sharedReplay: createInMemorySharedReplayStore(),
    });
    await expect(source.authenticate({
      method: 'GET', targetUri: `${BASE}${PATH}`, socket: null,
      headers: wptHeaders(workload, PATH),
    })).resolves.toMatchObject({ subject: workload.subject });
  });
});

const PATH = '/api/v1/connections';
const NONCE = 'same-random-value-for-two-workloads';

function signedResponse(workload: ReturnType<ReturnType<typeof trustDomain>['workload']>, created?: number) {
  const request = { method: 'GET', path: PATH, headers: {} };
  const response = {
    method: 'GET', status: 200,
    headers: signWimseResponse({
      status: 200, headers: {}, request, requestNonce: NONCE, wit: workload.wit,
      privateKey: workload.key.privateKey, alg: 'ES256', created,
    }),
  };
  const selected = selectWimseSignature(response.headers)!;
  selected.input.params.set('nonce', { type: 'string', value: NONCE });
  response.headers['signature-input'] = `${selected.label}=${serializeInnerList(selected.input)}`;
  const bytes = sign('sha256', Buffer.from(signatureBase(selected.input, response, request)), {
    key: workload.key.privateKey, dsaEncoding: 'ieee-p1363',
  });
  response.headers.signature = `${selected.label}=:${bytes.toString('base64')}:`;
  return { response, request };
}

describe('workload-scoped replay protection', () => {
  it('one workload cannot burn another workload\'s WPT jti in the same cache', async () => {
    const domain = trustDomain('domain-b.example');
    const one = domain.workload('/one');
    const two = domain.workload('/two');
    const source = createWimseIdentitySource({
      trustDomains: { [domain.name]: domain.anchors }, replay: createReplayCache(),
      replayMode: 'single-process',
    });
    const request = (workload: typeof one) => ({
      method: 'GET', targetUri: `${BASE}${PATH}`, socket: null,
      headers: wptHeaders(workload, PATH, { jti: NONCE }),
    });
    const first = request(one);
    const second = request(two);
    await expect(source.authenticate(first)).resolves.toMatchObject({ subject: one.subject });
    await expect(source.authenticate(second)).resolves.toMatchObject({ subject: two.subject });
    await expect(source.authenticate(first)).rejects.toMatchObject({ code: 'replay' });
    await expect(source.authenticate(second)).rejects.toMatchObject({ code: 'replay' });
  });

  it('one workload cannot burn another workload\'s HTTP-signature nonce in the same cache', () => {
    const domain = trustDomain('domain-b.example');
    const one = domain.workload('/one');
    const two = domain.workload('/two');
    const config = {
      trustDomains: { [domain.name]: domain.anchors }, replay: createReplayCache(), audiences: [`${BASE}${PATH}`],
    };
    const message = (workload: typeof one) => ({
      method: 'GET', path: PATH,
      headers: signWimseRequest({
        method: 'GET', path: PATH, headers: {}, wit: workload.wit,
        privateKey: workload.key.privateKey, alg: 'ES256', audience: `${BASE}${PATH}`, nonce: NONCE,
      }),
    });
    const first = message(one);
    const second = message(two);
    expect(verifyWimseRequestSignature(first, config)?.wit.subject).toBe(one.subject);
    expect(verifyWimseRequestSignature(second, config)?.wit.subject).toBe(two.subject);
    expect(() => verifyWimseRequestSignature(first, config)).toThrow('wimse: replay');
    expect(() => verifyWimseRequestSignature(second, config)).toThrow('wimse: replay');
  });

  it('one responder cannot burn another responder\'s response nonce in the same cache', () => {
    const domain = trustDomain('domain-b.example');
    const one = domain.workload('/one');
    const two = domain.workload('/two');
    const config = { trustDomains: { [domain.name]: domain.anchors }, replay: createReplayCache() };
    const first = signedResponse(one);
    const second = signedResponse(two);
    const verify = (message: typeof first) => verifyWimseResponseSignature(message.response, message.request, NONCE, true, config);
    expect(verify(first)?.wit.subject).toBe(one.subject);
    expect(verify(second)?.wit.subject).toBe(two.subject);
    expect(() => verify(first)).toThrow('wimse: replay');
    expect(() => verify(second)).toThrow('wimse: replay');
  });
});

describe('exclusive HTTP-signature expiration', () => {
  it.each(['request', 'response'] as const)('refuses a %s at expires and after, with a valid control before', (kind) => {
    const domain = trustDomain('domain-b.example');
    const workload = domain.workload();
    const now = Math.floor(Date.now() / 1000);
    const created = now - 60;
    let clock = now - 1;
    const config = { trustDomains: { [domain.name]: domain.anchors }, audiences: [`${BASE}${PATH}`], now: () => clock };
    const request = { method: 'GET', path: PATH, headers: signWimseRequest({
      method: 'GET', path: PATH, headers: {}, wit: workload.wit,
      privateKey: workload.key.privateKey, alg: 'ES256', audience: `${BASE}${PATH}`, created,
    }) };
    const response = signedResponse(workload, created);
    const verify = () => kind === 'request'
      ? verifyWimseRequestSignature(request, config)
      : verifyWimseResponseSignature(response.response, response.request, NONCE, true, config);
    expect(verify()?.wit.subject).toBe(workload.subject);
    clock = now;
    expect(verify).toThrow('wimse: expired_signature');
    clock = now + 1;
    expect(verify).toThrow('wimse: expired_signature');
  });
});
