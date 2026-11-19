import { afterEach, expect, it, vi } from 'vitest';
import { CredGuard } from '@credninja/guard';
import {
  CALENDAR, cleanupDirs, delegateWithHttpSig, trustDomain, txnIssuer,
  useWithHttpSig, wimseServer,
} from './wimse-fixture.js';

afterEach(() => {
  vi.restoreAllMocks();
  cleanupDirs();
});

async function useAcrossGuard(options: {
  advance: number;
  skew?: number;
  injectedClock?: boolean;
  afterGuardStorage?: boolean;
  budget?: boolean;
}) {
  const before = Math.floor(Date.now() / 1000);
  let wallClock = before;
  let transactionClock = before;
  let armed = false;
  let guardCalls = 0;
  let advanced = false;
  const advanceClock = () => {
    if (advanced) return;
    advanced = true;
    transactionClock += options.advance;
    if (!options.injectedClock) wallClock = transactionClock;
  };
  vi.spyOn(Date, 'now').mockImplementation(() => wallClock * 1000);
  const guard = new CredGuard({
    policies: [{
      name: 'transaction-clock-barrier',
      async evaluate(context) {
        if (armed && context.metadata?.brokered) {
          guardCalls++;
          await Promise.resolve();
          if (!options.afterGuardStorage) advanceClock();
        }
        return { decision: 'ALLOW', policy: 'transaction-clock-barrier' };
      },
    }],
  });
  const domain = trustDomain('txn-expiry.example');
  const workload = domain.workload();
  const issuer = txnIssuer(domain.name);
  const server = await wimseServer({
    domains: [domain],
    mapSubject: () => workload.subject,
    txnTokens: {
      [domain.name]: issuer.trust({
        clockSkewSec: options.skew ?? 0,
        ...(options.injectedClock ? { now: () => transactionClock } : {}),
      }),
    },
    config: { guard },
  });
  if (options.afterGuardStorage) {
    const getStored = server.vault.getStored.bind(server.vault);
    vi.spyOn(server.vault, 'getStored').mockImplementation(async (input) => {
      const stored = await getStored(input);
      if (armed && guardCalls > 0) advanceClock();
      return stored;
    });
  }
  const minted = await delegateWithHttpSig(server.app, server.agent, workload, {
    ...(options.budget ? { constraints: [{ key: 'max_calls', max_lifetime: 1 }] } : {}),
  }, {
    'txn-token': issuer.mint(),
  });
  expect(minted.status).toBe(200);
  const providerCalls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    providerCalls.push(String(url));
    return new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  armed = true;
  const response = await useWithHttpSig(server.app, server.agent, minted.body.access_token, workload, {
    url: CALENDAR, method: 'GET',
  }, { extraHeaders: { 'txn-token': issuer.mint({ iat: before - 5, exp: before + 1 }) } });
  armed = false;
  const retry = () => useWithHttpSig(server.app, server.agent, minted.body.access_token, workload, {
    url: CALENDAR, method: 'GET',
  }, { extraHeaders: { 'txn-token': issuer.mint() } });
  return { response, providerCalls, guardCalls, retry };
}

it('refuses dispatch when the transaction expires while Guard waits', async () => {
  const { response, providerCalls, guardCalls } = await useAcrossGuard({ advance: 2 });
  expect(guardCalls).toBe(1);
  expect(response.status).toBe(403);
  expect(response.body.error).toBe('txn_token_expired');
  expect(providerCalls).toHaveLength(0);
});

it('dispatches once when the transaction remains live across Guard', async () => {
  const { response, providerCalls, guardCalls } = await useAcrossGuard({ advance: 0 });
  expect(response.status).toBe(200);
  expect(providerCalls).toEqual([CALENDAR]);
  expect(guardCalls).toBe(1);
});

it('refuses at the exact zero-skew expiry boundary', async () => {
  const { response, providerCalls } = await useAcrossGuard({ advance: 1 });
  expect(response.status).toBe(403);
  expect(response.body.error).toBe('txn_token_expired');
  expect(providerCalls).toHaveLength(0);
});

it('preserves the configured skew window before its exclusive boundary', async () => {
  const { response, providerCalls } = await useAcrossGuard({ advance: 60, skew: 60 });
  expect(response.status).toBe(200);
  expect(providerCalls).toEqual([CALENDAR]);
});

it('refuses at exp plus the configured skew', async () => {
  const { response, providerCalls } = await useAcrossGuard({ advance: 61, skew: 60 });
  expect(response.status).toBe(403);
  expect(response.body.error).toBe('txn_token_expired');
  expect(providerCalls).toHaveLength(0);
});

it('uses the same injected trust clock as authentication', async () => {
  const { response, providerCalls } = await useAcrossGuard({ advance: 2, injectedClock: true });
  expect(response.status).toBe(403);
  expect(response.body.error).toBe('txn_token_expired');
  expect(providerCalls).toHaveLength(0);
});

it('checks after awaited storage work as well as Guard', async () => {
  const { response, providerCalls } = await useAcrossGuard({ advance: 2, afterGuardStorage: true });
  expect(response.status).toBe(403);
  expect(response.body.error).toBe('txn_token_expired');
  expect(providerCalls).toHaveLength(0);
});

it('refunds an unperformed call without resetting the delegation budget', async () => {
  const result = await useAcrossGuard({ advance: 2, budget: true });
  expect(result.response.status).toBe(403);
  expect(result.response.body.error).toBe('txn_token_expired');
  expect(result.providerCalls).toHaveLength(0);
  expect(result.guardCalls).toBe(1);
  expect((await result.retry()).status).toBe(200);
  const exhausted = await result.retry();
  expect(exhausted.status).toBe(403);
  expect(exhausted.body.error).toBe('cumulative_constraint_exceeded');
  expect(result.providerCalls).toEqual([CALENDAR]);
});
