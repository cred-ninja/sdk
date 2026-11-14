/**
 * A Cred Link delegation exercised inside a verified transaction. Link user
 * ids are reserved vault ids, never a Txn-Token's user, so such a call is
 * refused (txn_user_mismatch) and the provider is never called. Without the
 * Txn-Token the same workload-signed call succeeds, so the refusal is the
 * transaction's.
 */
import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import crypto from 'node:crypto';
import { createReplayCache } from '../identity/types.js';
import { createWimseIdentitySource } from '../identity/wimse.js';
import type { ExternalIdentityMapping } from '../identity/types.js';
import {
  ADMIN_TOKEN, AGENT_TOKEN, agentFor, BASE, CALENDAR_URL, LINK_AGENT_ID, connectAndActivate, delegate, makeHarness, registerClient, type Harness,
} from './link-harness.js';
import { linkVaultUserId } from '@credninja/vault';
import { delegateAs, newAgent } from './token-helpers.js';
import { delegateWithHttpSig, trustDomain, txnIssuer, useWithHttpSig } from './wimse-fixture.js';

let h: Harness | null = null;
afterEach(() => {
  h?.close();
  h = null;
});

describe('Cred Link delegation with a Txn-Token', () => {
  async function linkWithWorkload(trustOver: Record<string, unknown> = { required: false }, opts: { agentRecordId?: string } = {}) {
    const b = trustDomain('domain-b.example');
    const w = b.workload();
    const tts = txnIssuer('domain-b.example');
    // Filled once the Link agent's did:key exists; the server reads it per request.
    const mappings: ExternalIdentityMapping[] = [];
    h = await makeHarness({
      externalIdentity: {
        sources: [createWimseIdentitySource({ trustDomains: { [b.name]: b.anchors }, replay: createReplayCache() })],
        mappings,
        txnTokens: { [b.name]: tts.trust(trustOver as any) },
      },
    });
    const { app, fake } = h;
    const agent = await agentFor(app);
    mappings.push({ kind: 'wimse', subject: w.subject, agentDid: agent.did });
    // An external identity maps only to an agent already in the vault.
    const now = new Date().toISOString();
    await h.server.vault.registerAgent({
      id: opts.agentRecordId ?? `agt_${crypto.randomBytes(6).toString('hex')}`, did: agent.did, fingerprint: crypto.randomBytes(16).toString('hex'),
      name: 'link-agent', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now,
    });
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client);
    return { app, fake, agent, w, tts, connectionId };
  }

  it('is refused with txn_user_mismatch and never reaches the provider', async () => {
    const { app, fake, agent, w, tts, connectionId } = await linkWithWorkload();
    const minted = await delegate(app, { connection_id: connectionId });
    expect(minted.status).toBe(200);
    const token = minted.body.access_token as string;
    const call = { delegation_id: minted.body.delegation_id, url: CALENDAR_URL, method: 'GET' };

    const before = fake.upstream.length;
    const withTxn = await useWithHttpSig(app, agent, token, w, call, { extraHeaders: { 'txn-token': tts.mint() } });
    expect(withTxn.status).toBe(403);
    expect(withTxn.body.error).toBe('txn_user_mismatch');
    expect(fake.upstream.length).toBe(before);

    const control = await useWithHttpSig(app, agent, token, w, call);
    expect(control.status).toBe(200);
    expect(fake.upstream.length).toBe(before + 1);
  });

  it('is refused even when the Txn-Token names the Link connection\'s reserved vault id', async () => {
    const { app, fake, agent, w, tts, connectionId } = await linkWithWorkload({
      required: false, userSubject: { claim: 'sub', pattern: '^user:(.{1,200})$' },
    });
    const minted = await delegate(app, { connection_id: connectionId });
    const call = { delegation_id: minted.body.delegation_id, url: CALENDAR_URL, method: 'GET' };
    const before = fake.upstream.length;
    const res = await useWithHttpSig(app, agent, minted.body.access_token, w, call, {
      extraHeaders: { 'txn-token': tts.mint({ sub: `user:${linkVaultUserId(connectionId)}` }) },
    });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_user_mismatch');
    expect(fake.upstream.length).toBe(before);
  });

  it('is not issued inside a transaction, nor to an agent whose trust domain requires Txn-Tokens', async () => {
    const lax = await linkWithWorkload();
    const inTxn = await delegateWithHttpSig(lax.app, lax.agent, lax.w, { connection_id: lax.connectionId, service: undefined, user_id: undefined }, { 'txn-token': lax.tts.mint() });
    expect(inTxn.status).toBe(403);
    expect(inTxn.body.error).toBe('txn_user_mismatch');
    const audit = await request(lax.app).get('/admin/audit?limit=200').set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    const denied = (audit.body.entries as Array<{ action: string; metadata?: { details?: Record<string, unknown> } }>)
      .filter((e) => e.action === 'deny' && e.metadata?.details?.reason === 'txn_user_mismatch');
    expect(denied).toHaveLength(1);
    expect(denied[0].metadata?.details).toMatchObject({ identitySource: 'wimse', proof: 'http-sig', route: '/api/v1/delegate' });
    h?.close();

    const strict = await linkWithWorkload({});
    const required = await delegate(strict.app, { connection_id: strict.connectionId });
    expect(required.status).toBe(403);
    expect(required.body.error).toBe('txn_required_link_unsupported');
  });

  it('refuses a Link agent whose own did:key is Txn-required, even when it binds the delegation to a fresh key', async () => {
    // The Link agent (principal server-agent) is the vault agent whose did:key
    // is mapped from a trust domain that requires Txn-Tokens.
    const { app, connectionId } = await linkWithWorkload({}, { agentRecordId: LINK_AGENT_ID });
    const fresh = await newAgent();
    const res = await delegateAs(app, fresh, { connection_id: connectionId }, { bearer: AGENT_TOKEN, base: BASE });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_required_link_unsupported');
    expect(res.body.access_token).toBeUndefined();
  });
});
