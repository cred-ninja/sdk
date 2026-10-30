/**
 * Test helpers for Delegation Tokens: delegate as a did:key agent with a
 * DPoP proof, and exercise with `Authorization: DPoP <token>` plus a proof
 * naming the token (ath) and the exact body (cred_req), as the SDK does.
 */
import request from 'supertest';
import { createActorToken, createDpopProof, generateAgentIdentity, type AgentIdentity } from '@credninja/sdk';

export type App = Parameters<typeof request>[0];
export type { AgentIdentity };

export const newAgent = generateAgentIdentity;

/** POST /api/v1/delegate for `agent`, with a DPoP proof by its key. */
export function delegateAs(
  app: App,
  agent: AgentIdentity,
  body: Record<string, unknown>,
  opts: { bearer: string; base?: string; headers?: Record<string, string> },
) {
  const base = opts.base ?? 'http://localhost:3456';
  const req = request(app).post('/api/v1/delegate')
    .set('Authorization', `Bearer ${opts.bearer}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${base}/api/v1/delegate`));
  for (const [name, value] of Object.entries(opts.headers ?? {})) req.set(name, value);
  return req.send({ token_format: 'handle', agent_did: agent.did, ...body });
}

/** POST /api/v1/use with the Delegation Token and a proof by `agent`. */
export function exerciseAs(
  app: App,
  agent: AgentIdentity,
  token: string,
  body: Record<string, unknown>,
  opts: { base?: string; headers?: Record<string, string> } = {},
) {
  const base = opts.base ?? 'http://localhost:3456';
  const req = request(app).post('/api/v1/use')
    .set('Authorization', `DPoP ${token}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${base}/api/v1/use`, token, body));
  for (const [name, value] of Object.entries(opts.headers ?? {})) req.set(name, value);
  return req.send(body);
}

/** An RFC 7523 actor token proving `agent` to `path` on the server. */
export function actorTokenFor(agent: AgentIdentity, path: string, base = 'http://localhost:3456'): string {
  return createActorToken(agent, `${base}${path}`);
}
