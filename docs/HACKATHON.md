# Cred at the IETF 127 hackathon: the final hop

Cred is the last hop in trust domain B. An agent in domain B authenticates to Cred with its WIT plus a WPT or an HTTP signature, carrying a domain-B Txn-Token bound to that proof. Cred then calls a third-party resource server that does not speak WIMSE, using a credential a user delegated to that agent, with the provider's own scopes (draft-sweeney-wimse-credential-delegation). The WIT, the proof and the Txn-Token never reach the provider. Every audit line for the call carries the transaction id.

Branch `hackathon/ietf127` of `github.com/cred-ninja/sdk`. The WIMSE and Txn-Token paths run only when `externalIdentity` is configured. Two tightenings on this branch apply to every deployment: a fresh check just before each brokered provider call, and a longer list of headers that `extra_headers` cannot forward (see `CHANGELOG.md`).

## Try it (one command, no Docker)

```sh
git clone -b hackathon/ietf127 https://github.com/cred-ninja/sdk.git cred && cd cred
npm ci
npm run hackathon:demo
```

This builds Cred on the first run and starts, in one process, Cred for domain B, a WIT issuer and a Txn-Token Service for domain B, and a mock provider that stands in for the Google Calendar API. The issuers' keys are generated at start and written to files that Cred loads. It then prints PASS or FAIL for the delegated read and the refusals below, the audit trail for the run's transaction id, and the headers the provider received.

The #419 http-signature-08 vectors: `npm run conformance:wimse-419` (28/28).

## What Cred needs from you

1. **Your trust domain**, e.g. `domain-b.example`.
2. **Your WIT trust bundle**, a JWKS file with your WIT issuer's public keys. Each key needs a `kid` and the `use` you configure (SPIRE uses `wit-svid`). Cred never fetches keys and never takes them from a token.
3. **The audience your clients will use.** By default it is Cred's public URL plus the path, e.g. `http://127.0.0.1:3456/api/v1/connections`. Cred compares `wimse-aud` and the WPT `aud` to it by exact string, and never uses `Host`.
4. **Which workload is which agent**: an exact `spiffe://…` subject for each agent. Unmapped workloads are refused.
5. Optional: **your Txn-Token Service** keys (JWKS file), the `aud` your tokens carry, how to read the user (a claim and an anchored pattern), and how your `scope` values map to provider scopes.

## Config

Save as `my-domain.json`. Paths are relative to this file.

```json
{
  "host": "127.0.0.1",
  "port": 3456,
  "publicUrl": "http://127.0.0.1:3456",
  "trustDomains": {
    "domain-b.example": { "witBundle": "./domain-b.wit-bundle.json", "keyUse": "wit-svid" }
  },
  "txnTokens": {
    "domain-b.example": {
      "aud": "domain-b.example",
      "jwks": "./domain-b.txn-jwks.json",
      "keyUse": "sig",
      "userSubject": { "claim": "sub", "pattern": "^user:([a-z0-9._-]{1,64})$" },
      "scopeMap": { "google": { "calendar.read": ["calendar.readonly"], "calendar.write": ["calendar.events"] } },
      "required": true
    }
  },
  "user": "alice",
  "agents": [
    { "name": "planner", "workload": "spiffe://domain-b.example/ns/agents/sa/planner", "allowedScopes": ["calendar.readonly"] }
  ]
}
```

```sh
npm run hackathon:serve -- --config my-domain.json
```

Leave out `txnTokens` to test WIT + WPT or HTTP-sig alone. With `txnTokens` set and `"required": true`, every request from that domain must carry a bound Txn-Token. In code, the same settings are `createServer({ externalIdentity: { sources: [createWimseIdentitySource(...)], mappings, txnTokens } })`.

## Point your client at Cred

Send to an agent route, e.g. `GET /api/v1/connections?user_id=alice`:

- `Workload-Identity-Token: <WIT>` (typ `wit+jwt`, `cnf.jwk` ES256 P-256 or Ed25519 with an `alg`, a `kid` in your bundle).
- **Then one of these:**
  - `Authorization: WPT <wpt>`: typ `wpt+jwt`, `aud` = the audience above, `wth`, `jti`, `exp` within 5 minutes, and `tth` when you send a Txn-Token.
  - An HTTP signature per draft-ietf-wimse-http-signature-08: `tag="wimse-workload-to-workload"`, `created`, `expires` (at most 300 s apart), `nonce` (16+ characters), `wimse-aud`. It covers `@method @path @query workload-identity-token`, plus `authorization`, `txn-token`, `content-type` and `content-digest` when present. No `keyid` or `alg`.
- `Txn-Token: <token>` (optional unless required): typ `txntoken+jwt`, `aud` = your trust domain, with `txn`, `sub`, `scope`, `req_wl`, `iat` and `exp`.

Brokered provider calls go to `POST /api/v1/use` with `Authorization: DPoP <Delegation Token>` and a DPoP proof (Cred's delegation protocol). Your HTTP signature there must also cover `authorization`. `scripts/hackathon/lib/client.mjs` shows the whole sequence.

### The agent key (needed for `/delegate` and `/use`)

Every Delegation Token is bound to the agent's Ed25519 `did:key`, so `POST /api/v1/delegate` and `POST /api/v1/use` need a DPoP proof (RFC 9449, `typ dpop+jwt`, `alg EdDSA`) signed by that key, in addition to your WIT and WPT or HTTP signature. Two ways to hold it:

- Bring your own: set `"did": "did:key:z6Mk..."` on the agent in your config and keep the private key yourself.
- Let Cred generate one: it is written to `<state>/agents/<name>.json` (`did`, `privateKeyHex`, mode 0600).

On `/delegate`, send `agent_did` in the body and a proof with `htm`, `htu`, `iat`, `jti`. On `/use`, the proof also carries `ath` (SHA-256 of the Delegation Token) and `cred_req`: base64url SHA-256 of the RFC 8785 canonical JSON of the request body (`{"method":"GET","url":"..."}`). The Delegation Token is `access_token` in the `/delegate` response; `delegation_id` names it for revocation.

### With the Cred SDK (TypeScript)

The SDK signs each request after it has added its own headers and body, so the HTTP signature covers `Authorization: DPoP <Delegation Token>`, the body's `Content-Digest` and the Txn-Token:

```ts
import { Cred, createWimseHttpSigner } from '@credninja/sdk';

const cred = new Cred({
  baseUrl: 'http://127.0.0.1:3456',
  signRequest: createWimseHttpSigner({ wit, privateKey, alg: 'ES256', txnToken: () => currentTxnToken }),
});
const { token } = await cred.delegateHandle({ service: 'google', userId: 'alice', appClientId: 'local', scopes: ['calendar.readonly'], agentIdentity });
await cred.use({ token, url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events', method: 'GET', agentIdentity });
```

`agentIdentity` is the agent's did:key, from the section above. `signRequest` is on this branch only and not yet published to npm.

### Signed responses

To have Cred sign its responses, give it its own WIT in your trust domain and the matching key: `externalIdentity.responseSigning: { wit, privateKey, alg }`. A request that sets `wimse-sign-response` then gets a response signed per §3.4-3.5, which your client checks against Cred's WIT and your own request nonce. The demo does this.

## What each refusal looks like

For WIT, WPT and HTTP-signature failures the response never says which check failed; the detail goes only to Cred's log and audit trail. Txn-Token and delegation refusals name their reason.

| Case | Response |
|---|---|
| WIT without a WPT or signature | `401` `invalid_workload_identity`, `WWW-Authenticate: WPT` |
| Any HTTP-signature failure (bad WIT, bad signature, replay, wrong `wimse-aud`, untrusted trust domain, unmapped workload, a Txn-Token swapped after signing, a Txn-Token for another trust domain) | `400` `application/problem+json`, type `…#wimse-signature-invalid` (identical bodies) |
| Any WPT failure | `401` `invalid_workload_identity` |
| `wimse-sign-response` requested | a response signed with Cred's own WIT when `responseSigning` is configured (the demo does this); otherwise `501` `…#wimse-signed-response-unsupported` |
| Txn-Token with no user (autonomous) on a delegated call | `403` `txn_autonomous` |
| Txn-Token for another user than the delegation's | `403` `txn_user_mismatch` |
| Txn-Token scope with no mapping | `403` `txn_scope_unmapped` |
| Write under a read-only grant | `403` `scope_insufficient` |
| No delegation | `401` `invalid_token` on `/use`; `403` `permission_required` when asking for one |
| Revoked between authorization and use | `401` `delegation_revoked` |
| Txn-Token sent with the agent token (unbound) | `401` `txn_token_unbound` |

## Limits

- The replay cache (WPT `jti`, signature `nonce`) is per process; replicas do not share it.
- Cred signs responses only when given its own WIT (`responseSigning`). Its routes do not accept CONNECT.
- The mock provider stands in for `https://www.googleapis.com` inside the demo process only.
- Revoking a delegation (`DELETE /api/v1/delegations/:id`) also revokes that agent's access to the service: a later `/delegate` returns `403 agent_access_revoked` until an operator calls `POST /admin/permissions/:id/restore`. Restart `serve` with a fresh `--state` to reset.
