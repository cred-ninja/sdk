# npm 2.2.0 and PyPI 2.2.0

Status: prepared 2026-11-17; not yet published.

Every `@credninja` npm package moves to 2.2.0 together, and each one's range on the
others moves to `^2.2.0`. The Python packages move to 2.2.0 as well (from 2.0.1), so
npm and PyPI match; the Python change is additive — `create_wimse_http_signer`, the
client's `sign_request`, covering the WIMSE HTTP-signature request signing.

## What kind of release this is

2.2.0 adds opt-in agent authentication by an external workload identity (WIMSE) and by
Transaction Tokens, and tightens several checks that already existed. No export, type or
route is removed, and code written against 2.1.0 compiles and runs.

It is not a drop-in upgrade for a running deployment. A server that upgrades and changes
nothing else will refuse calls that worked on 2.1.0, and one Guard input changes. A
`^2.1.0` range picks 2.2.0 up at the next install, so read the checklist before that
install reaches production.

The new authentication is off unless `externalIdentity` is set on `ServerConfig`, and that
is programmatic only — no environment variable enables it — so a deployment that does not
configure it keeps 2.1.0's authentication behavior exactly.

## Authentication this release adds (opt-in)

- **External identity sources.** `externalIdentity.sources` lets an agent authenticate with
  an identity Cred verifies but does not issue — a WIMSE Workload Identity Token plus a
  Workload Proof Token or an HTTP message signature (RFC 9421 profile), or a Tailscale node
  proven through WhoIs. Each verified subject maps, by exact string, to an agent DID that
  already exists in the vault; nothing is created from an unknown identity.
- **Transaction Tokens.** `externalIdentity.txnTokens`, keyed by trust domain, requires a
  bound Txn-Token on the routes that obtain or use credentials, and narrows a brokered call
  to the transaction's user and scope.
- **Signed responses.** `externalIdentity.responseSigning` signs a response with Cred's own
  WIT when a request asks for one.
- **Signers** ship in `@credninja/sdk` (`createWimseHttpSigner`), `@credninja/mcp`
  (`CRED_WIMSE_*` file configuration) and the Python SDK.

Configure it only when you mean to: it is documented in `packages/server/README.md`.

## Behavior changes

| Change | Effect | Opt-out or mitigation |
| --- | --- | --- |
| A Web Bot Auth signature whose lifetime (`expires - created`) exceeds the cap | refused (2.1.0 accepted it) | `webBotAuthMaxSignatureLifetimeSeconds` (default 300) |
| A TOFU proof presented a second time on `POST /api/v1/delegate` | refused (2.1.0 accepted it) | sign a fresh proof for each request |
| An `agent_delegation` token at the instant it expires (`now == exp`) | refused `expired` (2.1.0 accepted it) | `clockSkewSeconds` on the verifier (default 0) |
| A receipt-chain hop at the instant it expires (`now == exp`) | refused `expired` (2.1.0 accepted it) | `clockSkewSeconds` on the verifier (default 0) |
| `requiresApproval` turned on for a Permission | the delegations already issued under it are revoked, so a live token stops working | none — the agent obtains a new one (which waits for approval) |
| `extra_headers` on `POST /api/v1/use` naming `Txn-Token`, `Workload-Identity-Token`, `DPoP`, `Content-Digest` or `Accept-Signature` | the header is dropped and not forwarded to the provider | none — workload and transaction credentials stay inside the trust domain |
| Guard on `POST /api/v1/use` | now receives the Delegation Token's DPoP-proven `agentDid` | review any Guard policy that judges identity |
| `externalIdentity.txnTokens` trust-domain keys | match case-insensitively; a mixed-case key that previously never matched now applies the `required` default; duplicate canonical keys refuse startup instead of overwriting policy | remove duplicate entries; each canonical domain must appear once |
| WIMSE replay deployment configuration | startup refuses a source with neither `sharedReplay` nor `replayMode: 'single-process'` | choose a shared cross-process store for replicas, or acknowledge single-process operation |
| WIMSE local replay keys | a verified workload's `jti` or nonce no longer consumes another workload's value; same-workload replays are still refused | none |
| HTTP request and response signatures at `now == expires` | refused rather than accepted at that boundary | sign before expiration; no expiration skew is applied |

## Upgrade checklist

1. Back up the vault and the identity database.
2. Upgrade the server, SDK, MCP adapter and integrations together. If you use the Python
   packages, upgrade them together too.
3. Review Web Bot Auth signers. A signature with `expires - created` over 300 seconds is
   now refused; raise `webBotAuthMaxSignatureLifetimeSeconds` on the server, or shorten
   the lifetime the signer asks for.
4. Review clients that send a TOFU proof to `POST /api/v1/delegate`. Each proof is now
   single-use; sign a fresh one per request instead of reusing it.
5. Expiry boundary: an `agent_delegation` token and a receipt-chain hop are now refused at
   the instant they expire (`now == exp`), where 2.1.0 accepted them. If a verifier's clock
   needs leeway for clock differences, pass a bounded `clockSkewSeconds`. Without it
   the default skew is 0. HTTP request and response signatures also expire exclusively
   (`now < expires`), with no leeway after their expiration.
6. If you turn `requiresApproval` on for a Permission
   (`PATCH /admin/permissions/:id`), the delegations already issued under it stop working.
   Plan for affected agents to obtain a new delegation, which waits for approval.
7. If you rely on `extra_headers` on `POST /api/v1/use` to forward `Txn-Token`,
   `Workload-Identity-Token`, `DPoP`, `Content-Digest` or `Accept-Signature` to a provider,
   those headers are now dropped. Workload and transaction credentials must not leave
   their trust domain.
8. If a Guard policy judges identity on `POST /api/v1/use`, it now sees the Delegation
   Token's DPoP-proven `agentDid`.
9. If you are adding `externalIdentity` (new in 2.2.0): supply one source per identity
   system and exact-subject mappings to agent DIDs that already exist, key `txnTokens` by
   the trust domain, and set `responseSigning` only if you want signed responses. On more
   than one replica, pass a cross-process `sharedReplay` store. For one process, choose
   `replayMode: 'single-process'` explicitly; startup refuses a source with neither
   choice. `createInMemorySharedReplayStore` does not protect separate processes.
10. With `webBotAuthMode: 'require'` and `externalIdentity`
    configured, an HTTP-signature workload is always refused (the server warns about the
    combination at startup).

## Kept from 2.1.0

- `metadata.webBotAuth` in the audit feed still holds every stored field. It is
  deprecated; read an event's own fields from `metadata.details`.
- A custom `StorageBackend` written for 2.0.0 or 2.1.0 compiles and works, with the same
  caveats 2.1.0 documented.
- The deprecated opt-outs from 2.1.0 (`CRED_ALLOW_AGENTS_WITHOUT_PERMISSION`,
  `CRED_ALLOW_REDELEGATION_AFTER_REVOCATION`, `CRED_ALLOW_UNCLASSIFIED_BROKER_CALLS`,
  `CRED_ALLOW_RAW_TOKENS`) still work and still warn at startup.

## What this release does not change

Known limitation: permissions are per agent and service, and the static `AGENT_TOKEN`
carries no user. On the legacy routes the user comes from the request's `user_id`, so
`user_id` is not an authorization boundary. The server warns at startup when one static
token serves more than one user.

Known limitation: whoever holds the agent token can revoke any delegation of a user it
names, and that revocation holds the agent out until an admin restores it. Treat the agent
token as an operator credential.

Revocation holds, replay caches, single-use grants and pending approvals are designed for
one server process per vault database. Replay caches, grants and pending approvals are
held in process memory, so a restart forgets them. In particular, the WIMSE WPT-`jti` and
HTTP-signature nonce caches are per process: with no `sharedReplay` store, a captured proof
can be replayed once per replica within its validity window. Cred ships the
`SharedReplayStore` interface and an in-memory implementation for tests, not a network one.

The built-in approval page authenticates the approval link, not the person opening it. An
external provider's CIBA `id_token` is not verified. Token exchange takes no DPoP proof.
`docs/protocol-conformance.md` states each of these.

No part of this release has been exercised against a live provider. The IETF 127 hackathon
results for Cred are self-attested; the interop runs against other WIMSE and Transaction
Token implementations are recorded with their scripts in `conformance/interop`, and the
http-signature vectors in `conformance/wimse-419`.

## Release order

1. Merge the release branch to `main`, and let CI pass on the merge commit. `main` already
   carries the `agent_delegation` expiry fix (#130); the receipt-chain expiry fix (#131)
   must be on the merge too.
2. Publish npm in dependency order: `protocol`, `attenuation`, `oauth`, `tofu`, `vault`,
   `guard`, `link`, `link-react`, `sdk`, `ai`, `mcp`, `server`, `create-app`. A later
   package's `^2.2.0` range cannot resolve until the earlier ones exist.
3. Check `npm view @credninja/server@2.2.0 dependencies`, and run `npm run smoke:npm` and a
   clean `npx @credninja/create-app` from the registry.
4. Publish PyPI: `cred-auth` first, then the five integrations. Run
   `bash scripts/smoke-python-wheels.sh` on 3.10, 3.12 and 3.13.
5. Deprecate 2.1.0 on npm with a message naming 2.2.0.

## Rollback

A published version cannot be replaced. If 2.2.0 has a defect, fix forward with 2.2.1.

For one deployment, restore the vault backup and pin 2.1.0. Going back brings back
everything 2.2.0 fixed — in particular the two expiry-boundary cases accept `now == exp`
again, the Web Bot Auth lifetime cap and the single-use TOFU proof are gone, and
`extra_headers` can forward workload credentials to a provider. Treat a downgrade as an
outage measure.
