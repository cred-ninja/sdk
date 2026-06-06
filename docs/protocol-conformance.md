# Cred Protocol Conformance (Reference Implementation)

> Status: **first-pass map**, maintained alongside [`cred-ninja/protocol`](https://github.com/cred-ninja/protocol).
> This SDK is named as the protocol's reference implementation. This document maps
> what the SDK actually implements to the protocol's capabilities and the six RFCs
> it profiles, and tracks the gaps. It should be reconciled with the protocol
> repo's formal conformance section as that stabilizes (the spec is a pre-submission
> draft targeting IETF 126).

## How to read this

- **Implemented** — the capability exists in this repo, grounded in the cited code.
- **Adjacent** — the capability exists, but via a mechanism *other than* the RFC the
  spec profiles (e.g. PoP via HTTP Message Signatures instead of DPoP). Functionally
  equivalent, not wire-compatible with the profiled RFC.
- **Gap** — not implemented yet.
- **Divergent** — the daemon (`cred-ninja/daemon`) and this SDK make different
  choices here; needs an explicit decision to converge.

## Capability conformance

The protocol README advertises these capabilities. Against the SDK:

| Protocol capability | Status | Where in this repo |
|---|---|---|
| Ephemeral agent identity via `did:key` | **Implemented** | `packages/sdk/src/identity.ts` (`generateAgentIdentity`, Ed25519 → `did:key:z…` multicodec) |
| Multi-hop delegation with attenuation | **Implemented** | `packages/vault/src/delegation-chain.ts` (`validateSubDelegation`), server `/api/v1/subdelegate` |
| Credential wrapping (agents never handle raw secrets) | **Implemented** | Brokered `cred_use` keeps the token server-side: `packages/mcp/src/tools/use.ts`, server `/api/v1/use` |
| Proof of possession | **Adjacent** | TOFU payload signing (`packages/tofu`, `cred.tofuDelegate`) + Web Bot Auth / HTTP Message Signatures (`packages/sdk/src/web-bot-auth.ts`). See RFC 9449 row. |
| Fine-grained capability tokens (not broad grants) | **Partial** | Scope-filter + max-ttl + url-allowlist policies (`packages/guard/src/policies`). Scope strings, not RFC 9396 `authorization_details`. |
| Fast revocation (<5s propagation) | **Partial** | Revoke endpoints exist (`/api/v1/agents/:agentId/revoke-all`, `DELETE /api/token/:provider`, `DELETE /api/v1/connections/:provider`). Propagation latency is not measured or asserted by tests. |
| Cross-provider interoperability | **Implemented** | OAuth provider adapters in `packages/oauth/src/adapters` (Google, GitHub, Slack, Notion, Salesforce, Linear, HubSpot, …) |

## RFC profile conformance

The spec profiles six standards. The SDK currently realizes the *intent* of several
through adjacent mechanisms rather than the profiled RFC itself:

| Profiled standard | Status | Notes |
|---|---|---|
| **RFC 8693** — Token Exchange | **Adjacent** | Delegation uses the custom `POST /api/v1/delegate` flow, not `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. Adapter token calls use standard `authorization_code` / `refresh_token` grants only. |
| **RFC 9449** — DPoP | **Adjacent** | No DPoP headers. PoP is achieved via TOFU payload signatures and Web Bot Auth (RFC 9421 HTTP Message Signatures). |
| **RFC 9396** — Rich Authorization Requests | **Gap** | No `authorization_details`; authorization is expressed as scope-string arrays. |
| **RFC 7523** — JWT Bearer | **Gap** | Agent auth uses opaque `cred_at_` bearer tokens plus TOFU-signed payloads, not a JWT bearer assertion grant. |
| **OIDC-CIBA** — Backchannel consent | **Gap** | Async consent is a redirect/poll flow surfaced via `ConsentRequiredError` + `consent_url`, not CIBA `auth_req_id` backchannel. |
| **W3C did:key** — Decentralized identifiers | **Implemented** | `did:key` generation + resolution (`packages/sdk/src/identity.ts`). |

## Divergence from the daemon

`cred-ninja/daemon` (Rust, M0) and this SDK overlap heavily (its `vault` / `Guard` /
`OAuth manager` mirror `@credninja/vault` / `guard` / `oauth`), but diverge on the
delegation token format:

| Concern | SDK (this repo) | Daemon | Action |
|---|---|---|---|
| Delegation token / attenuation proof | Ed25519 audit receipts + signed TOFU payloads | **biscuit** tokens | **Divergent** — decide whether the reference impl adopts biscuit, or the protocol admits both token profiles. |
| Identity document | `did:key` + agent records | SVID minting | Map `did:key` ↔ SVID claims. |
| Authorization enforcement | `@credninja/guard` (fail-closed, scope attenuation) | Guard component (fail-closed, monotonic attenuation) | Aligned in spirit; converge the attenuation algebra. |

## Proposed: protocol-version handshake

There is currently **no** protocol-version identifier exchanged between SDK, server,
and (future) daemon (`grep` for `PROTOCOL_VERSION` / `Cred-Protocol` returns nothing).
A version handshake is the smallest concrete step toward conformance tracking. Proposed
shape (not yet implemented — pending a canonical version string from the spec):

1. Export a constant, e.g. `CRED_PROTOCOL_VERSION = '0.1-draft'`, from `@credninja/sdk`.
2. SDK client sends `Cred-Protocol-Version: <v>` on delegation/use requests.
3. Server echoes the version it supports; on mismatch beyond a negotiated floor, it
   returns a structured `protocol_version_unsupported` error so clients fail loud.
4. The daemon's ACRP server advertises the same header, giving one negotiation path
   across all three implementations.

This is intentionally left as a proposal: the version string and negotiation rules are
protocol decisions that belong in `cred-ninja/protocol`, not invented here. Wiring is a
~1-file change in the SDK client once the string is fixed.

## Open questions / next steps

- [ ] Reconcile this table against the protocol repo's formal conformance section (needs that repo in scope, or its `CONFORMANCE` doc).
- [ ] Decide biscuit vs Ed25519-receipt token profile (SDK ↔ daemon convergence).
- [ ] Fix the canonical `CRED_PROTOCOL_VERSION` string and wire the handshake.
- [ ] Decide whether RAR (`authorization_details`) replaces or augments scope strings.
- [ ] Add a revocation-propagation latency test to back the "<5s" claim.
