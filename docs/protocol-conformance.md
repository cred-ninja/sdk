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
| Protocol-version handshake | **Implemented** | `packages/sdk/src/protocol.ts` (`CRED_PROTOCOL_VERSION`, `CRED_PROTOCOL_VERSION_HEADER`, supported-version set); SDK advertises via `Cred.headers()`, server selects/rejects via early middleware. See section below. |

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

## Protocol-version handshake — Implemented

A protocol-version identifier is now exchanged between the SDK client and server
via the `Cred-Protocol-Version` HTTP header. The protocol repo now fixes
`0.1.0` as the canonical initial wire version and defines a
`protocol_version_unsupported` error for explicit unsupported versions.

- **Version constant:** `CRED_PROTOCOL_VERSION = '0.1.0'`, exported from
  `@credninja/sdk` (`packages/sdk/src/protocol.ts`).
- **Supported set / floor:** `CRED_PROTOCOL_SUPPORTED_VERSIONS = ['0.1.0']` and
  `CRED_PROTOCOL_VERSION_MINIMUM = '0.1.0'`.
- **Advertise (SDK client):** `@credninja/sdk` sends `Cred-Protocol-Version: 0.1.0`
  on every outbound request via `Cred.headers()`.
- **Select (server):** `@credninja/server` sets `Cred-Protocol-Version: 0.1.0` on
  every response through an early middleware registered after JSON parsing.
- **Reject explicit unsupported versions:** the server returns HTTP 426 with
  `error: protocol_version_unsupported`, `requested_version`,
  `supported_versions`, `minimum_version`, and `current_version` when a request
  explicitly advertises a version outside the supported set. Missing request
  headers are still accepted during the `0.1.0` compatibility window because
  there is no earlier wire version to downgrade to.
- **Client selected-version check:** the SDK rejects a response that selects a
  version outside the SDK-supported set, surfacing the same
  `protocol_version_unsupported` code.
- **Future daemon path:** the daemon's ACRP server can advertise the same header,
  giving one negotiation path across all three implementations.

## Open questions / next steps

- [ ] Reconcile this table against the protocol repo's formal conformance section (needs that repo in scope, or its `CONFORMANCE` doc).
- [ ] Decide biscuit vs Ed25519-receipt token profile (SDK ↔ daemon convergence).
- [x] Fix the canonical `CRED_PROTOCOL_VERSION` string and wire the handshake. *(Done — `0.1.0` with explicit unsupported-version rejection.)*
- [ ] Decide whether RAR (`authorization_details`) replaces or augments scope strings.
- [ ] Add a revocation-propagation latency test to back the "<5s" claim.
