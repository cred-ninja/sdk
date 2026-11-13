# #419 test vectors for draft-ietf-wimse-http-signature-08

Cred's HTTP Message Signature verifier (`packages/server/src/identity/http-signature.ts`) run against the independent vector set posted in [ietf-wg-wimse/draft-ietf-wimse-s2s-protocol#419](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol/issues/419): 6 positive vectors (P-01 to P-06) and 22 negative cases (N-01 to N-22).

**Result: 28/28.** Per-vector outcomes are in [`results-2026-11-13.json`](results-2026-11-13.json).

## Run it

```sh
npm ci && npm run build
node scripts/conformance/run-wimse-419.mjs   # writes results-<date>.json
```

The suite is `packages/server/src/__tests__/conformance-wimse-419.test.ts` and also runs with the normal test suite.

## What is in `vectors.json`

The vectors as posted, with the corrections from the issue comments applied:

- P-01, P-02, P-06 (`sig2`) and N-15 use the signatures regenerated with `@query` carrying its leading `?` (RFC 9421 §2.2.7).
- P-04 uses the signature regenerated with `@authority` `svcb.example.com`, without the default port (RFC 9421 §2.2.3).

Verification time is the vectors' T0+60 (`1795000060`), and the trusted audience set is the one the vectors give. The Issuer key is configured as the trust anchor for `example.com`. Cred loads anchors only by a configured JWK `use`, so the configuration adds `"use": "wit-svid"` to that key. The key material is otherwise as published.

## How each kind of case is run

- **Positive vectors** run against Cred's verifier as published. A separate check rebuilds each published signature base with string operations only and verifies the published signature over it with `node:crypto`. This confirms the harness reads the vectors correctly, independently of Cred's code.
- **Message variations** (N-01 to N-15, N-21) apply the case's single change to its baseline. Where the case says the signature is recomputed, the suite re-signs with the published test key using that same independent base builder, not Cred's signer, so only the targeted check can fail. Each case is rejected at the check its MUST clause names (coverage, Content-Digest, parameters, tag count, validity window, audience, `wimse-req-nonce`, signed-response requirement, `cnf.jwk.alg`); the `detail` field in the results shows which.
- **Behaviour cases** test the role Cred plays:
  - N-16 (sender nonce entropy): Cred's signer draws 128-bit nonces from `crypto.randomBytes`, and 2000 of them are distinct.
  - N-17 (error surface): Cred as a server answers a WIT failure and a signature failure with the same `400` `wimse-signature-invalid` problem, with no `WWW-Authenticate`.
  - N-18 (signed response required): Cred does not sign responses, so a request with `wimse-sign-response` gets `501` `wimse-signed-response-unsupported` and never a successful unsigned response.
  - N-19 (weaker `Accept-Signature`): such a header never lowers what Cred does.
  - N-20 (no processing before validation): an expired WIT with a valid signature on a brokered call is refused, and no provider call is made.
  - N-22 (selection by tag): the WIMSE signature is found by its tag whether it is labelled `sig1` or `sig2`.

## Scope notes

- Cred's verifier supports the CONNECT coverage rules so that P-04, N-02 and N-21 run. Cred's own routes never accept CONNECT.
- The verifier's nonce floor (16 characters by default, configurable) is a local policy. The draft's 64-bit requirement binds the sender, which N-16 checks.
