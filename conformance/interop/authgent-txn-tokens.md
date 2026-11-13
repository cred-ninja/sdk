# Interop: Txn-Tokens from authgent's Transaction Token Service

Recorded 2026-11-13. Raw output: [`authgent-txn-run-2026-11-13.txt`](authgent-txn-run-2026-11-13.txt). Reproduce with `AUTHGENT=<authgent-server> scripts/hackathon/interop/authgent/run.sh`.

| | |
|---|---|
| Implementation | [authgent/authgent](https://github.com/authgent/authgent) @ `8341cf932c9816dc666f2a6577b6776bd6f3b978`, Python (Apache-2.0). Its Transaction Token Service follows draft-ietf-oauth-transaction-tokens-08/-09 |
| Cred | branch `hackathon/ietf127` (Txn-Token verifier per -11) |
| Toolchain | Python 3.12 (uv venv), Node 26.8.1, darwin/arm64 |

This is a Txn-Token run only. The WIT, WPT and HTTP signature come from Cred's demo issuer and client; authgent has no WIMSE workload credentials.

## What ran

- authgent ran locally with `AUTHGENT_TXN_TOKEN_TRUST_DOMAIN=domain-b.example`. Txn-Tokens were minted through its RFC 8693 token exchange (`requested_token_type` `urn:ietf:params:oauth:token-type:txn_token`), with `request_details` `{"user": "alice"}`, which authgent places in `tctx`.
- Out of band: authgent's `/.well-known/jwks.json` was saved to a file, which Cred loaded as the domain-B Txn-Token keys (`use` `sig`). Cred's user-subject rule for this run is the claim `tctx.user`. Its scope map is `calendar.read` → `calendar.readonly`.
- An authgent Txn-Token: header `{"alg":"ES256","kid":"…","typ":"txntoken+jwt"}`, claims `iss`, `iat`, `aud: "domain-b.example"`, `exp` (120 s), `txn`, `sub: "client:…"`, `scope: "calendar.read"`, `req_wl`, `tctx`, `rctx`.

## Result: PASS

| Case | Cred |
|---|---|
| WIT + WPT with the authgent Txn-Token bound by `tth`, `POST /api/v1/delegate` | `200` |
| WIT + HTTP signature covering the authgent Txn-Token, `POST /api/v1/use` (delegated read) | `200`, provider `200` |
| The authgent Txn-Token replaced by another authgent Txn-Token after signing | `400` |
| An authgent Txn-Token whose `tctx.user` is `bob` on alice's delegation | `403` `txn_user_mismatch` |
| Headers at the provider | none of `txn-token`, `workload-identity-token`, `signature`, `signature-input`, `dpop` |
| Audit lines | carry the `txn` values authgent minted (`delegate`, `access`, and the refused call's `deny`) |

## Notes

- authgent sets `sub` to the requesting client (`client:<id>`), so the user had to come from `tctx`. Cred's per-trust-domain `userSubject` rule covers this, and without a rule every token would count as autonomous.
- authgent's lifetime of 120 s is within Cred's default cap of 3600 s.
