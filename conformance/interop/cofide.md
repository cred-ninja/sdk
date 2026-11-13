# Interop: Cofide WIMSE HTTP-signature PoC and minispire

Recorded 2026-11-13. Raw output: [`cofide-run-2026-11-13.txt`](cofide-run-2026-11-13.txt). Reproduce with `scripts/hackathon/interop/cofide/run.sh`.

| | |
|---|---|
| Implementation | [cofide/wimse-s2s-httpsig-poc](https://github.com/cofide/wimse-s2s-httpsig-poc) @ `7984a60105002dc65b31e9cd08572cd5d10ed9d6` (2025-11-14), Go module pseudo-version `v0.0.0-20251114125238-7984a6010500` |
| WIT issuer | [cofide/minispire](https://github.com/cofide/minispire) v0.2.2 (the version the PoC README names) |
| Cred | branch `hackathon/ietf127` (verifier as at `df03b24`) |
| Toolchain | go1.27.1 darwin/arm64, Node 26.8.1 |

## Platform note

minispire v0.2.2 does not build on macOS: it reads peer credentials with Linux `SO_PEERCRED`. For this run, the one function that reads them was replaced with the macOS equivalent (`LOCAL_PEERCRED`, `LOCAL_PEERPID`). The change is [`minispire-v0.2.2-darwin-peercred.patch`](minispire-v0.2.2-darwin-peercred.patch). WIT minting, keys and the workload API are unchanged. On Linux, run minispire unmodified.

## What ran

Trust anchors were exchanged out of band. The harness fetched minispire's JWT bundle over the SPIFFE workload API and wrote it as a JWKS file, which Cred loaded from disk. minispire's bundle keys carry no JWK `use`, and Cred loads only keys with a configured `use`, so the harness adds `"use": "wit-svid"` to the copy it writes.

**A. A minispire-issued WIT on the final hop: PASS.** A WIT-SVID and key minted by minispire (`typ` `wit+jwt`, `kid` `kid`, ES256 `cnf.jwk`, 5-minute lifetime, subject `wimse://example.com/gid/…/pid/…/uid/…`) authenticated, in order:

- `POST /api/v1/delegate` with WIT + WPT: `200`, Delegation Token issued.
- `POST /api/v1/use` with WIT + HTTP signature (Cred's http-signature-08 signer, minispire's key): `200`, the provider answered `200`.
- No WIMSE header reached the provider.
- The audit lines name the workload, e.g. `"workload":{"subject":"wimse://example.com/gid/20/pid/…/uid/501","trustDomain":"example.com","proof":"http-sig"}`.

**B. Cofide's client library against Cred: refused, as expected for a different draft revision.** The PoC client sends:

```
Signature-Input: wimse=("@method" "@request-target" "workload-identity-token");created=…;expires=…;nonce="…";alg="ecdsa-p256-sha256";tag="wimse-workload-to-workload"
```

Cred answered `HTTP/1.1 400 Bad Request` (`wimse-signature-invalid`) and logged `forbidden_parameter: alg present`. The PoC follows draft-ietf-wimse-s2s-protocol-07. Under draft-ietf-wimse-http-signature-08 §3, this signature input differs in three ways, each of which a -08 verifier must refuse:

1. The `alg` signature parameter is present (§3: "MUST NOT be used: … alg"). Cred stops at this check.
2. It covers `@request-target` instead of `@path` and `@query` (§3: "The following derived components MUST be signed: @method, @path, @query").
3. There is no `wimse-aud` (§3: "For requests only … MUST also be included: wimse-aud").

The PoC client then failed on its own side, because it requires a signed response and Cred does not sign responses.

Result: Cred interoperates with minispire's WITs and keys, for both WPT and HTTP-signature proofs. It does not interoperate with the PoC client's -07 signatures, which -08 forbids.
