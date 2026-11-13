# Interop: go-spiffe v2.7.0 (experimental WIT-SVID)

Recorded 2026-11-13. Raw output: [`go-spiffe-run-2026-11-13.txt`](go-spiffe-run-2026-11-13.txt). Reproduce with `scripts/hackathon/interop/go-spiffe/run.sh`.

| | |
|---|---|
| Implementation | [spiffe/go-spiffe](https://github.com/spiffe/go-spiffe) `v2.7.0`: `bundle/spiffebundle` (WIT authorities, `use` `wit-svid`) and `exp/svid/witsvid` |
| Cred | branch `hackathon/ietf127` (as at `df03b24`) |
| Toolchain | go1.27.1 darwin/arm64, Node 26.8.1 |

go-spiffe v2.7.0 parses and validates WIT-SVIDs but does not mint them; minting is the SPIRE server's job. The harness (`scripts/hackathon/interop/go-spiffe/main.go`) therefore does three things:

- It writes the trust bundle with go-spiffe's own `spiffebundle.FromWITAuthorities(…).Marshal()`.
- It signs a WIT with go-jose, the JOSE library go-spiffe uses.
- It accepts that WIT only after go-spiffe's `witsvid.ParseAndValidate` validated it against that bundle.

## Results

**go-spiffe to Cred: PASS.**

- Cred loaded go-spiffe's bundle file unchanged: `{"keys":[{"use":"wit-svid","kty":"EC","kid":"go-spiffe-wit-1",…}]}`.
- With the go-spiffe-validated WIT and its key, `POST /api/v1/delegate` with WIT + WPT gave `200`.
- `POST /api/v1/use` with WIT + HTTP signature gave `200`, and the provider answered `200`.
- No WIMSE header reached the provider.
- The audit lines name `spiffe://domain-b.example/ns/agents/sa/planner` with proof `wpt`, then `http-sig`.

**Cred demo issuer to go-spiffe: PASS.** A WIT from Cred's demo issuer (`scripts/hackathon/lib/issuers.mjs`), together with its bundle file, gave `go-spiffe witsvid.ParseAndValidate: OK id=spiffe://domain-b.example/ns/agents/sa/planner kid=domain-b.example-wit-1`.

## Notes

- go-spiffe's `witbundle.Marshal` (the plain WIT bundle) emits keys without `use`. Cred loads only keys whose `use` is configured, so a deployment should give Cred the SPIFFE bundle form (`spiffebundle`), which tags WIT keys `wit-svid`.
- go-spiffe accepts WIT signature algorithms RS*/ES*/PS* (not EdDSA). Cred accepts ES256 and EdDSA/Ed25519 for `cnf.jwk`. ES256 is the common ground.
- go-spiffe v2.7.0 has no HTTP-signature or WPT code. The proofs in this run were made with Cred's signer, using the go-spiffe-validated WIT and key.
