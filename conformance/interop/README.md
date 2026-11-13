# Interop runs

Recorded runs of Cred (`hackathon/ietf127`) against other WIMSE and Transaction Token implementations, all on 2026-11-13. Each run has a write-up, the raw output, and a script under `scripts/hackathon/interop/` that reproduces it.

| Implementation | What was tested | Result |
|---|---|---|
| [SPIRE main](spire.md) `f722f5f` (WIT-SVIDs, experimental) | A SPIRE-minted WIT-SVID and SPIRE's exported trust bundle on the final hop (WPT, HTTP signature) | PASS |
| [go-spiffe v2.7.0](go-spiffe.md) | go-spiffe's WIT bundle and a go-spiffe-validated WIT on the final hop, and go-spiffe validating Cred-issued WITs | PASS, both directions |
| [wimsey](wimsey.md) `56b0705` (Rust) | wimsey-issued WITs, WPTs and HTTP signatures (ES256 and Ed25519) verified by Cred, and Cred's signatures and WPTs verified by wimsey | PASS, both directions |
| [Cofide PoC](cofide.md) `7984a60` + minispire v0.2.2 | minispire-issued WITs on the final hop; Cofide's client library calling Cred | WITs PASS; the PoC client's s2s-protocol-07 signatures are refused under http-signature-08 (three listed differences) |
| [authgent](authgent-txn-tokens.md) `8341cf9` (Python) | Txn-Tokens from authgent's Transaction Token Service, bound to WPT and HTTP signature, narrowing a delegated call | PASS |

In every run with a provider call, the provider received none of `Workload-Identity-Token`, `Txn-Token`, `Signature`, `Signature-Input` or `DPoP`.
