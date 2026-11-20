# Interop: SPIRE main with WIT-SVIDs

Recorded 2026-11-13 (runs repeated at `c75e4c1`). Raw output: [`spire-run-2026-11-13.txt`](spire-run-2026-11-13.txt). Reproduce with `SPIRE_BIN=<dir> scripts/hackathon/interop/spire/run.sh`.

| | |
|---|---|
| Implementation | [spiffe/spire](https://github.com/spiffe/spire) main @ `f722f5f0994ecc47ddd2ce9c805d262627529061` (2026-11-12), `spire-server` and `spire-agent` built from source (`1.16.1-dev`), with the experimental `enable_wit_svids` on server and agent |
| Workload API client | go-spiffe `v2.7.0` `workloadapi.FetchWITSVID` / `FetchWITBundles` |
| Cred | branch `hackathon/ietf127` @ `c75e4c1` (re-run after the review fixes) |
| Toolchain | go1.27.3 (fetched by `GOTOOLCHAIN=auto`), darwin/arm64, no Docker |

## Setup

This is a single-node local deployment: a SQLite datastore, the in-memory key manager, a `join_token` agent attested as `spiffe://domain-b.example/agent/local`, and the `unix` workload attestor. One registration entry, `spiffe://domain-b.example/ns/agents/sa/planner`, is selected by `unix:uid`. The configs are written by `run.sh`.

## Result: PASS

- The SPIRE server activated a WIT signing key, and the agent served a WIT-SVID for the workload over the Workload API. Its header is `{"alg":"ES256","kid":"<SPIRE authority id>","typ":"wit+jwt"}`, with an ES256 `cnf.jwk` and a 1-hour lifetime. go-spiffe's `witsvid.ParseAndValidate` accepted it.
- **Trust anchors out of band:** `spire-server bundle show -format spiffe` exports `x509-svid`, `jwt-svid` and `wit-svid` keys. Cred loaded that file unchanged; its `keyUse: "wit-svid"` keeps only the WIT key.
- With the SPIRE-minted WIT-SVID and its private key, `POST /api/v1/delegate` with WIT + WPT gave `200`.
- `POST /api/v1/use` with WIT + HTTP signature + Delegation Token gave `200`, and the provider answered `200`.
- No WIMSE header reached the provider.
- The audit lines name `spiffe://domain-b.example/ns/agents/sa/planner` with proof `wpt`, then `http-sig`.

SPIRE mints and serves WIT-SVIDs; it does not create WPTs or HTTP signatures. The proofs were made with Cred's demo client using the SVID's key.
