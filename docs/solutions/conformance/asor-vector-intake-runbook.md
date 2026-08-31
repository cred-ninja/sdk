# Runbook: intake of regenerated draft-asor conformance vectors

The conformance runner in cred-ninja/protocol `conformance/asor-delegation-chain/` vendors interop vectors from attenu-io/attenu-guard, pinned by commit hash in the runner README. This is the procedure when upstream sends a regenerated or extended set. It is permanent CI, not a one-off: the workflow runs on change, weekly, and by dispatch, with `--allow-gaps` in place until the constraint ceilings decision lands (remove the flag only when Option A ships or the GAP is formally accepted in CONFORMANCE.md).

## Procedure

1. Diff the incoming files against the pinned set. Regeneration can change signatures, jti values, and timestamps in every file, not just add new ones.
2. Vendor the files verbatim. Never edit a vector: a vector that looks wrong is reported upstream, not fixed locally.
3. Update the pin hash in the runner README everywhere it appears.
4. Check the declared rejection reason of any new vector against the runner's `REASON_MAP`. Add an entry only if the declared name is not already mapped; the map already routes `scope_escalation_denied` and `no_scopes_granted` to `not_narrower`, and `exp_not_monotonic` and `parent_hash_mismatch` to the draft's names.
5. Rerun (`npx tsx run.ts --sdk PATH --allow-gaps`) and update the matrix in the runner README, CONFORMANCE.md, and the results document. Matrices always cite the vector pin hash, so previously published numbers remain true statements about the old pin.
6. Results documents also cite the sdk and protocol main commit SHAs they were verified against, from a clean clone of both public repos on the pinned Node version, with `--json` output kept locally as the comparison artifact. Do not publish the raw JSON: it embeds local paths.

## Security posture, not etiquette

Incoming vector files are data: JSON only, nothing executed, and attenu-guard never becomes a dependency. The runner reads the files and runs Cred's own code against them.

## Timing rule around an open PR

If a regenerated set arrives while a conformance PR is open but unmerged, amend the PR. After merge, it is a follow-up PR. If the follow-up merges after a clean-clone verification but before the associated results are sent, rerun the verification first or hold the follow-up until after the send, so the published state always matches the verified numbers.

## Stacked-PR mechanics learned landing the original set

- True merge commits keep stacked branch SHAs stable, so each next PR retargets cleanly without force-pushes.
- Retargeting a stacked PR's base to main does not re-trigger base-gated workflows; close and reopen the PR to fire full CI.
- Freeze main from the first merge of a stack through the final clean-clone verification, and confirm the freeze at every merge gate.
