# Opaque-constraint conformance evidence

This snapshot compares the same unchanged protocol runner and vector files against
an SDK baseline and the reviewed opaque-constraint implementation. It is not a
claim of complete Asor conformance or complete hosted per-action enforcement.

## Pinned inputs

- SDK baseline: `a7eb38fda59a4ef82fa5e7e1d6e7460d9764242c`.
- SDK candidate code: `527cf665327df67fcb1b2aa90546ff792eb28294`.
- Protocol repository: `cred-ninja/protocol`, commit
  `df90107120edc9cb251ab0f55229fa4e88f49dd3`.
- Runner: `conformance/asor-delegation-chain/run.ts`.
- Vector sets: `vectors` (Asor -01, 20 files), `vectors-02` (Asor -02, 35 files).
- Runtime: Node `v22.23.4`, npm `10.9.9`.

`metadata.json` records the runner hash, every vector hash and every changed
candidate source/test/package file hash. The candidate code commit excludes this
subsequent evidence-only commit, avoiding a circular revision reference.

## Measured outcomes

| Set | Baseline PASS / FAIL / GAP / MASKED | Candidate PASS / FAIL / GAP / MASKED |
| --- | --- | --- |
| Asor -01 | 20 / 0 / 0 / 0 | 20 / 0 / 0 / 0 |
| Asor -02 | 20 / 5 / 10 / 0 | 21 / 4 / 10 / 0 |

The only changed row is `valid_unknown_constraint_identical.json`: baseline
`reject:malformed` at hop 1 becomes candidate `accept` and `PASS`. All other 54
rows, including diagnostic notes, are unchanged. No vector, expectation, reason
mapping or runner behavior was changed to obtain this result.

The four remaining FAIL and ten GAP outcomes are retained, not relabeled or
waived as passes. See the complete per-vector JSON files and `comparison.json`.
The -02 runner therefore still exits with status 1 on both SDK revisions.

The runner's absolute `source` path is normalized to
`packages/vault/src/index.ts`; no row or classification is normalized.

## Other verification

The final candidate passed the full workspace build, lint, typecheck and
**2,018 tests**, with one opt-in Web Bot Auth live smoke test skipped because no
live endpoint was configured. Packed-package smoke tests also passed, including
fresh ESM/CJS cloud-only SDK installs without optional vault/oauth peers.

Independent review probes were rerun against the repaired candidate: 12 passed.
The sole remaining failure is the explicitly retained baseline comparator for a
known hosted `prefix` restriction that is not enforced. This behavior also fails
at the baseline; this change does not implement arbitrary known per-action
constraints. The SDK README states that limitation rather than implying that
chain verification authorizes exercise.

Local raw-token paths reject all nonempty unsupported constraints instead of
silently dropping them. Unknown types report `unknown_constraint`; supported
parsing of a known type does not imply local enforcement.

## Reproduce the vector comparison

From an SDK checkout containing the pinned commits, with `TMPDIR` set to an
appropriate scratch directory:

```sh
git worktree add --detach ../sdk-asor-baseline a7eb38fda59a4ef82fa5e7e1d6e7460d9764242c
git worktree add --detach ../sdk-asor-candidate 527cf665327df67fcb1b2aa90546ff792eb28294
git clone https://github.com/cred-ninja/protocol.git ../protocol-asor-evidence
git -C ../protocol-asor-evidence checkout --detach df90107120edc9cb251ab0f55229fa4e88f49dd3

BASE=$(cd ../sdk-asor-baseline && pwd)
CANDIDATE=$(cd ../sdk-asor-candidate && pwd)
PROTOCOL=$(cd ../protocol-asor-evidence && pwd)
run() { npm exec --yes --package=node@22.23.4 --package=npm@10.9.9 -- "$@"; }

for sdk in "$BASE" "$CANDIDATE"; do
  (cd "$sdk" && run npm ci --no-audit --no-fund && run npm run build)
done
cd "$PROTOCOL/conformance/asor-delegation-chain"
run npm ci --no-audit --no-fund

for phase in baseline candidate; do
  if [ "$phase" = baseline ]; then sdk=$BASE; else sdk=$CANDIDATE; fi
  for vectors in vectors vectors-02; do
    status=0
    run node --import tsx run.ts --sdk "$sdk" --vectors "$vectors" --json \
      > "$TMPDIR/$phase-$vectors.json" || status=$?
    printf '%s %s exit=%s\n' "$phase" "$vectors" "$status"
  done
done
```

Expected process statuses are 0 for -01 and 1 for -02, for both revisions.
Compare JSON rows by `vector`, not array position, and verify declared counts
against the rows. The SDK regression commands, run from the candidate checkout
with the same `run` function, are:

```sh
run npm test
run npm run lint
run npm run typecheck
run npm run smoke:npm
```
