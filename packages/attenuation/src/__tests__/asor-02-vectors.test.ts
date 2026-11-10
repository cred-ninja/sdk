/**
 * The 35 interop vectors of draft-asor-wimse-agent-delegation-chain-02
 * (attenu-guard v0.20.0, tests/vectors-02/), scored natively: each file's
 * tokens go through verifyAgentDelegationChain() under the file's own
 * verifier block, with no claim mapping. A matching outcome name is not
 * enough on its own: CAUSE pins the hop and rule each reject vector
 * isolates, so a rejection for an unrelated reason fails the test.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyAgentDelegationChain } from '../agent-delegation.js';
import { createHs256Key, staticKeyResolver } from '../jws.js';

const DIR = join(__dirname, 'fixtures', 'asor-02');

const CAUSE: Record<string, { hop: number; cause: RegExp }> = {
  'reject_alg_not_accepted.json': { hop: 0, cause: /signature/ },
  'reject_altered_sub_and_par_hash.json': { hop: 2, cause: /parent/ },
  'reject_aud_empty_array.json': { hop: 2, cause: /\baud\b/ },
  'reject_aud_null.json': { hop: 2, cause: /\baud\b/ },
  'reject_audience_mismatch.json': { hop: 2, cause: /\baud\b|audience/ },
  'reject_child_exp_exceeds_parent.json': { hop: 2, cause: /expires/ },
  'reject_child_raises_del_max_depth.json': { hop: 2, cause: /del_max_depth|max depth/i },
  'reject_cnf_without_confirmation.json': { hop: 2, cause: /\bcnf\b/ },
  'reject_constraint_extra_member.json': { hop: 2, cause: /max_rows/ },
  'reject_cross_type_lifetime_for_max.json': { hop: 2, cause: /max_rows/ },
  'reject_detail_extra_member.json': { hop: 2, cause: /detail|actions/ },
  'reject_duplicate_key_type.json': { hop: 2, cause: /max_rows/ },
  'reject_max_lifetime_widened.json': { hop: 2, cause: /max_calls/ },
  'reject_max_subtree_widened.json': { hop: 2, cause: /max_spend/ },
  'reject_missing_client_id.json': { hop: 2, cause: /client_id/ },
  'reject_missing_cnf.json': { hop: 1, cause: /\bcnf\b/ },
  'reject_mixed_case_wildcard.json': { hop: 1, cause: /User\.\*/ },
  'reject_newline_scope.json': { hop: 1, cause: /crm\.read/ },
  'reject_opaque_case_folded.json': { hop: 1, cause: /user\.read/ },
  'reject_opaque_over_wildcard.json': { hop: 1, cause: /drive\.\*/ },
  'reject_principal_altered.json': { hop: 1, cause: /\bsub\b/ },
  'reject_rank_order_mismatch.json': { hop: 2, cause: /egress/ },
  'reject_rank_outside_order.json': { hop: 2, cause: /egress/ },
  'reject_rank_without_order.json': { hop: 2, cause: /egress/ },
  'reject_reissued_parent.json': { hop: 2, cause: /parent/ },
  'reject_root_without_principal.json': { hop: 0, cause: /\bsub\b/ },
  'reject_second_detail.json': { hop: 2, cause: /detail/ },
  'reject_unknown_detail_type.json': { hop: 0, cause: /detail/ },
  'reject_unsafe_integer.json': { hop: 0, cause: /integer/ },
  'reject_wildcard_over_opaque.json': { hop: 1, cause: /drive\.Read/ },
};

const files = readdirSync(DIR).filter((f) => f.endsWith('.json')).sort();

describe('draft-asor-wimse-agent-delegation-chain-02 vectors (attenu-guard v0.20.0)', () => {
  it('has all 35 vectors', () => {
    expect(files).toHaveLength(35);
  });

  for (const file of files) {
    it(file, () => {
      const data = JSON.parse(readFileSync(join(DIR, file), 'utf8'));
      expect(data.draft).toBe('02');
      const key = createHs256Key(Buffer.from(data.signer.secret_hex, 'hex'), data.signer.kid);
      const result = verifyAgentDelegationChain(data.tokens, {
        acceptedAlgs: data.verifier.accepted_algs,
        audience: data.verifier.audience,
        resolveKey: staticKeyResolver([key]),
        now: data.now,
      });
      const expected: string = data.expect ?? data.expect_reject_reason;
      if (expected === 'accept') {
        expect(result).toMatchObject({ ok: true });
        return;
      }
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.reason).toBe(expected);
      const cause = CAUSE[file];
      expect(cause, `no CAUSE entry for ${file}`).toBeDefined();
      expect(result.hop).toBe(cause!.hop);
      expect(result.message).toMatch(cause!.cause);
    });
  }
});
