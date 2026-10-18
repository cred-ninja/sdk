# Thread positions register

The standing position on every WIMSE and OAuth list thread that touches Cred's layer: delegation, sub-delegation, revocation, consumption and budgets, audit evidence, agent identity and authentication. One entry per thread. Seeded 2026-10-18 from a full read of every message in each thread.

How it is kept:

- The daily thread watch (scheduled task) reads Kieran's mailbox for new messages on tracked threads, for new threads on these topics, and for anything addressed to Kieran. It updates "Last read", "State" and "Stance" here and adds new threads.
- The Thursday sweep does the deep pass: drafts, Datatracker, archive discovery beyond adoption calls, and reply drafts in the weekly report.
- Entries are never deleted. A closed thread moves to Closed with the reason and the date.
- Stances: SPEAK (Kieran should post; reply target and speak-by date given), WATCH (no post now; the trigger that would change that is named), DROP (nothing to add; reason given).
- Nothing in this file is sent anywhere. Kieran sends.

## Owed by Kieran

| Item | Since | Speak by | Entry |
|---|---|---|---|
| Songbo Bu, review of -01 (client_id requester, WAG in act) | 2026-10-14 | before -02 upload, 2026-11-02 | Call for comments on -01 |
| Karl McGuinness, objection to the portable-artifact proposal | 2026-10-06 | 2026-10-23 | Fine-grained authorization |
| Ryan Nelson, private ask for adoption support | 2026-10-13 | 2026-10-22 | Nelson delegation receipts |
| Caleb Dayton, answers to the three -01 questions | 2026-10-16 | with the Songbo reply | Call for comments on -01 |
| Rafael Asor, list answer on rank order | 2026-10-18 | with the Songbo reply | Call for comments on -01 |
| WIMSE chairs, IETF 127 presenter | 2026-10-15 | 2026-11-02 | IETF 127 agenda |

## Fix in Kieran's own -02 before 2026-11-02

These came out of list threads and are edits to draft-sweeney-wimse-credential-delegation-02, not posts.

- Section 4 allows only "Ed25519 or P-256". Allow ML-DSA and add the asor -02 Section 6 step 1 rule: deny a chain whose algorithm is not on the verifier's local list. (PQ agent identity)
- Section 7: say that `revoked_count` reports invalidation, not closure; a token exchanged for direct presentation to a resource server leaves closure PARTIAL until the resource server checks authority at commit. (Revocation closure)
- Related Work, Nelson paragraph: principal-signed receipts add assurance only when the principal's key is user-held and user-verified. (Nelson receipts)
- Security Considerations: retained receipts and consent records are classical-signature evidence; long-term retention needs anchoring. (PQ agent identity)

## Active threads

### Call for comments on draft-sweeney-wimse-credential-delegation-01 (wimse, oauth)

- Last read: 2026-10-18. Latest: Rafael Asor, 2026-10-18 17:27 UTC.
- State: Songbo Bu (Oct 14) found both defects: the Section 4.4 WAG-in-act MAY contradicts the client_id/act.sub rule, and client_id must name the requester. Caleb Dayton (Oct 16): rank order in the token, keep both client_id and act.sub with the agreement rule, WAG as receipt evidence only; raised user-minted tokens as a second deployment shape that must compose. Asor (Oct 18): -02 puts the rank order in the token.
- Stance: SPEAK.
- Position: -02 answers all three. Section 5.4.1 makes the receiving agent the requester, so client_id, act.sub and the authenticated client are one party at every hop. Caleb's user-minted shape is real; adopting the agent_delegation detail lets a custody server at least read the authority of such a token, and full composition is -03 work.
- Reply to: Songbo, 2026-10-14 03:17 UTC (Gmail 1a1386a21b4cde4b). Caleb, 2026-10-16 16:34 UTC (Gmail 1a145911c6f0a7ee). Asor, 2026-10-18 (Gmail 1a1500edd7fa586f).
- Speak by: after the REVISION-02 decisions, before the -02 upload.

### Fine-grained authorization in OAuth (oauth)

- Last read: 2026-10-18. Latest: Omri Gazitt, 2026-10-15 22:03 UTC. Interim on draft-mcguinness-oauth-mission, 2026-10-26 17:00 UTC.
- State: three tracks. Before issuance: Yaron Zehavi's authority metadata with the `amb` digest, closed (Blake Morrison and Omri signed off Oct 15). After execution: Ron Bar-Tor's cross-resource-server join, moved to mission #1051 with a three-valued result. Instruction provenance: Arun, Iman Schrock and Mohamad Yossif on executor-side approval evidence. Open: who computes the join, fields or digests in evidence records (#1019).
- Stance: SPEAK.
- Position: Karl is right that an issuer cannot sign for what a resource server's fields mean, but that does not kill the portable artifact. The Mandate commits, per Authority Set entry, to the `amb` digest of the resource server's own authority description at approval. Any verifier holding the Mandate, the records and the metadata can then check each record against the description the approval used, and Ron's join is computable without the AS. Freshness stays with the issuer, the same split -02 Section 5.4 makes for receipt chains. Do not answer Karl's downstream-instruction question; that space is crowded.
- Reply to: Karl McGuinness, 2026-10-06 18:16 UTC (Gmail 1a1126e3d9f3da88). Same text on mission #1051, where Karl asked to continue.
- Speak by: 2026-10-23.

### Revocation closure semantics for delegated agents (oauth, Deonté O'dell Watts)

- Last read: 2026-10-18. Latest: Caleb Dayton, 2026-10-18 04:22 UTC (R1 to R13 negative tests). Duplicate posts under "Scoped revocation closure" (Gmail 1a141a4937ed6891, 1a140b2fda35514e) have no replies.
- State: Watts separates receipt of a revocation, invalidation, and evidence that queued or derived work can no longer commit (CLOSED, PARTIAL, FAILED, UNKNOWN). Thilina Senarath and Jeff Lombardo asked what is AI-specific; Watts conceded nothing and leaned to negative vectors. Open: how another domain authenticates a pre-revocation acceptance time.
- Stance: SPEAK.
- Position: where a mediator executes the call, it is the single commit-time enforcement point and its signed per-hop record is the authenticated acceptance time. Closure should be claimable only for sinks the claimant gates. Cred's own `revoked_count` is an invalidation report, not closure; a token exchanged to a resource server makes the result PARTIAL. Caleb's R6 and R7 cannot both hold past a token's lifetime.
- Reply to: Watts, 2026-10-18 03:29 UTC (Gmail 1a14d0feec558b39, thread 1a13e7e127e56a04).
- Speak by: 2026-10-20.

### Nelson delegation receipts (wimse, oauth, private)

- Last read: 2026-10-18. Latest: Jeff Lombardo, 2026-10-15 16:35 UTC (wimse). Draft at -14.
- State: Jeff's teardown: the AS consent is the attributable authorization, a rogue operator can produce a valid receipt, revoke credentials not receipts. Nelson has not answered. -14 still has no delegatee key binding, disclaims key custody, and has no OAuth binding. Nelson asked Kieran privately on Oct 13 for a mapping and for adoption support.
- Stance: SPEAK, private first.
- Position: the first hop belongs at the AS, but an AS sees only hops that pass through it; later hops need a server in the loop or an offline chain. A principal-signed root adds proof that the human, not the operator, authorized it, only with a user-verified, non-exportable key. Without that, delegatee binding and an OAuth binding, -14 is not adoptable. Do not promise support; judge any adoption call on its text.
- Reply to: Nelson private, 2026-10-13 17:40 UTC (Gmail 1a1365a71ab1e9ab). On list: Nelson's charter-fit post, 2026-10-10 19:26 UTC (Gmail 1a1274918384d30d), using sweep Draft 5. Not the April wimse thread.
- Speak by: private 2026-10-22; list before 2026-10-26.

### AIMS-00 multi-hop delegation context (wimse)

- Last read: 2026-10-18. Latest: Wes Jackson, 2026-10-14 (split thread, Gmail 1a1387ebdbc1f653).
- State: convergence thread. Kieran's act-as-attribution framing was adopted by Wes and Mikhail Sergeev. Mikhail's Section 11 text is PR #158, unreviewed. Badal Bhushan has not posted the example. Live edge: Girish Konda's runs show outstanding permits and stale receivers outlive revocation; Mikhail's example text defers that to "the selected profile" with only MBA as the worked case. Not a fight.
- Stance: SPEAK, short.
- Position: AIMS should state a property, not defer to a profile. Every deployment states its exposure bound after revocation: the receiver's maximum state age plus the lifetime of a permit issued on that state. A server in the call path states near zero; a caching PDP states its own number. Each is measured against its own bound, and no implementation's semantics go into WG text.
- Reply to: Mikhail Sergeev, 2026-10-12 05:42 UTC (Gmail 1a12ea23a19e1dee), cc Girish. Base on sweep Draft 2, last paragraph cut.
- Speak by: 2026-10-22.

### draft-seymour-wimse-connected-flight-06 (wimse)

- Last read: 2026-10-18. Latest: Girish Konda, 2026-10-15 17:30 UTC.
- State: -06 admits no atomic consumption mechanism and proposes a completion record checked before a second Boarding Pass is minted. Girish: that governs reissuance, not admission, and a lost completion report cannot prove a pass unused. Errol Seymour has not answered.
- Stance: SPEAK, short.
- Position: consumption has to be a check-and-set at admission by the single party that admits the call (the STS if it is in the path, otherwise the executor), written at admission, not at completion. The cost is that a pass admitted and then failed is spent; the draft should say so.
- Reply to: Girish, 2026-10-15 17:30 UTC (Gmail 1a1409ecb0271555).
- Speak by: before Errol posts -07.

### Gilda agent audit record, "could not evaluate" (wimse, moving to AUDIT BOF)

- Last read: 2026-10-18. Latest: Cliff Singletary, 2026-10-16 18:28 UTC. Replaced by draft-gilda-audit-agent-audit-record-00 (2026-10-16).
- State: settled. Required evaluation member, unavailableInput from a closed set, required lastResult and maxAge, age measured from decision.reportedAt.
- Stance: WATCH here; SPEAK on the AUDIT list.
- Position: -00 models effects only as path writes and admits only below-observed vantage as authoritative, so a mediator that makes every credentialed call itself has no effect profile and no authoritative tier. Add a mediated-call effect profile (resource, request digest, credential reference digest, upstream status) and admit a mediator for the effects it mediates.
- Reply to: a new thread on the AUDIT list about -00, using sweep Draft 7 retargeted.
- Trigger: the AUDIT list becomes active. Before IETF 127.

### Cross-org delegation test vectors (wimse)

- Last read: 2026-10-18. Latest: Girish Konda, 2026-10-15 17:31 UTC.
- State: the vectors check agreement with the AgentCreds wire format, not conformance to reece-02. Théo Adam fixed an approval-reuse bug with them. Open: how to represent instance identity (Théo, unanswered), the draft-02.1 cut.
- Stance: WATCH.
- Position: say only with results. Cred can produce a mapped run, not a native one. R10 one-time reliance is where Cred has a real answer (single-use grant, DS as single writer), but the single-use grant is not implemented yet.
- Trigger: Cred has a mapped run or Arun's refuse-accept-refuse sequence against the DS. Then reply to Arun, 2026-10-10 (Gmail 1a127bf969ce6686).

### PQ requirements for agent identity (wimse)

- Last read: 2026-10-18. Latest: Venkata Uppalapati, 2026-10-15 02:33 UTC.
- State: converged on splitting PQ-R7 between Gilda -03 and the audit architecture; (e) is a verifier rule. Questions 1 to 3 (transition date, algorithm-profile claim, ML-DSA for workload credentials) unanswered. Root-key provenance has no home.
- Stance: WATCH. The fixes go in Kieran's own -02 (see above).
- Trigger: question 2 resurfaces. Kieran's answer: a server that re-verifies every hop can sign the per-hop algorithm profile into its receipt. Reply to Uppalapati, 2026-09-29 (Gmail 1a0ee4c35e29237b).

### IETF 127 agenda (wimse, joint session)

- Last read: 2026-10-18.
- State: Asor declined to present (private, 2026-10-15). Justin Richer, Oct 10: no presenter, no slot. The held agenda-request draft that names Asor must not be sent.
- Stance: SPEAK once Kieran picks: present remotely, or ask the chairs for a presenter. Sweep Draft 8.
- Speak by: 2026-11-02.

## Closed

### AIMS negative test cases (wimse, Deonté O'dell Watts)

- Closed 2026-10-18. Jijie Wei answered (option 2: point to jackson evaluation-04 Appendix A, konda-01 Section 6, Gilda Section 6.5) and Deonté accepted on Oct 18. Sweep Draft 4 is superseded.

### AIMS-00 negative examples separating agent identity from delegated authorization (wimse)

- Closed 2026-10-18. Duplicate posts of the question above from two other addresses; no replies.
