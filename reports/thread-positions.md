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
| Songbo Bu, review of -01 (client_id requester, WAG in act) | 2026-10-14 | done 2026-10-20 (Gmail 1a15967d468bb7e7) | Call for comments on -01 |
| Karl McGuinness, objection to the portable-artifact proposal (list) | 2026-10-06 | done 2026-10-20 (Gmail 1a159680603a93ae) | Fine-grained authorization |
| Karl McGuinness, same text on mission #1051 (GitHub, promised in the list reply) | 2026-10-20 | 2026-10-23 | Fine-grained authorization |
| Ryan Nelson, private ask for adoption support | 2026-10-13 | done 2026-10-20 (private Gmail 1a15967b8aa2efb5; list Gmail 1a15967e1dd7edcd) | Nelson delegation receipts |
| Caleb Dayton, answers to the three -01 questions | 2026-10-16 | done 2026-10-20, in the Songbo reply | Call for comments on -01 |
| Rafael Asor, list answer on rank order | 2026-10-18 | done 2026-10-20, in the Songbo reply | Call for comments on -01 |
| WIMSE chairs, IETF 127 presenter | 2026-10-15 | 2026-11-02 | IETF 127 agenda |

## Fix in Kieran's own -02 before 2026-11-02

These came out of list threads and are edits to draft-sweeney-wimse-credential-delegation-02, not posts.

- Section 4 allows only "Ed25519 or P-256". Allow ML-DSA and add the asor -02 Section 6 step 1 rule: deny a chain whose algorithm is not on the verifier's local list. (PQ agent identity)
- Section 7: say that `revoked_count` reports invalidation, not closure; a token exchanged for direct presentation to a resource server leaves closure PARTIAL until the resource server checks authority at commit. (Revocation closure)
- Section 7: state that synchronous cascading revocation holds within one Delegation Server only, and that enforcement of a revoked delegation across administrative domains is out of scope. Watts asked proponents on 2026-10-19 for exactly this limit. (Revocation closure)
- Related Work, Nelson paragraph: principal-signed receipts add assurance only when the principal's key is user-held and user-verified. (Nelson receipts)
- Security Considerations: retained receipts and consent records are classical-signature evidence; long-term retention needs anchoring. (PQ agent identity)

## Active threads

### Call for comments on draft-sweeney-wimse-credential-delegation-01 (wimse, oauth)

- Last read: 2026-10-18. Latest: Rafael Asor, 2026-10-18 17:27 UTC.
- State: Songbo Bu (Oct 14) found both defects: the Section 4.4 WAG-in-act MAY contradicts the client_id/act.sub rule, and client_id must name the requester. Caleb Dayton (Oct 16): rank order in the token, keep both client_id and act.sub with the agreement rule, WAG as receipt evidence only; raised user-minted tokens as a second deployment shape that must compose. Asor (Oct 18): -02 puts the rank order in the token.
- Stance: WATCH (was SPEAK; posted 2026-10-20).
- Position: -02 answers all three. Section 5.4.1 makes the receiving agent the requester, so client_id, act.sub and the authenticated client are one party at every hop. Caleb's user-minted shape is real; adopting the agent_delegation detail lets a custody server at least read the authority of such a token, and full composition is -03 work.
- Reply to: Songbo, 2026-10-14 03:17 UTC (Gmail 1a1386a21b4cde4b). Caleb, 2026-10-16 16:34 UTC (Gmail 1a145911c6f0a7ee). Asor, 2026-10-18 (Gmail 1a1500edd7fa586f).
- Speak by: after the REVISION-02 decisions, before the -02 upload.
- Done: posted 2026-10-20 (Gmail 1a15967d468bb7e7), one reply to Songbo, Caleb and Rafael, including the one-sentence Principal-standing point for Cliff's thread. Stance now WATCH. Trigger: any reply, or -02 posting with a change that departs from what the reply promised.

### Fine-grained authorization in OAuth (oauth)

- Last read: 2026-10-19. Latest: Omri Gazitt, 2026-10-15 22:03 UTC. Interim on draft-mcguinness-oauth-mission, 2026-10-26 17:00 UTC. Related: on the OAuth IETF 127 agenda thread, Dapeng Liu (Max, Alibaba) asked the chairs on 2026-10-17 (Gmail 1a14a38a87cfb310) for 15 minutes in the OAuth session for draft-liu-mcguinness-oauth-bounded-work ("OAuth 2.0 Bounded Work Authorization", Liu and Karl McGuinness: use case, framework, requirements), offering to share time with related drafts. Not yet read on Datatracker (fetch failed 2026-10-19); the Thursday sweep should read it before Kieran replies to Karl, since it is likely where Karl's position now lives.
- State: three tracks. Before issuance: Yaron Zehavi's authority metadata with the `amb` digest, closed (Blake Morrison and Omri signed off Oct 15). After execution: Ron Bar-Tor's cross-resource-server join, moved to mission #1051 with a three-valued result. Instruction provenance: Arun, Iman Schrock and Mohamad Yossif on executor-side approval evidence. Open: who computes the join, fields or digests in evidence records (#1019).
- Stance: WATCH (was SPEAK; posted 2026-10-20).
- Position: Karl is right that an issuer cannot sign for what a resource server's fields mean, but that does not kill the portable artifact. The Mandate commits, per Authority Set entry, to the `amb` digest of the resource server's own authority description at approval. Any verifier holding the Mandate, the records and the metadata can then check each record against the description the approval used, and Ron's join is computable without the AS. Freshness stays with the issuer, the same split -02 Section 5.4 makes for receipt chains. Do not answer Karl's downstream-instruction question; that space is crowded.
- Reply to: Karl McGuinness, 2026-10-06 18:16 UTC (Gmail 1a1126e3d9f3da88). Same text on mission #1051, where Karl asked to continue.
- Speak by: 2026-10-23.
- Done: posted on list 2026-10-20 (Gmail 1a159680603a93ae), to Karl, cc oauth. The reply says "I'll put the same on #1051"; Kieran posts that himself. Stance now WATCH. Trigger: Karl's reply, or the 2026-10-26 interim. Note (read 2026-10-20): draft-liu-mcguinness-oauth-bounded-work defines AS-signed approval evidence that is explicitly not a permission and keeps lifecycle with the AS, which is consistent with the reply's freshness split.

### Revocation closure semantics for delegated agents (oauth, Deonté O'dell Watts)

- Last read: 2026-10-20 (no new messages since Watts on Oct 19; Kieran has not posted). Latest: Watts, 2026-10-19 10:32 UTC (Gmail 1a153b94633d2af6). Earlier: Caleb Dayton, 2026-10-18 04:22 UTC (R1 to R13 negative tests). Duplicate posts under "Scoped revocation closure" (Gmail 1a141a4937ed6891, 1a140b2fda35514e) have no replies.
- State: Watts separates receipt of a revocation, invalidation, and evidence that queued or derived work can no longer commit (CLOSED, PARTIAL, FAILED, UNKNOWN). Thilina Senarath and Jeff Lombardo asked what is AI-specific; Watts conceded nothing and leaned to negative vectors. Open: how another domain authenticates a pre-revocation acceptance time. Watts (Oct 19) thanked Caleb for the 13 scenarios and Ornella for GUARDAID and Guardalpha, said an audit chain recording issue or dispatch time does not show a downstream system cannot later commit a queued effect, and asked proponents for public, versioned specifications or reproducible tests defining (1) when a ticket is consumed versus when the action commits, (2) how a revoked epoch is enforced across administrative domains, (3) how unknown downstream paths or already-accepted obligations are represented.
- Stance: WATCH (was SPEAK. The Oct 19 ask is a direct opening: Kieran's -01 is a public, versioned specification for (1) and part of (2); posted 2026-10-20).
- Position: where a mediator executes the call, it is the single commit-time enforcement point and its signed per-hop record is the authenticated acceptance time. Closure should be claimable only for sinks the claimant gates. Cred's own `revoked_count` is an invalidation report, not closure; a token exchanged to a resource server makes the result PARTIAL. Caleb's R6 and R7 cannot both hold past a token's lifetime.
- Position addendum (2026-10-19): answer Watts's three questions with section pointers, not claims. (1) In draft-sweeney -01 the Delegation Server consumes at admission and executes the call, so consume and commit coincide for calls it mediates; it says nothing about effects queued behind the resource server. (2) Revocation is synchronous and cascading within one DS; across administrative domains it is not solved, and the draft should say so. (3) Unknown downstream paths: a token exchanged out of the DS's path is exactly the PARTIAL case. State the limits plainly.
- Reply to: Watts, 2026-10-19 10:32 UTC (Gmail 1a153b94633d2af6, thread 1a13e7e127e56a04). Supersedes the Oct 18 target (Gmail 1a14d0feec558b39).
- Speak by: 2026-10-20.
- Done: posted 2026-10-20 (Gmail 1a15967ca94391c2), answering (1) to (3) with section pointers and stating the limits. Stance now WATCH. Trigger: a reply from Watts or Caleb, especially on how a domain authenticates a pre-revocation acceptance time.

### Nelson delegation receipts (wimse, oauth, private)

- Last read: 2026-10-18. Latest: Jeff Lombardo, 2026-10-15 16:35 UTC (wimse). Draft at -14.
- State: Jeff's teardown: the AS consent is the attributable authorization, a rogue operator can produce a valid receipt, revoke credentials not receipts. Nelson has not answered. -14 still has no delegatee key binding, disclaims key custody, and has no OAuth binding. Nelson asked Kieran privately on Oct 13 for a mapping and for adoption support.
- Stance: WATCH (was SPEAK, private first; posted 2026-10-20).
- Position: the first hop belongs at the AS, but an AS sees only hops that pass through it; later hops need a server in the loop or an offline chain. A principal-signed root adds proof that the human, not the operator, authorized it, only with a user-verified, non-exportable key. Without that, delegatee binding and an OAuth binding, -14 is not adoptable. Do not promise support; judge any adoption call on its text.
- Reply to: Nelson private, 2026-10-13 17:40 UTC (Gmail 1a1365a71ab1e9ab). On list: Nelson's charter-fit post, 2026-10-10 19:26 UTC (Gmail 1a1274918384d30d), using sweep Draft 5. Not the April wimse thread.
- Speak by: private 2026-10-22; list before 2026-10-26.
- Done: private reply 2026-10-20 (Gmail 1a15967b8aa2efb5), no support promised, three conditions named; list reply on the charter-fit thread 2026-10-20 (Gmail 1a15967e1dd7edcd). Stance now WATCH. Trigger: Nelson replies or posts -15.

### AIMS-00 multi-hop delegation context (wimse)

- Last read: 2026-10-18. Latest: Wes Jackson, 2026-10-14 (split thread, Gmail 1a1387ebdbc1f653).
- State: convergence thread. Kieran's act-as-attribution framing was adopted by Wes and Mikhail Sergeev. Mikhail's Section 11 text is PR #158, unreviewed. Badal Bhushan has not posted the example. Live edge: Girish Konda's runs show outstanding permits and stale receivers outlive revocation; Mikhail's example text defers that to "the selected profile" with only MBA as the worked case. Not a fight.
- Stance: WATCH (was SPEAK, short; posted 2026-10-20).
- Position: AIMS should state a property, not defer to a profile. Every deployment states its exposure bound after revocation: the receiver's maximum state age plus the lifetime of a permit issued on that state. A server in the call path states near zero; a caching PDP states its own number. Each is measured against its own bound, and no implementation's semantics go into WG text.
- Reply to: Mikhail Sergeev, 2026-10-12 05:42 UTC (Gmail 1a12ea23a19e1dee), cc Girish. Base on sweep Draft 2, last paragraph cut.
- Speak by: 2026-10-22.
- Done: posted 2026-10-20 (Gmail 1a15967f8e860a4b), stating the exposure bound as a property. Stance now WATCH. Trigger: Mikhail revises PR #158 or replies.

### draft-seymour-wimse-connected-flight-06 (wimse)

- Last read: 2026-10-18. Latest: Girish Konda, 2026-10-15 17:30 UTC.
- State: -06 admits no atomic consumption mechanism and proposes a completion record checked before a second Boarding Pass is minted. Girish: that governs reissuance, not admission, and a lost completion report cannot prove a pass unused. Errol Seymour has not answered.
- Stance: WATCH (was SPEAK, short; posted 2026-10-20).
- Position: consumption has to be a check-and-set at admission by the single party that admits the call (the STS if it is in the path, otherwise the executor), written at admission, not at completion. The cost is that a pass admitted and then failed is spent; the draft should say so.
- Reply to: Girish, 2026-10-15 17:30 UTC (Gmail 1a1409ecb0271555).
- Speak by: before Errol posts -07.
- Done: posted 2026-10-20 (Gmail 1a15967eabe4fd21). Stance now WATCH. Trigger: Errol replies or posts -07.

### Gilda agent audit record, "could not evaluate" (wimse, moving to AUDIT BOF)

- Last read: 2026-10-20. Latest: Cliff Singletary, 2026-10-19 23:53 UTC (Gmail 1a15696283ee0628). Replaced by draft-gilda-audit-agent-audit-record-00 (2026-10-16).
- State: settled. Required evaluation member, unavailableInput from a closed set, required lastResult and maxAge, age measured from decision.reportedAt. Girish Konda (Oct 19, Gmail 1a156455320eaf70) reviewed -00 and vectors PR 185 and closed both his points: Section 5.4 measures age from lastResult to decision.reportedAt with age equal to maxAge still fresh, evaluated records carry their inputs, and a later hop writes its own record rather than amending the sealed one (FR15a, FR15b). Cliff confirmed the same day. Wes Jackson (Oct 19, separate "Heads-up: audit-record draft renamed", Gmail 1a15630793d22fc6) noted the rename keeps section numbers and that the PQ draft's planned citation and draft-thaha-wimse-agent-evidence-binding-00 (posted Oct 19) still cite the old name.
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

### draft-asor-wimse-agent-delegation-chain-02: Principal standing at time of use (wimse)

- Last read: 2026-10-19. Latest: Rafael Asor, 2026-10-18 17:24 UTC (Gmail 1a1500b970029d4c).
- State: Cliff Singletary (Oct 16, Gmail 1a145fc495439c10): Section 9.7 says verification shows no hop exceeded the root, never that the root was right; a second limit is that nothing shows the Principal in "sub" still holds the DT_0 authority when an action is taken. Asked for a Table 1 row: "chain alone - no; with the request - no". Asor (Oct 18) agreed; the row goes into -03 as written, credited to Cliff, before the 2 November cutoff.
- Stance: WATCH. No separate post.
- Position: the row is right for the chain. It should not read as "nobody can know". A server in the call path that holds the Principal's deposited grant learns at use time whether the upstream grant still stands, because the upstream refresh or call fails when it is withdrawn. That covers the withdrawn-grant case, not role loss inside the Principal's own organization. If Kieran wants it said, one sentence rides in the owed reply to Asor under the -01 call for comments, not a new thread.
- Trigger: -03 posts and the row or its prose implies the property cannot be established anywhere; or the shared constraint section changes.

### Brokered OAuth security as a separate document (oauth, Pedram Hosseyni)

- Last read: 2026-10-20. Latest: Pedram Hosseyni, 2026-10-19 08:49 UTC (Gmail 1a1535ae3ad26d26). No replies yet.
- State: Pedram asks whether there is interest in a separate document on brokered OAuth architectures, their common deployment patterns and security considerations, moving Section 2.4 (shared consent in brokered OAuth) of draft-ietf-oauth-security-topics-update-03 into it. Presented at IETF 126. Section 2.4 not yet read (Datatracker fetch failed 2026-10-19).
- Stance: WATCH (was SPEAK, short; posted 2026-10-20).
- Position: support the separate document. Cred is a brokered deployment in practice: the Delegation Server holds user-deposited OAuth credentials and agents exercise them by proxy without ever holding the token. That is a different pattern from a broker that hands tokens to multiple clients under one consent, with different risks: the custody broker concentrates refresh tokens and must bound who can cause a call, while the pass-through broker leaks consent scope across clients. The document should name both patterns and keep them apart. Offer the custody pattern as one worked case; do not pitch Cred. Read Section 2.4 first so the reply builds on its terms.
- Reply to: Pedram, 2026-10-19 08:49 UTC (Gmail 1a1535ae3ad26d26).
- Speak by: 2026-10-26.
- Done: posted 2026-10-20 (Gmail 1a159681be9a15b2). Section 2.4 read first (2026-10-20): it describes a broker that is one OAuth client for many downstream clients and leaves open whether tokens are passed on; the reply asks the document to name both the pass-on and the custody patterns and notes shared consent applies to both. Stance now WATCH. Trigger: chairs or Pedram move to start the document.

### draft-rampalli-pedigree status correction (wimse, Karthik Rampalli)

- Last read: 2026-10-19. Latest: Karthik Rampalli, 2026-10-18 13:00 UTC (Gmail 1a14f1ae8c94c1c8).
- State: Karthik corrected his July messages: draft-rampalli-pedigree-01 was never posted; only -00 (April 2026) exists. draft-rampalli-cross-org-delegation-mapping-05 cites -01 and should cite -00. The fail-closed revocation text and IANA fixes promised for -01 are in no posted revision. He will post when a revision is on the datatracker.
- Stance: WATCH.
- Position: nothing to add; a status correction. Do not cite pedigree -01 or its revocation text anywhere, including Kieran's -02 Related Work.
- Trigger: a pedigree revision posts with the fail-closed revocation text; then compare it with -02 Section 7.

### PQ requirements for agent identity (wimse)

- Last read: 2026-10-20. Latest: Venkata Uppalapati, 2026-10-15 02:33 UTC. Related: Wes Jackson, 2026-10-19, asked VK to retarget the planned Gilda -03 citation (Sections 4.7 and 4.6) to draft-gilda-audit-agent-audit-record-00.
- State: converged on splitting PQ-R7 between Gilda -03 and the audit architecture; (e) is a verifier rule. Questions 1 to 3 (transition date, algorithm-profile claim, ML-DSA for workload credentials) unanswered. Root-key provenance has no home.
- Stance: WATCH. The fixes go in Kieran's own -02 (see above).
- Trigger: question 2 resurfaces. Kieran's answer: a server that re-verifies every hop can sign the per-hop algorithm profile into its receipt. Reply to Uppalapati, 2026-09-29 (Gmail 1a0ee4c35e29237b).

### agentproto Topic 2: terminology and architectural concepts (agentproto)

- Last read: 2026-10-20. Latest: Girish Konda, 2026-10-20 05:54 UTC (Gmail 1a157e071dba98f2). Companion thread: Songbo Bu, "Topic 2: participant, principal and instance terminology", 2026-10-20 02:45 UTC (Gmail 1a157341368ceb6e), no replies.
- State: chairs Leslie Daigle and Orie opened Topic 2 on 2026-10-19 (Gmail 1a1564de7d707d22): candidate terms and architecture text for the Reference Architecture, naming dialog, dialog context, participants and intermediaries; Topic 1 closed the same day with draft-agentic-ai-usecases-requirements-04 as the starting point. Lars Kroehl (Oct 20): no candidate document separates a step that forwards a task unchanged from a step that narrows the authority it carries; "hop" has three meanings and the conveyed authority five names; offers a quote table. Girish (Oct 20): agrees with Lars; an intermediary that narrows authority is a decision point and records its own decision, one that only forwards must not change earlier results; proposes UCR-04 Section 2 as base plus Sections 2 and 5 of draft-konda-agentproto-evaluation-state-02. Songbo: separate a participant's role from the instance performing it and the principal it represents (Principal Binding -08 Section 8); continued authorization across instance replacement is not established by authentication or dialog correlation.
- Stance: SPEAK, short.
- Position: support the forward versus narrow split; this is the sub-delegation step in Kieran's draft. A narrowing step is a delegation: it is valid only if the result is a subset of what was received (monotonic attenuation over typed constraints, the same ceilings draft-asor uses), and the party that performs it should be the one that signs the record of it, so the record says whose decision it holds. A pure forwarder carries the authority by reference and makes no authorization claim. On Songbo's point, authority should attach to the delegation from the principal, not to the instance, so an instance replacement needs no new grant but does need the authority-holding party to recognize the replacement. Offer draft-sweeney-wimse-credential-delegation Section 5 as one worked definition; do not propose it as the base document.
- Reply to: Girish, 2026-10-20 05:54 UTC (Gmail 1a157e071dba98f2), which already agrees with Lars. Songbo's point can be answered in the same message.
- Speak by: 2026-10-27, before the chairs summarize Topic 2 (Topic 1 ran about two and a half weeks).

### Use case input: recomputing whether an agent acted within a delegated grant (agentproto, Toshikatsu Oga)

- Last read: 2026-10-20. Latest: Toshikatsu Oga, 2026-10-20 04:53 UTC (Gmail 1a157a8d9bd45b88). No replies.
- State: Oga offers a use case from a running system: two operators sign a contract granting an agent a bounded set of actions, the agent signs a record of each action, records are timestamped, and a third party recomputes compliance later (draft-oga-musubi-settlement-01, Informational). His narrow ask: a stable way to bind each action record to its delegation; today a request digest in his own format. He offers short use case text.
- Stance: WATCH.
- Position: the binding he asks for is real and is what DS-signed per-hop receipts provide when a server is in the call path: the record names the delegation it was exercised under, signed by the party that admitted the call. An agent-signed record binds the action to the agent's claim, not to an admission decision. Nothing to post until the editors decide whether to take the use case.
- Trigger: the use case editors take it up or the group proposes a binding identifier in dialog context. Then one short reply to Oga with the admission-side point.

### draft-heigh-wimse-workload-identity-metadata-00 (wimse, Joe Salowey)

- Last read: 2026-10-20. Latest: Joe Salowey, 2026-10-19 16:55 UTC (Gmail 1a15516d0197938c). No replies. Authors Heigh, Rosomakho, Salowey; asking for time at IETF 127.
- State: separates the workload identifier from metadata (group, role, owner), carried in WIT claims or an authenticated metadata endpoint. Datatracker (read 2026-10-20): Section 4.2 says per-request delegation belongs in the authorization context, such as an OAuth access token, and points to Token Exchange; Section 5 says a delegated agent's credential still identifies the agent and the agent does not take on the delegating principal's groups or roles. The durable principal association (owner or operator) has no claim yet and is an open issue.
- Stance: WATCH.
- Position: agrees with Kieran's draft: identity stays with the agent, authority travels in the delegation. Nothing to add now.
- Trigger: the open principal-association claim is defined in a way that lets an identity credential carry delegated authority, or an adoption call.

### draft-ietf-wimse-http-signature-08 (wimse, Yaron Sheffer and Joe Salowey)

- Last read: 2026-10-20. Latest: Yaron Sheffer, 2026-10-20 12:51 UTC (Gmail 1a1595e14e178225).
- State: -08 addresses Justin Richer's shepherd review, Yaroslav's CONNECT comment, "and an earlier comment from Kieran that we missed before". That is Kieran's 2026-10-08 post (Gmail 1a11970aa51f43cc) asking how wimse-aud is compared. -08 Section 3.2 (read 2026-10-20) now says the recipient MUST verify wimse-aud against its configured values using RFC 3986 Simple String Comparison, that trailing slash and default port variants do not match unless configured, and that the recipient MUST NOT derive an acceptable audience from untrusted fields such as Host (change log: #396). This is the first of the two fixes Kieran proposed. Acknowledgments credit Kieran's WGLC review.
- Stance: WATCH.
- Position: resolved as asked. No post needed; a thank-you is optional.
- Trigger: IETF last call, or #396 reopened.

### IETF 127 agenda (wimse, joint session)

- Last read: 2026-10-18.
- State: Asor declined to present (private, 2026-10-15). Justin Richer, Oct 10: no presenter, no slot. The held agenda-request draft that names Asor must not be sent.
- Stance: SPEAK once Kieran picks: present remotely, or ask the chairs for a presenter. Sweep Draft 8. A Gmail draft (2026-10-20, to Pieter and Justin) is ready but holds a pick-one placeholder; it was not sent on 2026-10-20 and needs Kieran's choice.
- Speak by: 2026-11-02.

## Closed

### AIMS negative test cases (wimse, Deonté O'dell Watts)

- Closed 2026-10-18. Jijie Wei answered (option 2: point to jackson evaluation-04 Appendix A, konda-01 Section 6, Gilda Section 6.5) and Deonté accepted on Oct 18. Sweep Draft 4 is superseded.

### AIMS-00 negative examples separating agent identity from delegated authorization (wimse)

- Closed 2026-10-18. Duplicate posts of the question above from two other addresses; no replies.
