# WIMSE Sweep, 2026-10-15

Baseline: Oct 6 sweep, Oct 13 standards pass (pending-replies register). Bottom line first: draft-asor-wimse-agent-delegation-chain-02 posted today and it lands everything you argued for, but it also shows that your -01's interop claim is wrong on the wire. Rafael declined to present at IETF 127, so your draft has no presenter and, under the chairs' stated rule, no slot. Songbo Bu found two real defects in your -01, and a reply plus a -02 fix are ready.

Assumptions for this unattended run: "within 7 days" means through 2026-10-22; the register's row statuses are updated from archive and Gmail evidence only; reply drafts are for your review and nothing was sent or posted.

## Deadlines inside 7 days

- **2026-10-19, OAuth interim (interim-2026-oauth-09), "Agent Authorization: Use Cases and Gaps".** The agenda is that one line, with no drafts, slots, or presenters ([agenda](https://datatracker.ietf.org/meeting/interim-2026-oauth-09/materials/agenda-interim-2026-oauth-09-oauth-01-00)). It is about draft-chen-oauth-agent-authz-use-cases (now -04). Caleb Dyer posted mechanism-neutral requirements R1 to R13 ([msg](https://mailarchive.ietf.org/arch/msg/oauth/D85ouFvh2-AZz-xOhsnw1lFS0TI/)): local verification without phoning home (R7), audience-bound (R8), delegate-bound so theft confers nothing (R9), caps the delegate cannot raise (R10). Xiang Liu added a cross-org supplier-agent use case (issue #31) ([msg](https://mailarchive.ietf.org/arch/msg/oauth/0viwS2hbFoDLeCfn3feBgGJpjwA/)). Optional pre-position: a short mechanism-neutral comment on #31 or #33 saying those properties hold whether the grant is user-minted or server-issued. You are not presenting; read the notes afterward.

Just outside the window: draft-gco-oauth-delegate-sd-jwt-00 expires 2026-10-24; Mission-Bound Authorization interim 2026-10-26 17:00 UTC ([announcement](https://mailarchive.ietf.org/arch/msg/oauth/KsfBiNMSJ42Tpwkt_p2S1pV5u7o/)); IETF 127 I-D cutoff 2026-11-02 23:59 UTC.

## Pending replies and their shelf life

Full register in `reports/pending-replies.md` (updated in this PR). Open items:

- **E1 Songbo Bu review of your -01** (Oct 14). Owed. Shelf life: until -02 posts, before Nov 2. Draft 1 below.
- **D3 IETF 127 presenter.** Asor declined privately today (Gmail, 2026-10-15 15:59 UTC, unread): "I am not presenting at IETF 127, my own draft included, and I am not asking for a slot. For yours, ask the chairs whether someone can present your slides for you." Your held agenda-request draft (Gmail r-3987888833381149220) names Asor as presenter and **must not be sent as written.** Justin Richer, Oct 10: "If someone cannot present the draft, then it will not be added to the agenda" ([msg](https://mailarchive.ietf.org/arch/msg/wimse/VFNvjk_i6ubndkDxAoJ5ptgTe0E/)). Decision is yours: present remotely, find a presenter, or skip 127. Draft 8 below covers the first two.
- **D4 Delegated SD-JWT Section 6 comments.** HOLD continues; no chair result. Correction to the standing prompt: your archived support ([msg](https://mailarchive.ietf.org/arch/msg/oauth/WziU-KYOfZ-S43ZdQq4rbGaLs74/)) is a bare "I support adoption". It does not ask for Section 6 formatting or act-chain mapping; those exist only in the Gmail HOLD draft. When adoption is announced, rework that draft to credit Rajasekar and Singletary, who have since raised the adjacent Section 6 points, and lead with the act-chain mapping, which nobody has made.
- **A6 HTTPSig JWK/pub note.** PARKED. No chair conclusion; the thread's last message is still Campbell's Oct 4 oppose.
- **E2 to E7.** New drafts from this week (below). None has a hard deadline inside 7 days; the fine-grained wedge (Draft 3) is timed for the Oct 26 interim.

## Status table

| Thread | Stance | One-line reason | Deadline | Reply-to |
|---|---|---|---|---|
| Call for comments on your -01: Songbo Bu review | REVISE (own draft) | Both defects are real: Section 4.4 MAY contradicts 5.1; client_id names the wrong party at sub-delegation | before -02, Nov 2 | https://mailarchive.ietf.org/arch/msg/wimse/qEvDvVG7q2RpzawaiTrpoZ-2AFI/ |
| asor -02 posted | no reply owed | Lands opaque scopes, sub/client_id, Delegation Server bridge (Section 8) and shared ledger (9.4). Your Oct 7 vector loop is closed by Appendix A and B | n/a | https://www.ietf.org/archive/id/draft-asor-wimse-agent-delegation-chain-02.txt |
| AIMS-00 multi-hop: Girish Konda vs Mikhail Sergeev on revocation | WEDGE | Girish shows outstanding permits and stale receivers outlive revocation; Mikhail writes one implementation's semantics into WG text. A stated exposure bound satisfies both | none | https://mailarchive.ietf.org/arch/msg/wimse/OBRXClsaF6HN6zd0OqBrK5l4K0M/ |
| AIMS negative test cases (Deonté O'dell Watts) | SUPPORT | Identity valid, authority revoked is Cred's model; point him at Girish's runs instead of a parallel appendix | none | https://mailarchive.ietf.org/arch/msg/wimse/wAVstR-NChrnu-Ylddi2tWiZWLQ/ |
| OAuth fine-grained: Karl's downstream-verification question; Blake and Arun answer opposite ways | WEDGE | Executor verifies links joined on intent_hash, not the instruction; portable-artifact principle applied to approval | Oct 26 interim | https://mailarchive.ietf.org/arch/msg/oauth/l4L-w22Nlo99gKGVE2W9xs0BA2k/ |
| Nelson delegation receipts, charter fit (-14 posted today) | REVISE | Holder-binding defect: a copied parent receipt can mint a passing child; Section 10 makes one implementation's gate normative | none | https://mailarchive.ietf.org/arch/msg/oauth/eNfyp7WcKWlun7fL582oaSPvTuY/ |
| Revocation closure semantics (Watts, oauth) | SUPPORT | Closure differs from invalidation; push to negative vectors, not a new object | none | https://mailarchive.ietf.org/arch/msg/oauth/zb3FqNpEi8MgBSTWXMlx6wZYC7k/ |
| gilda agent-audit-record adoption request | REVISE (optional) | Chairs declined the call Oct 12; AUDIT BOF approved for 127. -02 effect model is filesystem-only, so a mediating component can never emit an authoritative record | none | https://mailarchive.ietf.org/arch/msg/wimse/qw_P1pGFO8YCR7Cja-OsFqD2SFk/ |
| IETF 127 agenda (WIMSE + joint) | procedural | No presenter means no slot; neither your draft nor Asor's is named in any of 13 agenda messages | Nov 2 at latest | https://mailarchive.ietf.org/arch/msg/wimse/kTtvzzt0iVVkuvWI0nJey04pVi0/ |
| Delegated SD-JWT CfA | HOLD | 17 support, 0 oppose; no chair result; -00 expires Oct 24 | Oct 24 expiry | https://mailarchive.ietf.org/arch/msg/oauth/olDRhLWftgA-H8bgyt0ueKAWN4g/ |
| HTTPSig CfA | PARKED | No chair conclusion | none | https://mailarchive.ietf.org/arch/msg/oauth/rFLBcBk2sdJZgL8ff_67dcSmnMo/ |
| may_act / RFC 8707 (Zehavi) | SKIP | His Oct 8 reply asks nothing; his -00 adopted most of your points. Gaps if you review later: no signed_metadata, local-policy escape hatches, SHOULD-reject in 9.4 | none | https://mailarchive.ietf.org/arch/msg/oauth/d76iqAmcqVikn0GqZsAFUcV8V-c/ |
| WAG (draft-carleton-workload-authz-grant) | SKIP, monitor | Still -01; composition slot open ("intended to compose with delegation mechanisms in which the workload is the actor"); PoP still open (Section 8) | none | https://www.ietf.org/archive/id/draft-carleton-workload-authz-grant-01.txt |
| WIMSE EoI on the WAG problem | nothing owed | You answered yes/yes/yes Oct 8; Asor's Oct 15 reply notes his client_id is an unchecked string | none | https://mailarchive.ietf.org/arch/msg/wimse/wtGe2HqLNIeec1345pKAmjTxRWc/ |
| draft-jackson-wimse-evaluation-04 | SKIP | Credits you and Errol Seymour for per-hop attestation in 3.5 | none | https://mailarchive.ietf.org/arch/msg/wimse/4zC64UTVKiPf1TCKf2F50UrqJJY/ |
| http-signature-07 | SKIP | No -08; Section 3.2 still has no audience comparison rule; your residual WGLC point stands, already on record | none | https://www.ietf.org/archive/id/draft-ietf-wimse-http-signature-07.html |

Skipped with one line each: PQ agent identity (crypto agility, not delegation); Per-Call Proof for local tools (watch only); Txn Tokens agentic context and tt_xdomain JAG-to-Txn (watch: the cross-domain hop chains must survive); Transactional Access Tokens (Girish's cnf handoff point is the broker problem, watch); cross-org vectors (approval reuse fix, adjacent); AIN-WRP (registry vocabulary); Campbell on workload-creds-02 and wpt-01 (editorial); Simhadri book (not standards work); KYAPay and skyfire (payments and proofing); Issuer-signed JWT with DPoP (adjacent, watch); oob-authcode (UX); attestation-based client auth -12 (client auth); errata and sd-jwt-vc IANA (process).

## Standing targets

1. **Delegated SD-JWT**: CfA closed Oct 12; no announcement through Oct 15; -00 still current, expires Oct 24 (Datatracker). Your Section 6 and act-chain asks are not on the list (see D4).
2. **HTTPSig**: PARKED, no chair announcement.
3. **AIMS-00 multi-hop**: badal bhushan has not posted since Oct 1; others are writing the example in pieces (Blake hop 0, Mikhail wording, Girish test runs). Nobody pushed back on your act-as-attribution point; Wes and Blake both build on it. Nobody answered your Oct 8 post, which was an agreement, so nothing is lost.
4. **Fine-grained authz**: no design team. The chairs chose an interim on draft-mcguinness-oauth-mission instead (Oct 26). Mission still -00. Karl engaged your portable-artifact point within an hour of your Oct 6 post ([msg](https://mailarchive.ietf.org/arch/msg/oauth/zr7vyXmG6nU4IRvdQA9zgC2HuGY/)): he agreed the artifact matters more than where it lives and pointed to the Mission Mandate, but kept issuer-side freshness, so Section 16's coupling stands. Ron Bartor took your side and filed it into #1051. Lever for whoever handles #1051: the `amb` digest Zehavi and Morrison just agreed solves a similar freshness problem without a call home.
5. **agentproto**: chartered Oct 8; chairs Orie Steele and Leslie Daigle; AD Charles Eckel. Delegation and credentials are not deliverables; the charter defers identity and authorization to OAuth, webbotauth, and WIMSE. First adoption milestone Dec 2026 (use cases). 127 session requested. Optional: a short deployment-model note in Topic 1 pointing at WIMSE as the dependency.
6. **WAG**: -01 unchanged; composition slot open; PoP open; Girish's retirement signal filed as issue #18. The Oct 7 interim poll: 16 yes, 0 no, 2 no opinion on the problem and this document as a starting point ([poll](https://datatracker.ietf.org/meeting/interim-2026-wimse-02/materials/polls-interim-2026-wimse-02-202610071700-00)). Sean O'Dell asked for an actor claim; Paul Carleton said WAG has not gone there. That open actor slot is where on-behalf-of delegation composes.
7. **asor -02**: posted 2026-10-15 15:00 UTC, ahead of the Oct 19 target. Details next.

## asor -02: what landed, what changed for you

Read in full against -01 this run ([txt](https://www.ietf.org/archive/id/draft-asor-wimse-agent-delegation-chain-02.txt)).

What landed: Section 4.1 is the three-form grammar you and Iman settled, verbatim; classification by bytes alone; the residual ambiguity is stated next to the grammar as lowercase guidance ("should not grant a wildcard over its prefix"), not a MUST NOT, so it does not constrain broker deployments. Section 3 makes `sub` the Principal (invariant, checked at step 3) and `client_id` the Acting Agent, but `client_id` is "a string", unchecked. Section 8 keeps your online bridge as a MAY: "Deployments that require synchronous cascading revocation MAY issue and exercise Delegation Tokens through an online Delegation Server as specified by [I-D.sweeney-wimse-credential-delegation]". Section 9.4 names the Delegation Server as one place shared accounting can be held. Section 1.1 calls the two drafts "halves of one design, separated by a single axis: whether a server is in the path". Appendix A credits you for the opaque form and its vectors; three of your vectors are in the new set. `rank` carries its ordering on the wire in an `order` member, which closes the gap your -01 Section 5.3 raised.

What breaks: -02 Section 4 requires exactly one authorization detail, of type `agent_delegation`, closed to the members `type`, `scopes`, `constraints`; any other detail type is malformed. Your -01 carries `cred_delegation` details and a separate top-level `constraints` claim, and its Related Work says "a chain minted by either can be checked by a verifier written for the other". That sentence is false against -02. The -02 working copy in the protocol patch corrects it and leaves the bigger choice to you: adopt the `agent_delegation` shape for chain-verifiable tokens (restores the claim) or keep separate formats.

New conformance work: -02 ships a second, 35-vector set (`cnf`, `client_id`, principal invariance, `max_lifetime` and `max_subtree`, closed objects, `order`). The Cred harness has not run it. Cred will fail principal invariance today, since receipts put the agent in `sub`.

BYO check: clean. No provider registry, no mandated broker, the online server is optional and cited by role. Root issuance (9.7) and trust-anchor provenance (6.4) are stated as deployment and WG questions, not vendor-bound.

## Reply drafts

All drafts are for your review. Nothing was sent. Plain URLs only: your Oct 8 and Oct 13 posts went out with google.com/url redirect wrappers around datatracker and GitHub links; paste raw URLs.

### Draft 1 (REVISE, own draft). Answers https://mailarchive.ietf.org/arch/msg/wimse/qEvDvVG7q2RpzawaiTrpoZ-2AFI/

Before sending, decide whether you accept the single-use grant design; the -02 working copy implements it as Section 5.4.1 and the draft commits to it.

> Songbo,
>
> Both points are right, and both are defects in -01.
>
> Section 4.4. The MAY that lets a deployment carry the WAG identity as iss and sub inside act contradicts Section 5.1, and the paragraph contradicts itself: it says act.sub remains the Agent DID, then permits replacing it. A token built under that MAY has act.sub naming a platform-scoped identifier while client_id names the DID, which Section 5.1 calls malformed. -02 removes the MAY. WAG identity travels only as receipt evidence under Section 5.4, with the issuer and registration context Section 4.4 already requires. A verifier that needs the WAG identity reads it from a DS-signed receipt bound to the hop, not from a token claim whose meaning depends on a mapping the verifier may not hold.
>
> client_id. RFC 8693 Section 4.3 defines it as the client that requested the token, and RFC 9068 Section 2.2 imports that definition. -01 never says who requests a child, and the natural reading of Section 5.4 is that the delegating agent does. Under that reading A requests the token and client_id names B, which is wrong. The fix is to make B the requester:
>
> 1. A holds T1 (sub=user, client_id=A, act={"sub":A}). It calls the DS with T1, a DPoP proof, B's DID and the narrowed capabilities. The DS runs the Section 5.4 checks, signs receipt R2 naming A and B, and returns a single-use grant bound to B's DID.
> 2. B authenticates as itself per Section 4.2 and sends a token exchange request with that grant as subject_token, its own RFC 7523 assertion as actor_token, and a DPoP proof under its own key.
> 3. The DS issues T2: sub=user, client_id=B, act={"sub":B,"act":{"sub":A}}, cnf bound to B's key, prf=[R2].
>
> client_id is now the authenticated requester, act.sub agrees with it because both name B, and A appears only in nested act as attribution. The grant is useless to anyone without B's key. -02 adds this exchange to Section 5.4.
>
> On redundancy, I am keeping both. client_id is what an RFC 9068 resource server and AIMS Section 10.3 read; act carries prior actors. Rafael's -02 now puts client_id in every token for the agent acting at that hop, so dropping it here would split the two drafts. Once the receiving agent is the requester the two cannot legitimately differ, and the MUST in Section 5.1 becomes a consistency check.
>
> Thanks for reading it this closely.
>
> Kieran

### Draft 2 (WEDGE). Answers https://mailarchive.ietf.org/arch/msg/wimse/OBRXClsaF6HN6zd0OqBrK5l4K0M/

> Girish, Mikhail,
>
> Girish's runs show the two things the example has to keep apart: a permit already issued survives a revocation until its own expiry, and a receiver that has not seen the revocation keeps permitting until its state ages out. Mikhail is right that two receivers in one process do not establish cancellation or distributed timing, and the example text should not explain the result through one implementation's run-to-completion semantics.
>
> Both points are met by stating the bound as a property. After a delegation is revoked, the last action it authorizes happens no later than the receiver's state age limit plus the lifetime of the permit issued on that state. AIMS states that every deployment has this bound and that the deployer sets it by choosing those two values. The example then shows Girish's three cases, a new decision, an outstanding permit and a receiver holding stale state, each measured against that bound. The MBA results stay on the list as evidence the bound holds in one implementation, not as text in the draft.
>
> In both of Girish's cases the token facts kept verifying and only the delegated state changed. That is the case Section 11 should name: authority withdrawn while identity stays valid.
>
> Kieran

### Draft 3 (WEDGE). Answers https://mailarchive.ietf.org/arch/msg/oauth/l4L-w22Nlo99gKGVE2W9xs0BA2k/

Timed for the Oct 26 interim. Names no draft of yours; keep it that way, since Meiling Chen has called out authors pitching their own approaches.

> Karl, Blake, Arun,
>
> Karl asked whether parties downstream of the AS need to verify the original instruction themselves. Blake and Arun have answered in opposite directions. Blake is right that displayed_content is the agent's reading, so evidence of the display alone cannot show the reading matched what the person said. Arun is right that an executor can only check what it can recompute: the action it is about to perform and the bytes that were shown. Nobody downstream can recompute the instruction.
>
> Both hold if the executor verifies links instead of the instruction. Three signed statements, each from the party that witnessed its step. The intake signs over the instruction and the shaped Intent, which is Mission Request Provenance with the instruction digest Blake asks for. The Mandate commits the intent and the approved Authority Set. The approver's device signs the display digest and the action digest, which is OASNT's dsp and adg. The executor recomputes the action digest and checks that all three name the same intent_hash. It never sees the instruction and never calls the AS.
>
> What stays unverifiable is what Karl already names: whether the shaping was faithful. The chain does not close that gap. It pins it to one signer at one step, which is what an auditor needs.
>
> That works only if the action-bound approval names the intent_hash it was given under. Without that, the executor holds two valid signatures and nothing joining them. That requirement belongs in the problem statement for the 26 October interim.
>
> Kieran

### Draft 4 (SUPPORT). Answers https://mailarchive.ietf.org/arch/msg/wimse/wAVstR-NChrnu-Ylddi2tWiZWLQ/

He reposted it from a second address under a new subject (https://mailarchive.ietf.org/arch/msg/wimse/sWtb9kNIMbf2P5dcZSa-2xQNxDc/); answer the first.

> Deonté,
>
> Option 1, placed in the multi-hop example Badal is preparing rather than in a separate appendix. That thread already runs these cases: Girish's component tests produced distinct denials for revoked mission state, stale receiver state and an expired permit, with the token facts still verifying (https://mailarchive.ietf.org/arch/msg/wimse/mWKBPK-GLVOVNw8tKUMC1RhjfI8/), and Mikhail's proposed Section 11 text requires the record to tell a negative result from an evaluation that could not complete.
>
> Two properties make the negative cases worth having. Each case names the input that failed and records its own reason, so revoked, expired, wrong audience, insufficient and unavailable never collapse into one deny. And one case revokes the delegation while the agent's identity credential stays valid and keeps authenticating. That case shows authority withdrawn without touching identity, which is the separation your examples test.
>
> Kieran

### Draft 5 (REVISE). Answers https://mailarchive.ietf.org/arch/msg/oauth/eNfyp7WcKWlun7fL582oaSPvTuY/

Read against -14 (posted today; no wire changes from -13).

> Ryan,
>
> I read -14. Two technical points, then the charter question.
>
> First, sub-receipt holder binding. Sections 4.4 and 8.7 verify orchestratorSignature against the sub-receipt's own signerPublicKey. That key also signs the sub-receipt body, so the check shows only that one key signed twice. The parent body names no delegatee key (agentId is a string), so anyone holding a copy of a parent receipt can mint a narrower child that passes every check in 8.7. Receipts are bearer and get logged, so copies exist. The fix is to put the delegatee's public key or its thumbprint in the parent body and require the child's signerPublicKey to match it. orchestratorSignature then adds nothing and can go.
>
> Second, Section 10 makes the reference gate's check list, ordering, gate signing and audit logging normative for a conformance profile, along with a known deviation. Conformance should be the semantics of Sections 4 to 9. Check plumbing belongs to implementations.
>
> On charter fit: the problem is in scope. As written, the receipt touches no OAuth message. It defines no claim and no authorization_details type, and it says nothing about token exchange or the actor drafts you cited. A binding is what the WG can evaluate: for example, an authorization_details type or token claim carrying receiptId and the delegatee key, so an AS or RS can tie an access token to the receipt that authorized it.
>
> One data point. draft-sweeney-wimse-credential-delegation-01 Section 5.4 has a server sign each hop, binding the parent and child token identifiers, both actors and the subject, with the child sender-constrained. A principal-signed root and server-signed hops answer different questions and compose. A shared attenuation vocabulary would let one verifier check both.
>
> Kieran

### Draft 6 (SUPPORT). Answers https://mailarchive.ietf.org/arch/msg/oauth/zb3FqNpEi8MgBSTWXMlx6wZYC7k/

Thilina and Jeff Lombardo already asked what is new; Watts conceded nothing is AI-specific and leans to negative vectors. This gives him the distinction that survives that pushback.

> Deonté,
>
> On question 1: I know of nothing that defines it. Cascade revocation as specified today, including the revoked_count and timing bounds in draft-sweeney-wimse-credential-delegation-01 Section 7, reports invalidation. It does not say whether a queued job or a derived token can still commit. SSF and CAEP carry the event; they do not say whether the receiver acted on it.
>
> The distinction matters where the commit path has a single enforcement point that checks authority at commit time. There the cut set reduces to that point for every path through it. The paths that escape are tokens presented directly to a resource server after exchange, and cached decisions. Those are your cases 1 and 2.
>
> On question 2: a closure claim is only useful across domains if it names the enforcement points it covers. A CLOSED from a revocation service about a sink it does not gate is the failure to prevent.
>
> On question 3: negative vectors first. One to add: a queued job holds an exchanged token whose exp is later than the revocation time, and the sink does not check the epoch at commit. The correct answer is PARTIAL, never CLOSED.
>
> Kieran

### Draft 7 (REVISE, optional). Answers https://mailarchive.ietf.org/arch/msg/wimse/qw_P1pGFO8YCR7Cja-OsFqD2SFk/

Not an adoption post: the chairs declined the call ([Richer, Oct 12](https://mailarchive.ietf.org/arch/msg/wimse/JRagZQU6xb8UPizvzddlZt818To/)) and Campbell pointed it at the AUDIT BOF. Send only if you want the point on record before the format moves there.

> Subject: draft-gilda-wimse-agent-audit-record-02: effects that are not file writes
>
> Sankalp,
>
> Three points on -02, from the side of components that mediate an agent's calls rather than watch its host.
>
> Section 5.3 defines the effect as a path write set with before and after roots. A mediated call's effect is a credential used and an upstream request made. resource.kind already allows uri and tool, but effect only describes paths. I suggest an abstract effect keyed by resource, with path writes as one profile and a mediated-call profile beside it: resource id, request digest, credential reference digest, upstream status.
>
> Section 5.7 makes authoritative depend on below-observed vantage and a non-empty pathScope. A component that holds a credential the agent never sees observes every call made with it, from a layer the agent cannot address for those calls. Under -02 it can only emit voluntary records, which Section 5.7 says carry no evidence of observed fact. The tier clauses should admit a mediating observer for the effects it mediates.
>
> Section 8 puts the predicate type under probityai.github.io and says it should not move once records exist. Moving it to an IETF-controlled identifier now costs nothing. Doing it after deployment invalidates signatures.
>
> If this work moves to the AUDIT BOF, the same three points apply there.
>
> Kieran

### Draft 8 (procedural). IETF 127 agenda request, to the WIMSE chairs (reply on https://mailarchive.ietf.org/arch/msg/wimse/kTtvzzt0iVVkuvWI0nJey04pVi0/)

Send only after you pick the presenter line. Replaces the held Gmail draft that names Asor.

> Pieter, Justin,
>
> Requesting 10 minutes for draft-sweeney-wimse-credential-delegation, preferably in the joint session and adjacent to the delegation-chain discussion, since draft-asor-wimse-agent-delegation-chain-02 cites it as the server-side half and the two share one scope grammar, constraint vocabulary and sub/client_id split. [I will present remotely. / Can someone present slides on my behalf? I cannot attend.] -02, resolving the client_id and WAG issues Songbo Bu raised on the list, will be posted before the 2 November cutoff.
>
> Kieran Sweeney

## BYO landscape

The broker layer is no worse off this week and has one new structural ally. asor -02 frames online servers as an optional, role-named half (Sections 8, 9.4) and declines a provider registry; that is the broker-neutral framing you want. Watch items: (1) WAG is the strongest gravitational pull toward platform-issued agent identity. The EoI thread and the Oct 7 poll show momentum; your -01 Section 4.4 keeps WAG as evidence beside a self-generated did:key, and Asor's EoI reply ("a workload identifier it can verify without setup would let it check that name") is the opening to keep did:key and WAG as alternatives for verifying client_id, never WAG alone. (2) Mikhail Sergeev's AIMS example text names one reference implementation's semantics ("MBA"); Draft 2 keeps that out of WG text. (3) Nelson -14 Section 10 ties conformance to one implementation's gate; Draft 5 names it. (4) The joint 127 session is filling with transaction-token requests (Fletcher, Tulshibagwale, Raut). Without your draft on the agenda, 127 discusses delegation only through Txn-Tokens and verifier evaluation.

Anthropic surface: WAG (Carleton, Anthropic, ed.) unchanged at -01, composition slot and PoP both open, actor claim explicitly not taken (Oct 7 minutes). No new MCP-authorization or webbotauth activity on these lists this week. OpenAI surface: draft-ietf-wimse-aims still -00 (Datatracker, 2026-09-15); no Nick Steele list activity seen in the threads read; the multi-hop example is being written by non-authors.

## Repo state

Previous sweep's patch (Oct 6, sdk PR #37) is merged; the -01 prep (protocol PR #5) merged Oct 7 and -01 was submitted Oct 13 (protocol PR #9). Open-PR baseline from the standing prompt is stale: sdk #36, #37, #38 and protocol #5 are all merged.

This run's changes (delivered as patch files; see end of report):

- protocol, branch `wimse-sweep/2026-10-15`: `ietf/draft-sweeney-wimse-credential-delegation-02.mkd` working copy with generated `.xml`/`.txt`, readable `-02.md`, `ietf/REVISION-02.md`, README pointer. Fixes Songbo's two defects (new Section 5.4.1 Sub-Delegation Exchange), aligns Section 5.3 with asor -02, corrects the Related Work interop claim, bumps ASOR to -02 and Nelson to -14. Toolchain reproduced the committed -01 text byte for byte before editing; -02 renders with no line over 72 columns. Not submitted. Two decisions for you are written at the top of `REVISION-02.md`.
- sdk, branch `wimse-sweep/2026-10-15`: this report; the register updated; `docs/design/scope-abnf-interop.md` and `docs/protocol-conformance.md` updated for asor -02.

## Sources not loaded or not read

- The 127 agenda requests were read for names only, not for content beyond the summary above; eleven EoI replies (Kemp, Konda, Hutchinson, Seymour, Rose, Drake, Andreasen, Wei, Bu, Morrison, Cedergren) were not read.
- agentproto thread "binding resumed dialog context to current authorization" not read; it is the closest agentproto overlap with your work.
- The Oct 19 OAuth interim announcement message itself was not read; the agenda page was.
- GitHub mcguinness/mission-bound-authorization#1051 belongs to another agent and was not checked.
- First subagent pass hit a usage-credit error mid-run and was re-run on a different model; all findings above come from the completed second pass plus direct checks in this session.
