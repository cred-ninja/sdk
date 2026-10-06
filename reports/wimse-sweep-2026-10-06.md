# WIMSE Delta Sweep, 2026-10-06

Baseline: Oct 1 sweep. Bottom line first: none of the four drafted replies went out. One window closed (httpsig, Oct 5). One is still open and now urgent (Delegated SD-JWT, Oct 12). The AIMS act-claim point is still yours to make. The interim is tomorrow and its agenda changed the prep entirely.

## Today's sequence, three priorities

1. **Send the Delegated SD-JWT support reply** (CfA closes Oct 12). Fifteen supporters now, still zero substantive engagement; your reply remains the only one in the thread that touches the verification mechanics. Draft unchanged from Oct 1, reply-to the CfA root: https://mailarchive.ietf.org/arch/msg/oauth/olDRhLWftgA-H8bgyt0ueKAWN4g/

2. **Send the refreshed AIMS multi-hop reply** (v2 below). The thread grew six messages Oct 1 to 5 and nobody has named the RFC 8693 act claim; Blake Morrison and Jijie Wei circled sub without landing on act. Bhushan committed to drafting the example, so the carrier question gets decided soon, with or without you. New reply-to is Girish Konda's Oct 5 message.

3. **Interim prep for tomorrow** (Oct 7, Europe/Dublin tz). The agenda is a single item and it is not AIMS: draft-carleton-workload-authz-grant (Carleton, Anthropic, ed.; Steele; Parecki; Schwenkschuster; Campbell). Talking points and the one question worth asking are below. The Oct 1 report's interim talking point (AIMS composition) is moot for this meeting; the list thread is its venue now.

## httpsig: window missed, decision needed

CfA closed Oct 5. No message from you posted. Final rough tally 9 support, 5 oppose; Brian Campbell flipped the late count by opposing on Oct 4 ("additional WG-sanctioned mechanism will create uncertainty and harm interoperability"). No chair conclusion in the archive as of this morning. Recommendation: do not send the wedge late. A post-deadline vote does not count and reads as noise. If the chairs declare adoption, the JWK/pub alignment point lands as the first WG issue, which is exactly how the draft reply framed it; park it for that moment. If they decline adoption, the point is moot. Either way the chair announcement is the trigger, and the updated recurring prompt watches for it.

## What else changed, Oct 1 to 6

Delegated SD-JWT: five more supports (Cappalli, Morrison, Birgisson and Balfanz of Google, Niyikiza), zero opposition. Note the draft itself expires Oct 24, so a -01 lands quickly after adoption; the act-chain mapping ask in your reply positions you for that revision window.

Fine-grained authz thread: twelve more messages, no design team formed yet. The wedge needed rewriting and got it (v2 below): Ron Bartor conceded the metadata layer to Yaron, then self-corrected on Oct 3 after reading Karl McGuinness's runtime companion, and his remaining ask is the cross-PDP join that the companion's Section 16 declares out of scope. The portable-artifact synthesis is still unmade by anyone. McGuinness says Mission -01 publishes within weeks. New reply-to is Bartor's Oct 3 self-correction.

AIMS multi-hop thread: Wes Jackson asked what each verifier holds at decision time, Girish Konda split chain contents from issuer lookups and pushed as-of times plus the audit-record vocabulary, Blake Morrison wants the user's first-hop grant as its own step, Jijie Wei formalized containment versus intersection with a three-outcome decision. The thread is converging on the record shape with the attribution carrier still unnamed.

Your draft: unchanged on datatracker, rev 00, expires 2027-01-29. No new revisions of aims, delegate-sd-jwt, or httpsig. Agentproto chartering progressed (Eckel yes-ballots Oct 2, work-sequencing thread from Orie); still no adoption machinery. No new CfA or WGLC on any of the three lists.

## Reply draft v2: AIMS multi-hop

Reply-to: https://mailarchive.ietf.org/arch/msg/wimse/EVV1lJ_MaUbCNny_Qb1yXM6nVA0/ (Girish Konda, Oct 5)

> Girish, Jijie, Blake, Wes, Badal,
>
> This thread has sorted the per-hop record into the right columns: what the chain carries, what is an issuer lookup at an instant, what the grant covered at the first hop, and what the verifier decided with each input's as-of time. What nobody has named is the carrier for the first column, and it already exists. RFC 8693 defines the act claim for exactly the three attribution items on Badal's list: sub stays the original delegated subject through every exchange, act names the current actor, and nested act records the chain of prior actors hop by hop. AIMS-00 cites 8693 for the exchange mechanics in 10.8 and never mentions act, the one piece of that RFC built for this. The example should use it rather than invent a new container for who acts for whom.
>
> Two boundaries on what that buys. The act claim is attribution, not authority. Blake and Jijie are right that sub does not show coverage, and act does not either; it shows who did what on whose behalf, which is the input Section 11's chain reconstruction needs. And it carries none of the standing or freshness Girish separates out. Those stay lookups beside the chain, failing the way a timeout fails, exactly as he and Jijie describe.
>
> Badal, the example remains worth having, and the draft already contains every link your chain needs. 10.4.3 covers an agent invoked by another agent, 10.5 carries context down an internal call chain, 10.8 does the exchange at the tool boundary, and 10.6 handles the hop that crosses a trust domain. What the example will expose is that no text says how these compose, which is the gap I raised during the adoption call (https://mailarchive.ietf.org/arch/msg/wimse/eS929Q98Dk3JFs2eqjOboQ7_dYY/). The document should state the property: each hop re-verified, authority never widening, with Jijie's split between per-hop containment and order-independent intersection, sub preserved and act accurate at every hop, and the chain reconstructable for Section 11. The mechanism, 8693 act plus whatever decision and record shape the verifier-side drafts settle on, belongs in the example and in companion work. That split is the pattern Sections 5 and 8 already use, and it lets the proposals in this thread compete on merit instead of being welded in.
>
> I will review text when you draft it.
>
> Kieran Sweeney

## Reply draft v2: fine-grained authz wedge

Reply-to: https://mailarchive.ietf.org/arch/msg/oauth/RXmGP0IAbrj2NW5bqAxr-B54uX8/ (Ron Bartor, Oct 3)

> Ron, your correction sharpens the problem into one sentence: the record exists per PDP, and the join sits where no party stands. I read that as a symptom rather than the gap. The Mission lives at the AS, History lives at each PDP, and section 16 puts cross-PDP composition out of scope because no single party holds both the goal and all the typed records. Every fix proposed so far picks a residence for the semantics: Yaron publishes them from the RS, your issue asks the mission layer to host the join, Karl keeps the Authority Set at the AS. Each residence reproduces the problem one layer out, at the gateway that sees part of the traffic, at a second AS, at the auditor after the fact.
>
> The thing to constrain is the goal artifact, not where it lives. Make the Mission a portable, self-contained artifact: the committed Authority Set, the intent hash, and the typed vocabulary the records are written in, signed and presentable. Then any party holding the artifact and the records can compute your join, the inventory PDP, the payments PDP, a gateway, or an auditor holding neither service. Your own tie to Yaron points here: if the RS metadata fields and the post-execution record fields are the same declaration, the artifact binding them is the only missing piece, and nothing about it requires the AS to be present at evaluation time. That is the issue I would file against section 16. Not "compose the PDPs", which needs a protocol between every pair of parties, but "make the Mission evaluable by any party", which needs only the artifact.
>
> Kieran

## Reply draft, unchanged: Delegated SD-JWT support

Reply-to: https://mailarchive.ietf.org/arch/msg/oauth/olDRhLWftgA-H8bgyt0ueKAWN4g/ (full text in the Oct 1 report; core: support adoption, delegation lives in the credential, fix the Section 6 verification-step formatting since Section 8.1 makes chain binding load-bearing, and add the RFC 8693 act-chain relationship note.)

## Interim pack: draft-carleton-workload-authz-grant-01

Anthropic surface, squarely: Paul Carleton (Anthropic) is editor, with Steele (OpenAI), Parecki (Okta), Schwenkschuster (Defakto), Campbell (Ping). It solves agent provisioning, not delegation: a hosting platform signs an RFC 7523 JWT bearer grant naming one workload via an opaque never-reassigned Agent Identifier; the AS registers the platform once and accepts previously-unseen agents under it; no per-agent client registration, no refresh tokens; permissions are AS-local policy. On-behalf-of is explicitly out of scope, and the abstract says the grant "is intended to compose with delegation mechanisms in which the workload is the actor." That named composition slot is your layer.

BYO check: mostly clean. No mandated broker topology, no delegation welded to a runtime, flexible key distribution. One structural flag: the assertion issuer is by definition the hosting platform, so agent identity issuance is platform-resident and a customer cannot bring their own signer for agents hosted elsewhere. One opportunity: claim vocabularies are per-platform by rule (Section 6.2), so any cross-platform policy or broker layer needs a mapping table, which is the brokering surface Cred occupies. Open issues in the draft itself: bearer assertion with proof of possession unresolved (Section 8), jti replay, JWT typ.

Spoken talking points:

"WAG solves the provisioning problem, not the delegation problem, and it is careful to say so: workloads act on their own behalf, and composition with delegation is explicitly left to mechanisms where the workload is the actor. That slot is where the credential delegation work sits, and the fit is clean: WAG mints an opaque, never-reassigned agent identifier, which is exactly what an RFC 8693 act claim wants to name, so WAG establishes who the actor is and the delegation layer records on whose behalf it acts. On topology the draft stays bring-your-own almost everywhere: registration, permissions, and claim semantics are all AS-local, so nothing mandates a broker or welds delegation to a vendor runtime. The one structural tie is that the assertion issuer is by definition the hosting platform, so agent identity issuance is platform-resident. Section 6.1 scopes the agent identifier strictly to the platform registration, which is right for issuance but means the identifier is not, as written, something a downstream verifier in a delegation chain can resolve on its own. And since the grant is a bearer assertion with proof of possession still open, any delegation chain citing this actor identity today inherits only assertion-lifetime and jti protections at its root."

Question for the author: "The abstract says the grant is intended to compose with delegation mechanisms in which the workload is the actor. Is the Agent Identifier meant to be citable outside the platform-AS pair that minted it, for instance as the actor in an RFC 8693 act claim presented to a different verifier, and if so, what carries the platform context that Section 6.1 says the sub is only meaningful within?"

## Open loops from Oct 1

The sdk docs patch (wimse-sweep-2026-10-01.patch: AIMS title fix, composition-gap tracking item, test-vector instance_bound note) was delivered but push access was denied that run, so it is unapplied unless you applied it. The one-shot prompt below re-checks and applies or re-delivers.

## Source notes

All claims from pages fetched Oct 6. The oauth archive October index ended at Oct 4 at fetch time, so "no chair conclusion" means none archived yet; a conclusion sent but not yet archived cannot be ruled out. interim-2026-wimse-02 agenda confirmed via datatracker API after the .ics returned no event data. No other fetch failures.
