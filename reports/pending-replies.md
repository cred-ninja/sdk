# Pending replies register

Canonical list of (a) reply drafts written for Kieran but not yet posted and (b) list messages addressed to Kieran that he has not answered. The Thursday sweep (PHASE 0) reads this first and updates Status with archive evidence. Never delete a row; mark it sent, superseded, or closed. Dates are UTC. Rebuilt 2026-10-06 from a full scan of wimse, oauth and agentproto archives (Aug 1 to Oct 6).

## A. Drafted, unsent

| # | Thread | Answers (archive URL) | Draft location | Deadline / shelf life | Status |
|---|--------|-----------------------|----------------|-----------------------|--------|
| A1 | OAuth: Call for adoption - Delegated SD-JWT | https://mailarchive.ietf.org/arch/msg/oauth/olDRhLWftgA-H8bgyt0ueKAWN4g/ | send-pack-2026-10-06.md reply 1 | CfA closes 2026-10-12 | unsent; first Gmail draft vanished without a sent copy, recreated 2026-10-06 17:35 UTC |
| A2 | WIMSE: AIMS-00 multi-hop delegation context | https://mailarchive.ietf.org/arch/msg/wimse/EVV1lJ_MaUbCNny_Qb1yXM6nVA0/ | send-pack-2026-10-06.md reply 2 | before Badal posts the example | SENT 2026-10-06 17:13 UTC https://mailarchive.ietf.org/arch/msg/wimse/tCfvG6GJXTGf94hmyhq0QyobnWI/ |
| A3 | OAuth: fine-grained authorization (IETF 126 follow-up) | https://mailarchive.ietf.org/arch/msg/oauth/RXmGP0IAbrj2NW5bqAxr-B54uX8/ | send-pack-2026-10-06.md reply 3 | before design team forms / Mission -01 | SENT 2026-10-06 17:12 UTC https://mailarchive.ietf.org/arch/msg/oauth/mVbtryEEfiIad1pOOOY3zHA0Kwk/ |
| A4 | WIMSE: draft-asor -01 Section 4.1 scope ABNF (provider-native scopes rejected) | root https://mailarchive.ietf.org/arch/msg/wimse/6IN8EiDzXeLI3xJ0JHxVIjcvPuc/ , latest Asor https://mailarchive.ietf.org/arch/msg/wimse/9BJwF-yNuE4-BCIhu-aJjbEMz9A/ | sdk docs/design/scope-abnf-interop.md; Gmail draft 2026-10-06 replying to Asor's Oct 4 message, cc Asor | Asor folds list input by 2026-10-09, aims to post -02 by 2026-10-19, hard stop 2026-11-02 | SENT 2026-10-06 17:12 UTC https://mailarchive.ietf.org/arch/msg/wimse/YGSUGKbkSqaG6vppovX8iiAo8sE/ ; watch for Asor's answer and the Oct 12 negative-vector offer |
| A5 | WIMSE: draft-asor online half (atomic check-and-debit, sub/client_id alignment) | https://mailarchive.ietf.org/arch/msg/wimse/jJr81ZlNkuVZij6SN-x_ymxTtE8/ (Asor Sep 18); Asor's open question Sep 17 https://mailarchive.ietf.org/arch/msg/wimse/4rWNZBqMESZdsnjlJRRJHm53_nQ/ | Cred Ninja/Patches/wimse-sweep-2026-09-24.md reply draft 2 | same window as A4 | unsent since 2026-09-24 |
| A6 | OAuth: HTTPSig CfA (JWK/pub alignment) | CfA root https://mailarchive.ietf.org/arch/msg/oauth/rFLBcBk2sdJZgL8ff_67dcSmnMo/ | Cred Ninja/Patches/wimse-sweep-2026-09-24.md reply draft 1 | CfA closed 2026-10-05; PARKED until chair announcement | parked |
| A7 | Email to Rafael Asor: 20-vector conformance results cover note | off-list | Desktop/Cred/asor-send-package/cover-note.md (Sep 3) | Asor replied privately Sep 6 and Sep 15 (both unread until Oct 6) asking for the SDK commit behind the 17/20 so Iman Schrock can cite it; answer is 4a24376; PR cred-ninja/protocol#6 opened Oct 6 with pinned commits and retained JSON | SENT privately 2026-10-06 17:12 UTC; await Asor's README update and Iman's citation |

## B. Addressed to Kieran, unanswered

| # | From, date | Thread | Message | What is owed | Status |
|---|-----------|--------|---------|--------------|--------|
| B1 | Yaron Sheffer, 2026-09-04 | WIMSE WGLC http-signature | https://mailarchive.ietf.org/arch/msg/wimse/Oe2KhBxW7Ln0Hg2u3INeCeUz3D4/ | confirm draft-ietf-wimse-http-signature-07 (posted 2026-09-20; doc shepherd Justin Richer assigned 2026-10-05, follow-up underway; changelog cites #297, #301, #305) resolves @request-target, @authority, response-signing scope, wimse-req-nonce; residual: 3.2 keeps a derived wimse-aud default with no comparison rule | Gmail draft r7051587365452870599 (2026-10-06), unsent |
| B2 | Yaron Zehavi, 2026-09-03 | OAuth: may_act with RFC 8707 resource indicators | https://mailarchive.ietf.org/arch/msg/oauth/G7uL5zBgdT9f3TIG5SpMu5uRjU4/ | view on PRM URI as a party identifier under RFC 8693 4.4 and the token_exchange_clients metadata idea; draft says: CIMD client_id in may_act as primary form, PRM pointer as compatibility form, signed_metadata + cache lifetime, exact client_namespace match or deny | Gmail draft r7457248274561364256 (2026-10-06), unsent |
| B3 | Yaron Zehavi, 2026-09-10 | OAuth: Shared Consent in Brokered OAuth | https://mailarchive.ietf.org/arch/msg/oauth/cOKh0twQrJda9pFVJfEMtIIRbI0/ | acknowledge -01 section 11.2 (three truncation cases) and 8.8; one gap: per-node `resource` has no subset rule between adjacent nodes | Gmail draft r7330369075575596282 (2026-10-06), unsent |
| B4 | Altru (Valentyn), 2026-09-13 | OAuth: execution-time state binding | https://mailarchive.ietf.org/arch/msg/oauth/VsNpyqA-O1TW03oJRhrgLnXrvVI/ | none. Thread closed itself on 2026-09-14: Valentyn conceded to Warren Parad that the OAuth part is answered ("closes the OAuth part of the question for me"), and Kieran's Sep 14 reply to Warren agreeing the thread had run its course went to Warren only, not to the list (Gmail message 1a09fd3b1548c43f). The archive therefore shows Kieran's last list post as the Sep 13 request for a concrete case. A reply three weeks after the concession reopens a thread the list treated as done | closed, not owed |
| B5 | morganLR, 2026-08-01 | OAuth: ID-JAG topology (R7 of draft-reece) | https://mailarchive.ietf.org/arch/msg/oauth/fwfVf74iHcE3PoQKO6alpwvCuSc/ | minor; revocation window across hops | open, low |
| B6 | leleueri, 2026-09-13 | GitHub oauth-wg/oauth-identity-assertion-authz-grant issue #114 | https://github.com/oauth-wg/oauth-identity-assertion-authz-grant/issues/114 | check whether a reply is owed | unverified |

## C. Misfiled or never registered

| # | Item | Detail | Status |
|---|------|--------|--------|
| C1 | mTLS WGLC review in wrong thread | Kieran's 2026-08-12 review of draft-ietf-wimse-mutual-tls-02 landed in the Workload Identifier WGLC thread (https://mailarchive.ietf.org/arch/msg/wimse/JQN8BoIc8GXSAG3f9Iyet-ScwTA/); the mTLS WGLC thread (https://mailarchive.ietf.org/arch/msg/wimse/oP9hfPl5b8P5G8s8IQwha6u6Nb8/) has no entry from him; channel-binding text offer never taken up | open |
| C2 | draft-sweeney never introduced on wimse | No announcement post; only Asor's two references (Sep 5, Sep 17). -00 expires 2027-01-29 | open, pair with -01 submission |
