WIMSE interim, 2026-10-07, 17:00-18:00 Europe/Dublin (16:00-17:00 UTC)

Agenda: https://datatracker.ietf.org/meeting/interim-2026-wimse-02/materials/agenda-interim-2026-wimse-02-wimse-01-00
Remote participation: https://meetings.conf.meetecho.com/interim/?session=35929 (chair reminder, Pieter Kasselman, Oct 6: https://mailarchive.ietf.org/arch/msg/wimse/1cPh43cOUrLf1W93wSt1kHTO86s/)
Materials as of Oct 6: chair boilerplate slides only; no presenter slides for the draft yet.

Read draft-carleton-workload-authz-grant-01: https://datatracker.ietf.org/doc/draft-carleton-workload-authz-grant/

Already raised on the WIMSE list against -01, do not re-raise: Girish Konda, Sep 25 and Oct 5, retirement signalling (Section 10 cut in -01, not in Section 8 open issues; filed as repo issue #18) and subject-only relying parties (settled by Section 6.3 named claim plus IDJAG tenant claim). Thread: https://mailarchive.ietf.org/arch/msg/wimse/5TRTIdWgMoU2_lEoVx2VVazeX8k/

Question for the author:

"The abstract says the grant is intended to compose with delegation mechanisms in which the workload is the actor. Is the Agent Identifier meant to be citable outside the platform-AS pair that minted it, for instance as the actor in an RFC 8693 act claim presented to a different verifier, and if so, what carries the platform context that Section 6.1 says the sub is only meaningful within?"

If asked what you would do: RFC 8693 Section 4.1 already allows act to carry iss together with sub to identify an actor, so act.iss holding the Platform issuer plus act.sub holding the Agent Identifier is the smallest answer, and where several Platforms share an issuer the Section 6.3 distinguishing claim rides alongside. The delegation layer records that evidence in its signed receipt; the outer sub stays the delegated principal. WAG Section 6.1 scopes sub and jti to the matched Platform registration, so a bare identifier is never globally resolvable. WAG establishes the actor; user consent, attenuation, and downstream freshness remain delegation-layer duties. WAG is a bearer assertion with proof of possession open (Section 8), so any chain citing a WAG actor inherits only assertion-lifetime and jti protection at its root unless the delegation layer sender-constrains its own tokens.

Spoken talking points are in reports/wimse-sweep-2026-10-06.md, Interim pack section. Prep is not attendance evidence; after the meeting, close follow-ups from the published notes.
