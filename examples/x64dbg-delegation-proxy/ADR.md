# ADRs - x64dbg delegation proxy

These decisions had real alternatives and shape the security of the proxy. They
are recorded here.

---

## ADR-0001: `ExecuteDebuggerCommand` is denied outright

**Status:** Accepted.

**Context.**
`ExecuteDebuggerCommand` takes an arbitrary x64dbg command string. The x64dbg
command processor can read and write memory (`mov`, `d`, `e`), set registers,
assemble, set breakpoints, allocate memory, run scripts, and drive the debug
session. A single tool therefore reaches the capability of most of the other 70
tools. If it is mapped to any single scope, that scope silently becomes every
scope: a caller holding `x64dbg:read` could patch memory by sending
`ExecuteDebuggerCommand("e <addr> 90")`. The scope model would be defeated.

The requirement offered two options: deny outright, or gate it behind a
command-string allowlist checked before forwarding.

**Why an allowlist cannot be argued safe here.**
An allowlist is only as strong as the parser that decides what the string does,
and that parser would have to model x64dbg's command language from outside the
plugin. That language is adversarial to allowlisting:

- Commands can be chained and sequenced (separators, script blocks), so a check
  on the leading token does not bound the rest.
- Commands have many aliases and short forms (`d`/`dump`, `e`/`edit`, ...), so a
  name allowlist must enumerate every alias or be bypassed by an unlisted one.
- Command arguments are themselves expressions evaluated by x64dbg's expression
  engine, which can dereference memory and, depending on build, produce side
  effects. A "read-only looking" command can carry a writing expression.
- Script and control-flow commands can execute further commands that the outer
  string never named.

We do not control the plugin and cannot enumerate or version-pin its grammar.
Any allowlist we ship would be a best-effort denylist-in-disguise, and the
failure mode is silent privilege escalation. That is exactly the outcome the
requirement warns against.

**Decision.**
Deny `ExecuteDebuggerCommand` outright. In `config/scope-map.json` it carries
`{ "deny": true }`. The proxy's `tool-disposition` policy denies it before any
scope check, so it is refused for every credential including one holding all
scopes. There is no configuration that forwards it.

**Consequences.**
- The scope model holds: no tool can smuggle capability past its scope.
- An operator who genuinely needs raw command access cannot get it through this
  proxy. That is intentional. The right way to add a narrow command capability
  is a new, specific MCP tool upstream with its own scope - not a hole in the
  proxy. We do not modify the upstream plugin (non-goal), so that path is out of
  scope for this example.
- `EvalExpression` is the same class of risk one level down: the expression
  engine is narrower than the command processor but still not provably
  side-effect-free from outside. It is mapped to `x64dbg:read` for analyst
  usefulness and flagged in `config/scope-map.json` and the README as a
  documented residual. An operator wanting a hard boundary changes its entry to
  `{ "deny": true }` - it is config, not code.

---

## ADR-0002: an SSE stream is terminated when the token that opened it expires

**Status:** Accepted.

**Context.**
The SSE transport (`GET /sse`) holds a long-lived server-to-client stream. A
delegated credential is short-lived by design. The stream can therefore outlive
the token that opened it. The requirement: pick a behavior for that case and
justify it.

Two candidate behaviors:

1. **Terminate** the stream at token expiry.
2. **Ride to completion** - let a stream, once opened with a valid token, run
   until the client or server closes it.

A key fact narrows the risk either way: in this transport the SSE stream is the
server-to-client *response/notification* channel. New privileged operations are
client-to-server `tools/call` messages sent as POSTs, and the proxy verifies the
credential and re-checks scope on *every* POST independently. So even under
"ride", an expired token cannot authorize a new tool call - the POST carrying it
is rejected. The choice is about the lifecycle of the stream itself, not about
letting expired tokens execute tools.

**Decision.**
Terminate. When a stream is opened, the proxy schedules closure at the receipt's
`exp`. At that time it emits a final JSON-RPC error message on the stream
(`token_expired`), ends the response, and tears down the upstream connection.
The audit trail records the termination (`sse_terminated_token_expired`).
Behavior is configurable via `X64DBG_SSE_ON_EXPIRY=terminate|ride`; the default
is `terminate`.

Termination fires at `exp` precisely, using the proxy's own clock. The
60-second clock-skew grace applied when *validating* a presented token is a
tolerance for other parties' clocks whose accuracy we cannot control; it does
not apply to a timer the proxy runs against its own clock on a stream it already
holds.

**Rationale.**
- A delegated credential's value is bounded authority in *time* as well as
  scope. A stream that a now-expired credential keeps alive indefinitely quietly
  removes the time bound and leaves an authenticated channel with no live
  credential behind it.
- It removes a resource-leak / zombie-session foothold: opening a stream just
  before expiry cannot yield an indefinitely open authenticated channel.
- It is the behavior that matches how an operator reads "the token expired":
  access, including the open stream, stops.
- The cost is low. A client whose work outlives its credential must obtain a
  fresh delegation and reconnect - the same thing it must already do to send any
  further `tools/call`.

**Consequences.**
- Long analysis sessions must use a credential whose TTL covers the work, or
  reconnect on expiry. This is a deliberate, visible constraint, not a silent one.
- `ride` remains available for operators who want stream continuity and accept
  that the stream may outlive the credential (still safe for tool calls, which
  are re-checked per POST).

---

## ADR-0003: argument-level policy, in addition to tool-name scope

**Status:** Accepted.

**Context.**
Tool-name scope answers "which tools may this credential call". It does not
answer "how much may it do within a granted tool". A credential with
`x64dbg:read` can call `ReadMemory` on any address for any size; a credential
with `x64dbg:exfil` can `DumpMemory` to any path on disk. Scope alone leaves the
*extent* of a granted capability unbounded, which for a debugger is most of the
risk (bulk memory scraping, writing a dump to a world-readable location).

**Decision.**
Add an argument-level policy layer, declared per tool in the scope map as an
optional `args` object, evaluated as a third guard policy that runs only after
the scope check passes. Matchers: `required`, `enum`, `max`/`min` (numeric,
accepts `0x`-hex), `maxLength`, `prefixOneOf`, `pattern`, `denyPattern`.
Evaluation is fail-closed: an argument that cannot be evaluated against its
declared matcher is a violation, and the denial names the specific argument.

The shipped map uses this to cap `ReadMemory.size` at 4096 bytes per call and to
confine `DumpMemory`/`DumpModule.path` to a sandbox prefix while rejecting
traversal (`..`). These are examples, not a complete policy; the point is that
extent is now expressible and reviewable as data.

**Why this altitude.**
The constraints live in the same reviewable artifact as the scope map, so an
operator reads one file to understand both which tools and how much. Argument
policy runs after scope so it only ever sees calls the scope already permits,
and it reuses the same guard chain, so every argument denial produces the same
structured audit line as a scope denial.

**Consequences.**
- Extent within a scope is now bounded per operator policy. A read credential
  can still be prevented from pulling megabytes per call; an exfil credential can
  be pinned to a quarantine directory.
- The matchers are general but not exhaustive. Address-range allowlisting for
  `ReadMemory.address` is expressible via `pattern` today but a first-class
  range/CIDR matcher would be a natural extension.
- Argument policy is only as good as the operator's declarations; the shipped
  values are a sane default, not a guarantee.

---

## ADR-0004: proof-of-possession is mandatory

**Status:** Accepted.

**Context.**
A delegation receipt is a signed statement that a subject (an agent did:key) was
granted some scopes. If the proxy accepts the receipt on presentation alone
(bearer), then a receipt captured from logs, memory, a proxy, or a compromised
process grants its bearer the full scope of that receipt until it expires. In the
real deployment the agent, the local model, and the unauthenticated MCP all run
on one machine, so a receipt in process memory is squarely in reach of local
malware. Bearer is not good enough there.

**Decision.**
Require proof-of-possession on every credentialed request, with no bearer
fallback. The receipt binds a subject did:key (an Ed25519 public key). Each
request must also carry a PoP proof (`X64dbg-PoP` header): a short-lived compact
JWS, signed by the subject's *private* key, binding this request. The proof's
payload carries `htm` (method), `htu` (path), `iat` (freshness), `jti`
(single-use nonce), `ath` (hash of this receipt), and `bh` (hash of the body).
The verifying key is taken from the receipt's verified subject, never from the
proof, so the proof cannot assert its own identity. This is DPoP (RFC 9449) in
spirit, with the key pinned by the receipt rather than presented in the proof.

**What each binding buys.**
- Signature over the subject key: possession, so a stolen receipt without the key
  is inert.
- `ath`: ties the proof to one receipt, so a proof cannot be moved to another.
- `htm`/`htu`/`bh`: ties the proof to one request, so it cannot authorize a
  different call.
- `iat` window + `jti` replay cache: a captured proof is useless outside a narrow
  window and cannot be replayed even once.

**Consequences.**
- Clients must hold the subject private key and sign every request. This is the
  standard cost of PoP and is what makes credential theft ineffective.
- The demo shows all three failure modes refused: a receipt with no proof, a
  stolen receipt signed with the wrong key, and a replayed proof.
- The replay cache is in-process here; a multi-instance deployment needs a shared
  nonce store. Path binding (`htu`) covers the path, not the host; host binding
  belongs in the receipt `aud` and is left as a hardening.
- `X64DBG_POP_WINDOW_SECONDS` tunes the freshness window; there is no switch to
  disable PoP.
