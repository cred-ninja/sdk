# ADRs - x64dbg delegation proxy

Two decisions had real alternatives and shape the security of the proxy. They
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
