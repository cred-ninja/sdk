# Scoped delegation proxy for x64dbg-mcp-server

A worked example for `draft-sweeney-wimse-credential-delegation`. It puts a
scoped, delegated, audited authorization boundary in front of an MCP server that
has none, without touching that server.

The demonstration target is [`duty1g/x64dbg-mcp-server`](https://github.com/duty1g/x64dbg-mcp-server)
(MIT), a native x64dbg plugin that exposes the debugger over HTTP as an MCP
server: 71 tools, MCP `2024-11-05`, no authentication, no authorization, no
scoping, and no audit trail of any kind. Its destructive tools include
`WriteMemToAddress`, `Assemble`, `SetRegister`, `AllocateMemory`, `AttachProcess`,
`LoadBinary`, `StopDebug`, and `ExecuteDebuggerCommand` (an arbitrary-command
catch-all).

The claim being demonstrated: an agent talking to a tool should present a
**scoped, delegated, auditable credential** rather than inheriting ambient
authority over the whole tool surface. Here, a read-only analyst agent holding
`x64dbg:read` alone is provably unable to patch process memory, and every
attempt is logged.

Zero changes to the Zig plugin. No fork, no patch, no upstream PR. The point is
that this works against a tool whose author never cooperated.

## What it does

The MCP client points at the proxy instead of at the plugin. For every request
the proxy:

1. Verifies the delegated token (a Cred delegation receipt: an Ed25519 JWS
   carrying granted `scopes`, the agent `sub`, `service`, and `exp`), reusing
   `@credninja/sdk`'s `verifyDelegationReceipt`.
2. Verifies a **mandatory proof-of-possession** bound to the receipt's subject
   key and to this exact request (see [Proof of possession](#proof-of-possession-mandatory)).
   A stolen receipt without the subject's key is inert.
3. On `tools/call`, parses the JSON-RPC body, reads `params.name`, resolves the
   required scope from `config/scope-map.json`, and checks it against the token's
   granted scopes, reusing `@credninja/guard`'s `CredGuard` + `scopeFilterPolicy`.
   Then applies **argument-level policy** to bound *how much* the call may do
   (see [Argument-level policy](#argument-level-policy)).
4. Forwards the request upstream, or rejects it with a **JSON-RPC error** (not a
   bare HTTP 403) so MCP clients surface something readable.
5. Emits a structured **audit line** for the decision.

Scope enforcement is **per tool call**, not per connection. One credential can
read across a whole session and never be able to write, and even a read cannot
pull more than its argument policy allows.

```
$ curl ... WriteMemToAddress   (credential holds x64dbg:read)
{"jsonrpc":"2.0","id":2,"error":{"code":-32002,
  "message":"Delegated access denied: tool \"WriteMemToAddress\" requires scope
             \"x64dbg:write\", which this credential was not granted.
             Granted scopes: [x64dbg:read].",
  "data":{"tool":"WriteMemToAddress","requiredScope":"x64dbg:write",
          "grantedScopes":["x64dbg:read"],"policy":"scope-filter",
          "subject":"did:key:zAnalyst"}}}
```

## Threat model: this is a confused deputy

The proxy controls **who asks**. It does not, and cannot, shrink **what x64dbg
can do**.

x64dbg holds full control of the debuggee. The plugin will faithfully execute
any request that reaches it, from anyone, because it has no notion of a caller.
The proxy inserts an authorizer in front of it. But the plugin is still a
listening socket. If a caller can reach that socket directly, it bypasses the
proxy entirely and inherits x64dbg's full authority. That is the classic
[confused deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem): the
plugin is a deputy holding powerful authority, willing to act for whoever asks,
and the proxy only helps if the plugin will *only* take requests from the proxy.

By default the plugin binds `0.0.0.0:9094` (x64) / `0.0.0.0:9095` (x32) - every
interface. The proxy is **advisory only** until the direct path to the plugin is
closed.

### The real deployment: everything is local

The expected setup runs the agent, a local model, and the unauthenticated MCP on
one machine. That changes the dominant threat from "someone on the network" to
"another process on this host". Two consequences shape the design:

- The network boundary is loopback plus a host firewall (below), because there is
  no remote client to serve. This makes the plugin reachable only from the host.
- The attacker who matters is local, so a delegated credential sitting in the
  agent's process memory is within reach. A bearer credential would be enough for
  local malware to lift and replay. That is exactly why **proof-of-possession is
  mandatory** here: the receipt is useless without the subject's private key, and
  a captured proof cannot be replayed. Scope and argument policy then bound what
  even a legitimately-held credential can do.

### Closing the bypass (required for real enforcement)

Two steps, both outside the proxy, make the boundary real:

1. **Bind the plugin to loopback.** In x64dbg's plugin config dialog, set the
   MCP server bind address to `127.0.0.1`. Now only processes on the same host
   can reach it, and the proxy (also local) becomes the reachable front door.

2. **Add a host firewall rule.** Defense in depth, in case the bind setting is
   missed, reverted, or unavailable. On the Windows host running x64dbg, block
   inbound connections to the plugin ports from off-host:

   ```
   netsh advfirewall firewall add rule name="x64dbg-mcp deny inbound" ^
     dir=in action=block protocol=TCP localport=9094-9095 remoteip=any
   ```

   (Loopback traffic is not subject to this rule, so the local proxy still
   reaches the plugin.)

With the plugin on `127.0.0.1` and the proxy the only listener the agent is
given, the delegated credential is on the only path that exists.

**Without both steps, the proxy is advisory only:** an agent that knows the
plugin's address can open its own socket to `127.0.0.1:9094` (or the LAN address,
if bound wide) and call `WriteMemToAddress` with no credential at all. Say this
plainly to anyone deploying it.

If the agent is not on the same host, terminate TLS (and, ideally, mutual TLS or
Web Bot Auth request signing) at the proxy edge and keep the plugin on loopback.
That transport layer is out of scope for this example, which runs everything
locally.

## Honest limits

- **The proxy is who-asks, not what-x64dbg-can-do.** See the threat model. It
  adds an authorization boundary that did not exist; it does not sandbox the
  debugger.
- **Proof-of-possession is mandatory, with residuals.** A stolen receipt is
  inert without the subject's key, and a captured proof cannot be replayed. The
  residuals are honest ones: the replay nonce cache is in-process (a
  multi-instance deployment needs a shared store), and the proof binds the
  request path but not the host (host binding belongs in the receipt `aud`, left
  as a hardening). Optionally pin the subject with `X64DBG_EXPECTED_AGENT_DID`
  as an extra allowlist on top of PoP.
- **Argument policy is operator-declared and general.** It bounds extent within a
  scope (size caps, path prefixes, patterns), but it is only as good as the
  declared constraints, and the matchers are general-purpose. First-class
  address-range/CIDR matching for memory operations is expressible via `pattern`
  today but would be a natural next matcher.
- **`EvalExpression` is a residual catch-all.** x64dbg's expression engine is
  narrower than its command processor but still not provably side-effect-free
  from outside the plugin. It is mapped to `x64dbg:read` for analyst usefulness
  and flagged as a residual in `config/scope-map.json`. Operators wanting a hard
  boundary set its entry to `{ "deny": true }`. See ADR-0001.
- **The proxy trusts the scope map it is given.** The map is the authorization
  artifact; review it as one (`config/scope-map.json`, `config/scope-map.schema.json`).

## Scope model

Five scopes, deny-by-default. Any tool name not in the map is denied
(`unmappedPolicy: deny`), so a tool added by a future plugin version fails closed
rather than sailing through unmapped.

| Scope | Meaning |
|---|---|
| `x64dbg:read` | Observe process/debugger state. Strictly non-mutating. |
| `x64dbg:control` | Drive execution and breakpoints (run, step, pause, breakpoints, thread switch). |
| `x64dbg:write` | Mutate process memory, registers, thread run-state, patches, or the debugger analysis database. |
| `x64dbg:session` | Create/destroy the debug target (load, attach, stop, restart). |
| `x64dbg:exfil` | Write process memory to disk (memory/module dumps). |

Two tools get explicit handling beyond a plain scope:

- **`ExecuteDebuggerCommand` → denied outright.** An arbitrary-command catch-all
  that would defeat the whole scope model. See ADR-0001.
- **`EvalExpression` → `x64dbg:read`, flagged.** Secondary catch-all risk; see
  Honest limits and ADR-0001.

All 71 tools are placed. The map is a standalone, reviewable file:
[`config/scope-map.json`](./config/scope-map.json).

## Argument-level policy

Scope decides *which* tools; argument policy decides *how much* within a granted
tool. Declared per tool in the scope map as an optional `args` object, evaluated
as a third guard policy that runs only after the scope check passes. Fail-closed,
and the denial names the specific argument.

Matchers: `required`, `enum`, `max`/`min` (numeric, accepts `0x`-hex),
`maxLength`, `prefixOneOf`, `pattern`, `denyPattern`. The shipped map, as
examples:

```json
"ReadMemory": { "scope": "x64dbg:read", "args": { "size": { "max": 4096 } } },
"DumpMemory": { "scope": "x64dbg:exfil",
  "args": { "path": { "required": true,
    "prefixOneOf": ["C:/cred-sandbox/", "/var/cred-sandbox/"], "denyPattern": "\\.\\." } } }
```

So a read credential cannot pull more than 4096 bytes per call, and an exfil
credential can only dump under a sandbox prefix, with traversal rejected. See
ADR-0003.

## Proof of possession (mandatory)

Holding a receipt is not enough. Every credentialed request must also carry a PoP
proof in the `X64dbg-PoP` header: a short-lived compact JWS signed by the
subject's did:key **private** key. The proof binds `htm` (method), `htu` (path),
`iat` (freshness), `jti` (single-use nonce), `ath` (hash of this receipt), and
`bh` (hash of the body). The verifying key is taken from the receipt's verified
subject, never from the proof itself.

This is DPoP (RFC 9449) in spirit, with the key pinned by the receipt. The result:
a stolen receipt without the key is inert; a proof cannot be moved to another
receipt or another request; and a captured proof cannot be replayed. There is no
bearer fallback and no switch to disable PoP; `X64DBG_POP_WINDOW_SECONDS` only
tunes the freshness window. See ADR-0004.

## Delegated token

A Cred delegation receipt - Ed25519 JWS, `header.payload.signature`. The payload
carries `sub` (agent DID, the delegated subject), `scopes` (granted), `service`
(must match `X64DBG_SERVICE`, default `x64dbg`), `iat`, and `exp`. The proxy is
configured with the issuer's public key (`X64DBG_ISSUER_PUBLIC_KEY_HEX`,
defaulting to Cred's pinned key) and verifies signature, subject binding, service,
and expiry via `@credninja/sdk` before trusting any claim.

## Audit

One structured JSON line per decision, on stdout (and, if `X64DBG_AUDIT_LOG` is
set, appended to that file). Each line carries at least: timestamp, delegated
subject, tool name, required scope, decision (allow/deny), and upstream status.
The full Cred guard event is embedded under `guard`. This is the capability the
bare plugin has zero of.

```
decision tool                     scope           up   reason
allow    ReadMemory               x64dbg:read     200  All requested scopes are allowed
deny     WriteMemToAddress        x64dbg:write    -    Disallowed scopes requested: x64dbg:write
deny     ExecuteDebuggerCommand   -               -    arbitrary-command catch-all; denied outright (see ADR-0001)
allow    -                        -               200  sse_stream_opened
deny     -                        -               200  sse_terminated_token_expired
```

## SSE token expiry

The SSE transport holds a long-lived stream that can outlive the token that
opened it. This proxy **terminates the stream at the token's `exp`**
(configurable via `X64DBG_SSE_ON_EXPIRY=terminate|ride`, default `terminate`).
Every `tools/call` is a separate POST that is re-verified independently, so an
expired token cannot authorize a new call regardless; terminating the stream
additionally honors the credential's time bound and avoids a zombie
authenticated channel. See ADR-0002.

## Run the demo (under 90 seconds)

Runs entirely in-process against a mock upstream, so it needs no Windows host and
no live x64dbg. It shows allow; deny by scope, catch-all, and **argument policy**
(oversized read, path traversal); **mandatory PoP** refusing a missing proof, a
stolen receipt signed with the wrong key, and a replayed proof; least-privilege
`tools/list`; an unauthenticated rejection; SSE expiry termination; and prints
the resulting audit lines. It asserts every expectation and exits non-zero on
failure.

```bash
# from this directory. Node >= 18. Use npx tsx; do NOT run `npm install` in this
# subdirectory (it is not a workspace member and would reach the monorepo root).
npx tsx demo/demo.ts
```

Expected tail:

```
=== DENY   WriteMemToAddress (read-only credential cannot patch memory) ===
  [PASS] rejected as a JSON-RPC error (not bare 403)
  [PASS] error names the required scope x64dbg:write
...
DEMO PASSED
```

## Run against a live x64dbg

1. In x64dbg, load the MCP plugin and set its bind address to `127.0.0.1` (see
   "Closing the bypass"). Note the port (9094 for x64, 9095 for x32).
2. Point the proxy at it and give it the issuer public key (run from this
   directory, so tsx picks up this example's `tsconfig.json`):

   ```bash
   X64DBG_UPSTREAM_URL=http://127.0.0.1:9094 \
   X64DBG_ISSUER_PUBLIC_KEY_HEX=<cred issuer ed25519 public key hex> \
   X64DBG_LISTEN_PORT=9114 \
   X64DBG_AUDIT_LOG=./audit.log \
   npx tsx src/proxy.ts
   ```

3. Point the MCP client at `http://127.0.0.1:9114` and give the agent a Cred
   delegation receipt scoped to what it should do.

To mint a receipt for local testing (throwaway issuer key):

```bash
SCOPES=x64dbg:read SUBJECT=did:key:zAnalyst npx tsx demo/mint-receipt.ts
```

This prints the issuer public key (feed it to the proxy) and a matching receipt.

### Configuration

| Env var | Default | Meaning |
|---|---|---|
| `X64DBG_UPSTREAM_URL` | `http://127.0.0.1:9094` | The plugin's HTTP base. |
| `X64DBG_LISTEN_HOST` | `127.0.0.1` | Proxy bind host. |
| `X64DBG_LISTEN_PORT` | `9114` | Proxy bind port. |
| `X64DBG_ISSUER_PUBLIC_KEY_HEX` | Cred's pinned key | Ed25519 public key that signs receipts. |
| `X64DBG_SERVICE` | `x64dbg` | Required `service` claim. |
| `X64DBG_SCOPE_MAP` | `config/scope-map.json` | Path to the scope map. |
| `X64DBG_EXPECTED_AGENT_DID` | (unset) | Extra subject allowlist on top of PoP. Unset = any subject that proves possession. |
| `X64DBG_POP_WINDOW_SECONDS` | `30` | PoP freshness window and replay-cache TTL. PoP itself cannot be disabled. |
| `X64DBG_SSE_ON_EXPIRY` | `terminate` | `terminate` or `ride`. |
| `X64DBG_FILTER_TOOLS_LIST` | `true` | Narrow `tools/list` to callable tools. |
| `X64DBG_AUDIT_LOG` | (unset) | Append audit lines to this file. |
| `X64DBG_AUDIT_STDOUT` | `true` | Mirror audit lines to stdout. |

## Decisions

The decisions with real alternatives are recorded in [`ADR.md`](./ADR.md):
`ExecuteDebuggerCommand` disposition (ADR-0001), SSE expiry behavior (ADR-0002),
argument-level policy (ADR-0003), and mandatory proof-of-possession (ADR-0004).

## Deviations from the initial scope-map draft

The starting scope map in the task under-specified the real tool set. Corrections
made while placing all 71 tools:

- **~20 tools were unplaced** and have been added: `GetCurrentAddress`,
  `WaitForPause`, `ListCommandsByCategory`, `SearchForStrings`, `Echo`,
  `GetDumpableRegions`, `GetPatches`, `DetectOEP`, `FollowPointer`, and the full
  breakpoint set (`SetHardwareBreakpoint`, `SetConditionalBreakpoint`,
  `EnableBreakpoint`, `DisableBreakpoint`, `DeleteAllBreakpoints`,
  `ResetHitCount`) beyond the "set/delete/toggle/list" shorthand.
- **`ListBreakpoints` is a read**, not control. Listing breakpoints observes
  state; it is in `x64dbg:read`.
- **`EvalExpression` is a secondary catch-all**, not a plain read. It stays in
  `x64dbg:read` for usefulness but is flagged; see Honest limits and ADR-0001.
- **`ClearEventLog` is anti-forensic** - it destroys the debugger's own event
  log. It is `x64dbg:write`, never a read. Annotation/bookmark writes
  (`CommentOrLabelAtAddress`, `SetBookmark`, `DeleteBookmark`) mutate the
  analysis database and are `x64dbg:write` too, so `read` stays strictly
  non-mutating.
- **`LoadBinary`, `AttachProcess`, and `ExecuteDebuggerCommand` are available
  with no debug session** (they are in the plugin's "always available" set). So
  session-creating tools and the catch-all are reachable before any session
  exists; the proxy gates them regardless of session state.
- **Transport naming.** "Streamable HTTP" is the `2025-03-26` transport name;
  `2024-11-05` defines the HTTP+SSE transport. The proxy handles both a JSON/SSE
  `POST /` and a `GET /sse` stream, so it works either way.

## Reused Cred primitives

Per the "match the existing stack" requirement, this example reuses rather than
reimplements:

- `@credninja/sdk` - `verifyDelegationReceipt` (token verification path),
  `generateAgentIdentity` (agent DID for the demo), `CRED_PUBLIC_KEY_HEX`.
- `@credninja/guard` - `CredGuard` + `scopeFilterPolicy` (the scope check;
  deny-by-default, first-DENY-wins, fail-closed), and `buildAuditEvent` (the
  structured guard event, embedded under `guard` in each audit line). A small
  custom `tool-disposition` policy (a documented guard extension point) handles
  the catch-all/unmapped denials.

The proxy itself is built on `node:http` with no runtime dependencies, matching
Cred's "Node.js built-ins only" posture.

## Non-goals

Not a general-purpose MCP gateway - one target, one proof. No UI. No changes,
fork, or issues against the upstream Zig plugin. Nothing here reverses, unpacks,
or defeats protection on software. This is a defensive exercise against a binary
the author owns: the proxy adds an authorization boundary that did not exist.
