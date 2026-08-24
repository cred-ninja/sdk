# Putting a delegation boundary in front of an MCP that has none

A worked example: using Cred to make the unauthenticated x64dbg MCP server safe
enough to hand to a local agent, without touching the plugin.

## The problem

[`duty1g/x64dbg-mcp-server`](https://github.com/duty1g/x64dbg-mcp-server) exposes
the x64dbg debugger over HTTP as an MCP server. 71 tools. It can read and write
any byte of a debugged process, set registers, assemble, allocate memory, attach
to processes, dump memory to disk, and run arbitrary debugger commands. There is
no authentication, no authorization, no scoping, and no audit trail.

That is an enormous, destructive capability surface, and it is exactly what a
security engineer wants for real reverse-engineering work. The trouble starts
when you point an agent at it. The expected setup runs the agent, a local model,
and the MCP on one machine. Now any tool call, from anything on that host that can
reach the socket, inherits the full debugger. `WriteMemToAddress`, `DumpMemory`,
`ExecuteDebuggerCommand`. Silently. A prompt injection, a confused agent, or local
malware all cash out the same way.

You do not fix that by trusting the model. You fix it by putting an authorization
boundary in front of the tool.

## The idea

Delegation, not exposure. The agent should present a scoped, delegated,
auditable credential and receive exactly the capability it was granted, instead
of inheriting ambient authority over the whole tool surface. This is the core
claim of the WIMSE credential-delegation draft, and it is what Cred does.

We built it as a reverse proxy that sits in front of the plugin's HTTP interface.
The MCP client talks to the proxy. The proxy validates the credential and either
forwards the JSON-RPC call upstream or rejects it. Zero changes to the Zig plugin.
No fork. It works against a tool whose author never cooperated.

## What the boundary enforces

Every request passes five checks before anything reaches x64dbg.

1. **Delegated token.** A Cred delegation receipt: an Ed25519 JWS carrying the
   granted scopes, the agent subject, the service, and an expiry. Verified with
   Cred's own verification path.

2. **Mandatory proof-of-possession.** Holding the receipt is not enough. Each
   request carries a short-lived proof signed by the subject's private key,
   bound to this method, path, body, and receipt, with a single-use nonce. The
   verifying key comes from the receipt's subject, not the proof. A receipt
   lifted from process memory is inert without the key, and a captured proof
   cannot be replayed. This matters precisely because the attacker is local.

3. **Per-tool scope.** The proxy parses the JSON-RPC body, reads the tool name,
   resolves the required scope from a standalone, reviewable scope map, and
   checks it against the granted scopes. A read-only analyst is provably unable
   to call `WriteMemToAddress`. Deny-by-default: an unmapped tool fails closed.

4. **Argument-level policy.** Scope decides which tools; argument policy decides
   how much within a tool. A read scope cannot pull more than 4 KB per call. An
   exfil scope can only dump under a sandbox prefix, with path traversal
   rejected. This closes the "a read can read anything, a dump can land anywhere"
   gap that tool-name scoping alone leaves open.

5. **Structured audit.** One JSON line per decision: timestamp, subject, tool,
   required scope, allow or deny, deciding policy, upstream status. This is the
   capability the bare plugin has zero of, and it is half the value for a
   security team.

`ExecuteDebuggerCommand` is the honest hard part. It takes an arbitrary x64dbg
command string and can reach the capability of most of the other 70 tools, so any
scope mapping is a bypass. We deny it outright rather than ship an allowlist over
a command grammar we cannot model from outside the plugin. The reasoning is
written down, not hidden.

## What it is, and what it is not

It is a capability-reduction and accountability layer. It converts an
all-or-nothing, unauthenticated, unaudited surface into a delegated, scope- and
argument-limited, proof-bound, audited one. A read-only agent cannot patch memory
or bulk-exfiltrate, a stolen credential is useless, and every attempt is logged.

It is not a sandbox. It controls who asks, not what x64dbg can do. If a local
process can reach the plugin socket directly, it bypasses the proxy. So deploy it
as defense-in-depth: bind the plugin to loopback, add a host firewall rule, and
run the debugger in a disposable VM. Cred is the least-privilege and
accountability layer on top of that isolation, not a replacement for it.

That honesty is the point. The design is credible because it refuses to overclaim
exactly where a weaker one would: the catch-all is denied, the network boundary
is named as load-bearing, and the residual risks are written down.

## Try it

The example ships with a self-contained demo that runs in a few seconds against a
mock upstream (the real plugin is Windows-only), asserting allow, scope denial,
catch-all denial, oversized-read denial, path-traversal denial, missing-proof
denial, stolen-receipt denial, replay denial, and stream expiry, then printing
the audit log.

Code, threat model, ADRs, and demo: `examples/x64dbg-delegation-proxy/` in
[cred-ninja/sdk](https://github.com/cred-ninja/sdk). More on Cred at
[cred.ninja](https://cred.ninja).

---

## X thread (ready to post)

> Fill in your handle/links; the repo link points at the example directory.

**1/**
x64dbg has an MCP server now. It exposes the debugger over HTTP: 71 tools, read
and write of any process's memory, arbitrary debugger commands. No auth, no
scoping, no audit. Point a local model at it and the agent inherits the whole
debugger.

**2/**
That's fine until it isn't. The agent, the model, and the MCP all run on one box.
Any tool call, from anything that reaches the socket, gets full debugger
authority. WriteMemToAddress, DumpMemory, ExecuteDebuggerCommand. Silently.

**3/**
You don't fix that by trusting the model. You put a delegation boundary in front
of the tool. The agent presents a scoped, delegated credential and gets exactly
what it was granted. Every call is logged.

**4/**
Built it with Cred as a reverse proxy in front of x64dbg-mcp-server. Zero changes
to the plugin. A read-only analyst agent provably cannot patch memory. The
refusal is a legible error. The attempt is in the audit log.

**5/**
Five checks before anything reaches x64dbg:
- delegated receipt
- mandatory proof-of-possession (stolen credential is inert, no replay)
- per-tool scope (read vs write vs exfil, deny-by-default)
- argument policy (a read can't pull >4KB; a dump is confined to a sandbox dir)
- structured audit on every decision

**6/**
ExecuteDebuggerCommand is the honest hard part: an arbitrary-command catch-all
that defeats any scope map. We deny it outright instead of pretending an
allowlist over x64dbg's command grammar is safe. Documented, not hidden.

**7/**
Honest about limits: this is a confused-deputy mitigation, not a sandbox. It
controls who asks, not what x64dbg can do. Bind the plugin to loopback + host
firewall, run it in a disposable VM. Cred is the least-privilege + accountability
layer on top.

**8/**
It's a worked example for the WIMSE credential-delegation draft: an agent talking
to a tool should present a scoped, delegated, auditable credential, not inherit
ambient authority. Code + threat model + demo:
github.com/cred-ninja/sdk (examples/x64dbg-delegation-proxy)
