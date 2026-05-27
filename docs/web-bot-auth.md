# Web Bot Auth

Web Bot Auth is Cred's transport identity layer for signed agent requests.

Use Web Bot Auth for:

- who sent this request
- whether the sender controls the signing key it claims to use
- publishing and verifying agent identity material through a signed directory

Use Cred delegation for:

- what user-delegated credential the agent is allowed to use
- whether consent exists
- whether Guard policies allow issuance

These are complementary layers.

## What Cred Supports

### `@credninja/server`

- hosts `/.well-known/http-message-signatures-directory`
- can verify inbound signed-agent requests
- can require replay defense with nonces
- can restrict trusted remote `Signature-Agent` origins

### `@credninja/mcp`

- can add native Web Bot Auth headers on outbound local `cred_use` requests and remote broker requests to Cred
- is the first end-to-end execution path where Cred both delegates credentials and signs the transport request

### `@credninja/sdk`

- can manage Web Bot Auth keys
- can create signed requests outside MCP

## Recommended Reading

- [Server docs](../packages/server/README.md)
- [MCP docs](../packages/mcp/README.md)
- [Cloudflare submission checklist](./cloudflare-submission-checklist.md)
- [TOFU proof of possession](./tofu-proof-of-possession.md)

## Operator Notes

- Web Bot Auth is optional by default.
- Use `WEB_BOT_AUTH_MODE=require` when signed ingress is mandatory.
- Use a shared nonce store if multiple Cred instances must reject the same replay.
- Keep the directory on a stable HTTPS origin.

## Contributor Notes

Implementation details are covered by the server, MCP, SDK, and TOFU tests in
this repository. Keep public Web Bot Auth documentation limited to shipped
operator behavior and checked-in examples.
