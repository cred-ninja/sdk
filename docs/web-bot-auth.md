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

- can add native Web Bot Auth headers on outbound `cred_use` requests
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

Implementation notes, ADRs, threat modeling, and design docs live under:

- [Internal Web Bot Auth docs](./internal/web-bot-auth/)
