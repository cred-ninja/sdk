# Cred + VestAuth Interop

This example shows the intended layering:

- Cred handles credential delegation and policy.
- Cred can now speak Web Bot Auth directly through its own directory and MCP signer path.
- VestAuth remains a compatible partner path if you want a managed signer workflow on top.

## Model

```text
VestAuth or Cred-native identity -> Web Bot Auth signed HTTP request
Cred delegation -> short-lived OAuth access token
Cloudflare -> verifies agent transport identity
Origin API -> receives both signed-agent identity and delegated OAuth access
```

## Option 1: Cred-Native Web Bot Auth

Use Cred's own directory and native MCP signer:

1. Start `@credninja/server`.
2. Register a Web Bot Auth key through `POST /api/v1/web-bot-auth/keys`.
3. Point your agent identity at:

```text
https://your-cred-host/.well-known/http-message-signatures-directory
```

4. Configure `@credninja/mcp` with:

```bash
CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX=<32-byte-ed25519-private-key-hex>
CRED_WEB_BOT_AUTH_SIGNATURE_AGENT=https://your-cred-host/.well-known/http-message-signatures-directory
```

5. Use `cred_delegate` and `cred_use` as usual. Outbound requests from `cred_use` will include:

- `Signature`
- `Signature-Input`
- `Signature-Agent`

Reference file:

- `examples/vestauth-interop/cred-native-web-bot-auth.ts`

## Option 2: Cred Delegation + VestAuth Signing

If you prefer VestAuth-managed signing, keep Cred as the delegation layer and let VestAuth handle signed transport:

1. Obtain a delegated token from Cred.
2. Sign or send the HTTP request using VestAuth.

Reference file:

- `examples/vestauth-interop/cred-with-vestauth.ts`

This example shells out to the verified VestAuth CLI flow:

```bash
vestauth agent curl https://www.googleapis.com/calendar/v3/calendars/primary/events \
  -H "Authorization: Bearer <cred-delegated-access-token>"
```

In this mode:

- VestAuth answers "who signed the request?"
- Cred answers "which user-delegated credential was the agent allowed to use?"

## When To Use Which

Use Cred-native Web Bot Auth when:

- you want one stack to host the directory and sign MCP outbound requests
- you want Cred-controlled policy and audit metadata for signed-agent identity

Use Cred + VestAuth when:

- you already standardized on VestAuth-managed agent identities
- you want a managed signing layer but still need Cred's delegation and guardrails

These are compatible paths, not competing ones.
