# Cloudflare Submission Checklist

Use this checklist before submitting a Cred-backed signed-agent setup or key directory to Cloudflare.

## Required Runtime State

- Production directory URL is stable and HTTPS.
- `/.well-known/http-message-signatures-directory` returns `200`.
- Directory response has content type `application/http-message-signatures-directory+json`.
- Directory response includes valid `Signature` and `Signature-Input` headers with `tag="http-message-signatures-directory"`.
- Published keys use Ed25519 OKP JWKs with stable `kid` values.

## Ingress / Request Behavior

- Intended signed execution path is known.
  - Native Cred path: MCP `cred_use` or SDK signer helper.
  - Partner path: external signer such as VestAuth paired with Cred delegation.
- Requests include:
  - `Signature`
  - `Signature-Input`
  - `Signature-Agent`
- `Signature-Input` includes:
  - `@authority`
  - `signature-agent`
  - `keyid`
  - `created`
  - `expires`
  - `nonce`
  - `tag="web-bot-auth"`

## Rotation Readiness

- Rotation process is documented for operators.
- Directory publishes both current and previous keys during the grace window.
- Old key removal timing is understood and tested.
- Audit trail records `keyid`, `Signature-Agent`, and identity source for key events and signed requests.

## Replay Defense

- `WEB_BOT_AUTH_MODE=require` is enabled in production if signed ingress is mandatory.
- Nonce replay defense is enabled.
- If multiple Cred instances can receive the same traffic:
  - `WEB_BOT_AUTH_NONCE_STORE=sqlite`
  - `WEB_BOT_AUTH_NONCE_PATH` points to a path shared by those instances

## Example Submission Values

- Directory URL:
  - `https://cred.example.com/.well-known/http-message-signatures-directory`
- Key management API:
  - `POST /api/v1/web-bot-auth/keys`
  - `POST /api/v1/web-bot-auth/keys/:agentId/rotate`
- Signed ingress mode:
  - `WEB_BOT_AUTH_MODE=require`

## Final Validation

- Run the package test suites for `tofu`, `sdk`, `mcp`, and `server`.
- Run the gated live directory smoke check against the production base URL:
  - `RUN_WEB_BOT_AUTH_LIVE_SMOKE=1`
  - `WEB_BOT_AUTH_LIVE_BASE_URL=https://cred.example.com`
- Confirm at least one real signed request succeeds against the intended execution path.
- Confirm replay of the same nonce is rejected.
- Confirm remote non-HTTPS `Signature-Agent` URLs are rejected.
- Confirm docs and operator runbooks match the deployed configuration.
