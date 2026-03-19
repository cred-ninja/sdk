# Contributing to cred-ninja/sdk

Cred is an agent credential delegation protocol — it lets AI agents receive and use OAuth tokens on behalf of users without ever seeing raw credentials. This is protocol infrastructure: changes here affect every system that implements the Cred Delegation Protocol, so we hold contributions to a high standard.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Repo Structure](#repo-structure)
- [Running Tests](#running-tests)
- [Adding an OAuth Provider Adapter](#adding-an-oauth-provider-adapter)
- [Security Policy](#security-policy)
- [Protocol Contributions](#protocol-contributions)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
- [Good First Issues](#good-first-issues)

---

## Development Setup

**Requirements:** Node.js 20+, npm 10+

```bash
# Clone the repo
git clone https://github.com/cred-ninja/sdk.git
cd sdk

# Install all workspace dependencies
npm install

# Build all packages
npm run build

# Verify everything works
npm test
```

If you're working on a specific package:

```bash
cd packages/oauth   # or vault, sdk, mcp
npm run build
npm test
```

TypeScript is compiled to `dist/` in each package. Never commit `dist/` — it's gitignored and built in CI.

---

## Repo Structure

```
sdk/
  packages/
    oauth/      @credninja/oauth   — OAuth provider adapters and token exchange logic
    vault/      @credninja/vault   — Encrypted credential storage and retrieval
    sdk/        @credninja/sdk     — Main entry point; composes oauth + vault into the delegation flow
    mcp/        @credninja/mcp     — MCP (Model Context Protocol) transport adapter
  .github/      CI workflows and issue templates
```

**Package responsibilities:**

- **`@credninja/oauth`** — Provider-specific OAuth adapters (GitHub, Google, Slack, Notion, Salesforce, HubSpot), token refresh, and the `OAuthAdapter` interface all providers must implement.
- **`@credninja/vault`** — AES-GCM encrypted vault for storing delegated tokens at rest. Contains `encryption.ts` — see [Security Policy](#security-policy) before touching this.
- **`@credninja/sdk`** — The public-facing SDK. Orchestrates delegation flows: issue credential, store in vault, expose to agent. Most integrators only use this package.
- **`@credninja/mcp`** — Adapter for MCP-compatible runtimes. Wraps SDK calls in the MCP tool/resource model.

---

## Running Tests

Run all tests across the monorepo:

```bash
npm test
```

Run tests for a single package:

```bash
npm test --workspace=packages/oauth
npm test --workspace=packages/vault
npm test --workspace=packages/sdk
npm test --workspace=packages/mcp
```

Run in watch mode during development:

```bash
cd packages/oauth
npx jest --watch
```

Tests use Jest with `ts-jest`. All new code requires tests. PRs that reduce coverage will not be merged.

---

## Adding an OAuth Provider Adapter

This is the most common contribution. Follow the pattern exactly.

**1. Create the adapter file**

```bash
touch packages/oauth/src/providers/your-provider.ts
```

**2. Implement `OAuthAdapter`**

```typescript
import type { OAuthAdapter, TokenResponse, RefreshResult } from "../types";

export const yourProviderAdapter: OAuthAdapter = {
  id: "your-provider",
  displayName: "Your Provider",
  authorizationUrl: "https://your-provider.com/oauth/authorize",
  tokenUrl: "https://your-provider.com/oauth/token",
  defaultScopes: ["read"],

  async exchangeCode(code: string, redirectUri: string): Promise<TokenResponse> {
    // Implement PKCE or standard code exchange
    // Return: { accessToken, refreshToken, expiresAt, scope }
  },

  async refreshToken(refreshToken: string): Promise<RefreshResult> {
    // Return: { accessToken, expiresAt } or throw CredRefreshError
  },

  validateScopes(requested: string[], granted: string[]): boolean {
    // Return true if granted satisfies requested
  },
};
```

**3. Export from the package index and register**

Add to `packages/oauth/src/index.ts` and `packages/oauth/src/registry.ts`.

**4. Write tests**

Mock all HTTP calls. Cover: successful code exchange, token refresh, refresh failure, scope validation.

**What we check in review:**
- No client secrets hardcoded anywhere
- Token exchange uses HTTPS only
- Refresh errors throw `CredRefreshError`, not generic `Error`
- `expiresAt` is a UTC timestamp in milliseconds, never a duration

---

## Security Policy

**To report a vulnerability:** See [SECURITY.md](./SECURITY.md). Do not open a public GitHub issue. Email the address in SECURITY.md with subject `[CRED SECURITY]`. Response within 48 hours.

**Files that require explicit security review before merge:**

- `packages/vault/src/encryption.ts` — AES-GCM implementation, key derivation
- Any file touching cryptographic primitives, key material, or token storage format
- Changes to how tokens are scoped, delegated, or revoked in `@credninja/sdk`

Open these as draft PRs and tag `@cred-ninja/security`. We do not merge crypto changes under time pressure.

**PRs rejected outright:**

- Logs or writes token values outside the encrypted vault
- Weakens encryption (downgrading algorithms, reducing key length)
- Adds any bypass or debug mode that skips token validation
- Contains credentials, secrets, or tokens in the diff

---

## Protocol Contributions

The Cred Delegation Protocol is an open standard. The SDK is the reference implementation.

To propose a protocol change: open an issue tagged `protocol`, discuss to consensus, then PR the spec and SDK together. Protocol changes that break backward compatibility require a major version bump and migration guide.

If you are involved in IETF standardization and want to align with an active draft, open an issue and tag `@cred-ninja/protocol`.

---

## Pull Request Process

Before opening a PR, all of these must pass:

```bash
npm run build
npm run typecheck
npm test
npm run lint
```

**Checklist:**

- [ ] Tests pass
- [ ] Types pass with zero errors
- [ ] No `any` types introduced
- [ ] No secrets, tokens, or credentials in the diff
- [ ] New public API has JSDoc comments
- [ ] CHANGELOG.md updated under `[Unreleased]`

**PR description must include:** What, Why, Testing, Security impact.

We squash-merge PRs.

---

## Code Style

- **No `any`** — use `unknown` and narrow it, or discuss the right type
- **No type assertions without a comment** — `value as Foo` needs justification
- **No em dashes** in comments, JSDoc, or docs — use commas, colons, or parentheses
- **Errors are typed** — throw `CredError`, `CredRefreshError`, not raw `Error`
- **Async is explicit** — don't mix Promise chains and async/await in the same function

ESLint and Prettier run in CI: `npm run lint`, `npm run format`.

---

## Good First Issues

Issues tagged [`good first issue`](https://github.com/cred-ninja/sdk/issues?q=is%3Aopen+label%3A%22good+first+issue%22) are scoped, well-specified starting points.

The most common: **adding an OAuth provider adapter**. Check if an issue exists first, open one to confirm it's wanted, then follow the guide above.

Start by reading `packages/sdk/src/index.ts` — it's the clearest picture of the full delegation flow.

Questions? Open a discussion on GitHub before starting large work.
