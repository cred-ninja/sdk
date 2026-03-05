# Contributing to Cred

Thanks for your interest. Contributions to the SDKs and integrations are welcome.

## What lives here

This repo contains the client-side SDKs and framework integrations. The Cred API (token vault, OAuth flows, consent management) is hosted separately and not in this repo.

**In scope for contributions:**
- Bug fixes in SDK clients (`@credninja/sdk`, `cred-auth`)
- OAuth package improvements (`@credninja/oauth`): adapters, middleware, PKCE
- Vault package improvements (`@credninja/vault`): storage backends, encryption
- Framework integrations (LangChain, CrewAI, OpenAI Agents, and new frameworks)
- Custom OAuth adapter implementations
- Examples and documentation
- Test coverage improvements

**Out of scope:**
- Changes to the hosted Cred Cloud API behavior
- Encryption algorithm changes (AES-256-GCM is fixed by design)

## Getting started

```bash
git clone https://github.com/cred-ninja/sdk
cd sdk
npm install

# Run all TypeScript tests
npm test

# Individual packages
cd packages/oauth && npm test    # 54 tests: adapters, PKCE, middleware
cd packages/vault && npm test    # 55 tests: encryption, storage backends
cd packages/sdk && npm test      # 60 tests: delegation, identity
cd packages/mcp && npm test      # MCP server, SSRF protection

# Python SDK / integrations
pip install httpx respx pytest hatchling
cd packages/sdk-python && pytest
```

## Pull requests

- One feature or fix per PR
- Tests required for new behavior
- Keep SDK changes backward compatible. Agents depend on these interfaces.
- For new framework integrations, open an issue first to discuss the design

## Design principles

- **Agent tokens are deployment config.** `appClientId` and `agentToken` are baked in at deploy time, not passed at runtime by users.
- **ConsentRequiredError is a first-class flow.** Integrations must handle it, not swallow it.
- **No credentials stored in SDK.** The SDK is stateless; Cred's API holds all secrets.

## Code of conduct

Be direct and constructive. We value clear technical communication over ceremony.
