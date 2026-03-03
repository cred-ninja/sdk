# Contributing to Cred

Thanks for your interest. Contributions to the SDKs and integrations are welcome.

## What lives here

This repo contains the client-side SDKs and framework integrations. The Cred API (token vault, OAuth flows, consent management) is proprietary and not in this repo.

**In scope for contributions:**
- Bug fixes in SDK clients (`@credninja/sdk`, `cred-auth`)
- Framework integrations (LangChain, CrewAI, OpenAI Agents, and new frameworks)
- Examples and documentation
- Test coverage improvements

**Out of scope:**
- Changes to the hosted API behavior
- New OAuth providers (those are added server-side)
- Encryption or token storage logic

## Getting started

```bash
git clone https://github.com/cred-ninja/sdk
cd sdk

# TypeScript SDK
cd packages/sdk && npm install && npm test

# Python SDK / integrations
pip install httpx respx pytest hatchling
cd packages/sdk-python && pytest
```

## Pull requests

- One feature or fix per PR
- Tests required for new behavior
- Keep SDK changes backward compatible — agents depend on these interfaces
- For new framework integrations, open an issue first to discuss the design

## Design principles

- **Agent tokens are deployment config** — `appClientId` and `agentToken` are baked in at deploy time, not passed at runtime by users
- **ConsentRequiredError is a first-class flow** — integrations must handle it, not swallow it
- **No credentials stored in SDK** — the SDK is stateless; Cred's API holds all secrets

## Code of conduct

Be direct and constructive. We value clear technical communication over ceremony.
