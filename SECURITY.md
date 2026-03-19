# Security Policy

## Scope

This policy covers the SDKs and integrations in this repository. For vulnerabilities in the hosted Cred API or portal, see below.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: security@cred.ninja

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

We'll acknowledge within 48 hours and aim to resolve critical issues within 14 days.

## What counts as a vulnerability

**In this repo (SDKs):**
- Credential or token exposure in SDK code
- Insecure defaults that could lead to token leakage
- Dependency vulnerabilities with active exploits

**In the hosted service (report to same email):**
- Authentication bypass
- Cross-user token access
- Encryption weaknesses
- OAuth flow manipulation

## Out of scope

- Theoretical attacks without proof of concept
- Issues in dependencies without a clear exploit path
- Rate limiting or availability issues

## Disclosure policy

We follow coordinated disclosure. We'll work with you to understand and fix the issue before public disclosure. Credit is given to researchers who report valid vulnerabilities.
