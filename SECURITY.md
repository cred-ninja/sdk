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

## CI and automated review boundaries

The [review-gate runbook](./docs/ci-review-gate.md) defines the candidate CI policy
and its protected bootstrap requirements. Automated reviews are advisory evidence
in a non-atomic **advisory-only** aggregate, not a required merge context or a
replacement for independent human/code-owner approval. Two isolated Claude sessions share one provider; that
is not independent-provider review. The candidate policy must be deployed and
verified on a hosted canary before claiming that it protects the default branch.

Do not run pull-request code, dependency installation, hooks or arbitrary mention
commands in a job holding model credentials or a repository-write token. The
trusted target workflow reads PR/issue diffs as data, disables model tools and
keeps check publication in a separate non-model job. Future workers must not
change security/release policy, branch protection, approvals or publishing
without explicit maintainer authorization. A missing required check or review-service failure
is never permission to bypass native approvals or weaken the policy.

## Disclosure policy

We follow coordinated disclosure. We'll work with you to understand and fix the issue before public disclosure. Credit is given to researchers who report valid vulnerabilities.
