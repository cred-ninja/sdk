import { describe, it, expect } from 'vitest';
import { UrlAllowlistPolicy, urlAllowlistPolicy } from '../policies/url-allowlist.js';
import type { GuardContext } from '../types.js';

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'github',
    agentTokenHash: 'agent-hash-123',
    requestedScopes: ['repo'],
    consentedScopes: ['repo'],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('UrlAllowlistPolicy', () => {
  describe('string prefix matching', () => {
    it('allows URLs that match prefix', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/repos/', 'https://api.github.com/user'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/repos/owner/repo/issues',
      }));

      expect(result.decision).toBe('ALLOW');
      expect(result.reason).toContain('matches allowed pattern');
    });

    it('denies URLs that do not match any prefix', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/repos/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/orgs/myorg',
      }));

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('does not match any allowed pattern');
    });

    it('exact prefix match works', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/user'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/user',
      }));

      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('regex pattern matching', () => {
    it('allows URLs matching regex', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          google: [/^https:\/\/www\.googleapis\.com\/calendar\//],
        },
      });

      const result = policy.evaluate(makeContext({
        provider: 'google',
        targetUrl: 'https://www.googleapis.com/calendar/v3/events',
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('denies URLs not matching regex', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          google: [/^https:\/\/www\.googleapis\.com\/calendar\//],
        },
      });

      const result = policy.evaluate(makeContext({
        provider: 'google',
        targetUrl: 'https://www.googleapis.com/drive/v3/files',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('complex regex patterns work', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: [/^https:\/\/api\.github\.com\/repos\/[^/]+\/[^/]+\/issues$/],
        },
      });

      // Matches
      const result1 = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/repos/owner/repo/issues',
      }));
      expect(result1.decision).toBe('ALLOW');

      // Doesn't match (extra path segment)
      const result2 = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/repos/owner/repo/issues/123',
      }));
      expect(result2.decision).toBe('DENY');
    });
  });

  describe('mixed patterns', () => {
    it('supports both strings and regex in same provider', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: [
            'https://api.github.com/user',
            /^https:\/\/api\.github\.com\/repos\//,
          ],
        },
      });

      const result1 = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/user',
      }));
      expect(result1.decision).toBe('ALLOW');

      const result2 = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/repos/owner/repo',
      }));
      expect(result2.decision).toBe('ALLOW');
    });
  });

  describe('SKIP conditions', () => {
    it('SKIPs when no targetUrl (delegation request)', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: undefined,
      }));

      expect(result.decision).toBe('SKIP');
      expect(result.reason).toContain('not a cred_use request');
    });

    it('SKIPs when provider not in config', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          google: ['https://www.googleapis.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        provider: 'github',
        targetUrl: 'https://api.github.com/user',
      }));

      expect(result.decision).toBe('SKIP');
      expect(result.reason).toContain('No URL restrictions');
    });

    it('SKIPs when provider has empty allowedUrls', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: [],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/user',
      }));

      expect(result.decision).toBe('SKIP');
    });
  });

  describe('origin bypass protection', () => {
    it('denies attacker-controlled subdomain suffix', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com.evil.com/repos/owner/repo',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('denies userinfo-embedded host trick', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com@evil.com/repos/owner/repo',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('denies credentials embedded against the legitimate host', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/repos/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://user:pass@api.github.com/repos/owner/repo',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('denies a scheme downgrade to the allowed host', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'http://api.github.com/repos/owner/repo',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('denies a different port on the allowed host', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com:8443/repos/owner/repo',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('denies an unparseable target URL (fail closed)', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'not-a-valid-url',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('still allows the legitimate same-origin host', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/repos/owner/repo',
      }));

      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('edge cases', () => {
    it('handles URLs with query parameters', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/search/'],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/search/repositories?q=test',
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('handles URLs with special characters', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {
          github: [/^https:\/\/api\.github\.com\/repos\/[^/]+\/[^/]+$/],
        },
      });

      const result = policy.evaluate(makeContext({
        targetUrl: 'https://api.github.com/repos/my-org/my-repo',
      }));

      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('factory function', () => {
    it('creates a UrlAllowlistPolicy instance', () => {
      const created = urlAllowlistPolicy({ allowedUrls: {} });
      expect(created).toBeInstanceOf(UrlAllowlistPolicy);
      expect(created.name).toBe('url-allowlist');
    });
  });

  // U2 (docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md):
  // wildcardSubdomains + scopeGate, generalizing what token-cache.ts used to
  // hardcode for Salesforce and Google specifically.
  describe('wildcardSubdomains', () => {
    it('allows a hostname matching a configured wildcard suffix', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {},
        wildcardSubdomains: { salesforce: ['.salesforce.com', '.force.com'] },
      });

      const result = policy.evaluate(makeContext({
        provider: 'salesforce',
        targetUrl: 'https://mycompany.salesforce.com/services/data/v59.0/sobjects',
      }));

      expect(result.decision).toBe('ALLOW');
      expect(result.reason).toContain('wildcard suffix');
    });

    it('denies a hostname that does not match any configured suffix', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {},
        wildcardSubdomains: { salesforce: ['.salesforce.com', '.force.com'] },
      });

      const result = policy.evaluate(makeContext({
        provider: 'salesforce',
        targetUrl: 'https://attacker.example.com/',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('rejects a numeric-looking leading label (DNS-rebinding guard)', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {},
        wildcardSubdomains: { salesforce: ['.salesforce.com'] },
      });

      const result = policy.evaluate(makeContext({
        provider: 'salesforce',
        targetUrl: 'https://192.168.1.1.salesforce.com/',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('rejects a wildcard-suffix match over HTTP, with userinfo, or on a non-default port', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: {},
        wildcardSubdomains: { salesforce: ['.salesforce.com'] },
      });

      expect(policy.evaluate(makeContext({ provider: 'salesforce', targetUrl: 'http://mycompany.salesforce.com/' })).decision).toBe('DENY');
      expect(policy.evaluate(makeContext({ provider: 'salesforce', targetUrl: 'https://user:pass@mycompany.salesforce.com/' })).decision).toBe('DENY');
      expect(policy.evaluate(makeContext({ provider: 'salesforce', targetUrl: 'https://mycompany.salesforce.com:8443/' })).decision).toBe('DENY');
    });

    it('SKIPs a provider with neither allowedUrls nor wildcardSubdomains configured', () => {
      const policy = new UrlAllowlistPolicy({ allowedUrls: {}, wildcardSubdomains: { salesforce: ['.salesforce.com'] } });
      const result = policy.evaluate(makeContext({ provider: 'github', targetUrl: 'https://api.github.com/user' }));
      expect(result.decision).toBe('SKIP');
    });

    it('a provider with only wildcardSubdomains (no allowedUrls entry) is not SKIPped', () => {
      const policy = new UrlAllowlistPolicy({ allowedUrls: {}, wildcardSubdomains: { salesforce: ['.salesforce.com'] } });
      const result = policy.evaluate(makeContext({ provider: 'salesforce', targetUrl: 'https://mycompany.salesforce.com/' }));
      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('scopeGate', () => {
    it('allows a pattern match when the scope gate passes', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: { google: ['https://www.googleapis.com/calendar/'] },
        scopeGate: {
          google: (scopes) => scopes.some((s) => s.includes('calendar')),
        },
      });

      const result = policy.evaluate(makeContext({
        provider: 'google',
        requestedScopes: ['calendar.readonly'],
        targetUrl: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('denies a pattern match when the scope gate rejects it', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: { google: ['https://www.googleapis.com/'] },
        scopeGate: {
          google: (scopes) => scopes.some((s) => s.includes('calendar')),
        },
      });

      const result = policy.evaluate(makeContext({
        provider: 'google',
        requestedScopes: ['drive.readonly'],
        targetUrl: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      }));

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('does not match an allowed scope');
    });

    it('a provider with no scopeGate entry is ungated beyond the base URL match', () => {
      const policy = new UrlAllowlistPolicy({
        allowedUrls: { github: ['https://api.github.com/'] },
      });

      const result = policy.evaluate(makeContext({
        provider: 'github',
        requestedScopes: ['repo'],
        targetUrl: 'https://api.github.com/user',
      }));

      expect(result.decision).toBe('ALLOW');
    });
  });
});
