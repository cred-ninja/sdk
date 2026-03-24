import { describe, expect, it } from 'vitest';
import { webBotAuthPolicy } from '../policies/web-bot-auth.js';

describe('webBotAuthPolicy', () => {
  it('allows when key id is present and source is allowed', () => {
    const policy = webBotAuthPolicy({
      requireKeyId: true,
      allowedIdentitySources: ['web-bot-auth'],
      allowedSignatureAgentPrefixes: ['https://cred.example.com/'],
    });

    const result = policy.evaluate({
      provider: 'google',
      agentTokenHash: 'abc',
      requestedScopes: ['calendar.readonly'],
      consentedScopes: ['calendar.readonly'],
      timestamp: new Date().toISOString(),
      identitySource: 'web-bot-auth',
      webBotAuthKeyId: 'kid_123',
      signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
    });

    expect(result).toEqual({
      decision: 'ALLOW',
      policy: 'web-bot-auth',
    });
  });

  it('denies when key id is required and missing', () => {
    const policy = webBotAuthPolicy({ requireKeyId: true });

    const result = policy.evaluate({
      provider: 'google',
      agentTokenHash: 'abc',
      requestedScopes: [],
      consentedScopes: [],
      timestamp: new Date().toISOString(),
    });

    expect(result.decision).toBe('DENY');
    expect(result.reason).toContain('Missing Web Bot Auth key id');
  });
});
