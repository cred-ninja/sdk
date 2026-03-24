import { describe, it, expect, vi } from 'vitest';
import { CredGuard } from '../guard.js';
import { wrapMcpToolHandler } from '../middleware/mcp.js';
import type { CredPolicy } from '../types.js';
import type { CallToolResult, McpToolContext, CredToolInput } from '../middleware/mcp.js';

// Import middleware module to register prototype method
import '../middleware/mcp.js';

function makeToolInput(overrides: Partial<CredToolInput> = {}): CredToolInput {
  return {
    provider: 'github',
    scopes: ['repo'],
    ...overrides,
  };
}

function makeContext(overrides: Partial<McpToolContext> = {}): McpToolContext {
  return {
    agentToken: 'test-agent-token',
    ...overrides,
  };
}

function makeSuccessHandler(): (input: CredToolInput, ctx: McpToolContext) => Promise<CallToolResult> {
  return async () => ({
    content: [{ type: 'text', text: 'Success!' }],
  });
}

function makeAllowPolicy(): CredPolicy {
  return {
    name: 'allow-all',
    evaluate: () => ({ decision: 'ALLOW', policy: 'allow-all' }),
  };
}

function makeDenyPolicy(reason = 'denied'): CredPolicy {
  return {
    name: 'deny-all',
    evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason }),
  };
}

describe('MCP Tool Wrapper', () => {
  describe('wrapMcpToolHandler', () => {
    it('calls handler on ALLOW', async () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'Success!' }],
      });
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const wrapped = wrapMcpToolHandler(guard, handler);

      const result = await wrapped(makeToolInput(), makeContext());

      expect(handler).toHaveBeenCalled();
      expect(result.content[0].text).toBe('Success!');
      expect(result.isError).toBeUndefined();
    });

    it('returns error on DENY', async () => {
      const handler = vi.fn();
      const guard = new CredGuard({ policies: [makeDenyPolicy('rate limit exceeded')] });
      const wrapped = wrapMcpToolHandler(guard, handler);

      const result = await wrapped(makeToolInput(), makeContext());

      expect(handler).not.toHaveBeenCalled();
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('deny-all');
      expect(result.content[0].text).toContain('rate limit exceeded');
    });

    it('returns error if agent token is missing', async () => {
      const handler = vi.fn();
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const wrapped = wrapMcpToolHandler(guard, handler);

      const result = await wrapped(makeToolInput(), { /* no token */ });

      expect(handler).not.toHaveBeenCalled();
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Missing agent token');
    });

    it('hashes the agent token', async () => {
      let capturedHash = '';
      const guard = new CredGuard({
        policies: [{
          name: 'capture-hash',
          evaluate: (ctx) => {
            capturedHash = ctx.agentTokenHash;
            return { decision: 'ALLOW', policy: 'capture-hash' };
          },
        }],
      });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler());

      await wrapped(makeToolInput(), makeContext());

      expect(capturedHash).toMatch(/^[a-f0-9]{64}$/);
      expect(capturedHash).not.toBe('test-agent-token');
    });

    it('accepts pre-hashed agent token', async () => {
      let capturedHash = '';
      const precomputedHash = 'abc123def456'.repeat(5).slice(0, 64);
      const guard = new CredGuard({
        policies: [{
          name: 'capture-hash',
          evaluate: (ctx) => {
            capturedHash = ctx.agentTokenHash;
            return { decision: 'ALLOW', policy: 'capture-hash' };
          },
        }],
      });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler());

      await wrapped(makeToolInput(), { agentTokenHash: precomputedHash });

      expect(capturedHash).toBe(precomputedHash);
    });

    it('passes provider to guard context', async () => {
      let capturedProvider = '';
      const guard = new CredGuard({
        policies: [{
          name: 'capture-provider',
          evaluate: (ctx) => {
            capturedProvider = ctx.provider;
            return { decision: 'ALLOW', policy: 'capture-provider' };
          },
        }],
      });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler());

      await wrapped(makeToolInput({ provider: 'google' }), makeContext());

      expect(capturedProvider).toBe('google');
    });

    it('passes scopes to guard context', async () => {
      let capturedScopes: string[] = [];
      const guard = new CredGuard({
        policies: [{
          name: 'capture-scopes',
          evaluate: (ctx) => {
            capturedScopes = ctx.requestedScopes;
            return { decision: 'ALLOW', policy: 'capture-scopes' };
          },
        }],
      });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler());

      await wrapped(makeToolInput({ scopes: ['read', 'write'] }), makeContext());

      expect(capturedScopes).toEqual(['read', 'write']);
    });

    it('passes targetUrl to guard context (cred_use)', async () => {
      let capturedUrl = '';
      const guard = new CredGuard({
        policies: [{
          name: 'capture-url',
          evaluate: (ctx) => {
            capturedUrl = ctx.targetUrl ?? '';
            return { decision: 'ALLOW', policy: 'capture-url' };
          },
        }],
      });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler());

      await wrapped(
        makeToolInput({ targetUrl: 'https://api.github.com/user' }),
        makeContext()
      );

      expect(capturedUrl).toBe('https://api.github.com/user');
    });

    it('attaches audit event to context', async () => {
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler());
      const ctx = makeContext() as any;

      await wrapped(makeToolInput(), ctx);

      expect(ctx.guardAuditEvent).toBeDefined();
      expect(ctx.guardAuditEvent.type).toBe('guard.decision');
    });

    it('captures Web Bot Auth identity fields from metadata', async () => {
      let capturedKeyId = '';
      let capturedSignatureAgent = '';
      const guard = new CredGuard({
        policies: [{
          name: 'capture-web-bot-auth',
          evaluate: (ctx) => {
            capturedKeyId = ctx.webBotAuthKeyId ?? '';
            capturedSignatureAgent = ctx.signatureAgent ?? '';
            return { decision: 'ALLOW', policy: 'capture-web-bot-auth' };
          },
        }],
      });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler());
      const ctx = makeContext() as any;

      await wrapped(makeToolInput({
        metadata: {
          identitySource: 'web-bot-auth',
          webBotAuthKeyId: 'kid_456',
          signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
        },
      }), ctx);

      expect(capturedKeyId).toBe('kid_456');
      expect(capturedSignatureAgent).toContain('/.well-known/http-message-signatures-directory');
      expect(ctx.guardAuditEvent.webBotAuthKeyId).toBe('kid_456');
    });

    it('updates input scopes when narrowed', async () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'Success!' }],
      });
      const guard = new CredGuard({
        policies: [{
          name: 'narrower',
          evaluate: () => ({
            decision: 'ALLOW',
            policy: 'narrower',
            narrowedScopes: ['read-only'],
          }),
        }],
      });
      const wrapped = wrapMcpToolHandler(guard, handler);
      const input = makeToolInput({ scopes: ['read', 'write'] });

      await wrapped(input, makeContext());

      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({ scopes: ['read-only'] }),
        expect.any(Object)
      );
    });

    it('returns error on handler exception', async () => {
      const handler = vi.fn().mockRejectedValue(new Error('Handler failed'));
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const wrapped = wrapMcpToolHandler(guard, handler);

      const result = await wrapped(makeToolInput(), makeContext());

      // This catches guard evaluation errors, not handler errors
      // Handler errors should propagate through
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Guard evaluation failed');
    });
  });

  describe('custom onDeny handler', () => {
    it('supports custom onDeny handler', async () => {
      const onDeny = vi.fn().mockReturnValue({
        content: [{ type: 'text', text: 'Custom deny message' }],
        isError: true,
      });
      const guard = new CredGuard({ policies: [makeDenyPolicy()] });
      const wrapped = wrapMcpToolHandler(guard, makeSuccessHandler(), { onDeny });

      const result = await wrapped(makeToolInput(), makeContext());

      expect(onDeny).toHaveBeenCalled();
      expect(result.content[0].text).toBe('Custom deny message');
    });
  });

  describe('CredGuard.wrapMcpTool()', () => {
    it('is available as a method on CredGuard', async () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'Success!' }],
      });
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });

      expect(typeof guard.wrapMcpTool).toBe('function');

      const wrapped = guard.wrapMcpTool(handler);
      const result = await wrapped(makeToolInput(), makeContext());

      expect(handler).toHaveBeenCalled();
      expect(result.content[0].text).toBe('Success!');
    });
  });
});
