import { describe, it, expect } from 'vitest';
import {
  ClassificationCeilingPolicy,
  classificationCeilingPolicy,
} from '../policies/classification-ceiling.js';
import { CredGuard } from '../guard.js';
import type { ClassificationCeilingPolicyConfig, GuardContext } from '../types.js';

const LEVELS = ['public', 'internal', 'confidential', 'restricted'];

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'google',
    agentTokenHash: 'agent-hash-123',
    requestedScopes: ['read'],
    consentedScopes: ['read'],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makePolicy(overrides: Partial<ClassificationCeilingPolicyConfig> = {}): ClassificationCeilingPolicy {
  return new ClassificationCeilingPolicy({
    levels: LEVELS,
    agentCeilings: { 'agent-hash-123': 'confidential' },
    ...overrides,
  });
}

describe('ClassificationCeilingPolicy', () => {
  describe('ceiling comparison', () => {
    it('allows a resource below the ceiling', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 'internal' } }));

      expect(result.decision).toBe('ALLOW');
      expect(result.policy).toBe('classification-ceiling');
      expect(result.code).toBeUndefined();
    });

    it('allows a resource exactly at the ceiling', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 'confidential' } }));

      expect(result.decision).toBe('ALLOW');
    });

    it('allows the lowest level', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 'public' } }));

      expect(result.decision).toBe('ALLOW');
    });

    it('denies a resource above the ceiling', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 'restricted' } }));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('classification_exceeded');
      expect(result.reason).toContain('restricted');
      expect(result.reason).toContain('confidential');
    });

    it('works with other level vocabularies', () => {
      const policy = new ClassificationCeilingPolicy({
        levels: ['U', 'CUI', 'S', 'TS'],
        agentCeilings: { 'agent-hash-123': 'S' },
      });

      expect(policy.evaluate(makeContext({ metadata: { classification: 'S' } })).decision).toBe('ALLOW');
      expect(policy.evaluate(makeContext({ metadata: { classification: 'TS' } })).code).toBe(
        'classification_exceeded',
      );
    });
  });

  describe('unknown levels (fail closed)', () => {
    it('denies a level not in the list', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 'secret' } }));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('classification_unknown');
    });

    it('matches levels case-sensitively', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 'Internal' } }));

      expect(result.code).toBe('classification_unknown');
    });

    it('denies a non-string level', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 1 } }));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('classification_unknown');
    });

    it('denies an empty-string level', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: '' } }));

      expect(result.code).toBe('classification_unknown');
    });

    it('does not treat inherited object keys as levels', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: 'toString' } }));

      expect(result.code).toBe('classification_unknown');
    });
  });

  describe('missing classification', () => {
    it('denies by default when no classification is present', () => {
      const result = makePolicy().evaluate(makeContext());

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('classification_missing');
    });

    it('treats null as missing', () => {
      const result = makePolicy().evaluate(makeContext({ metadata: { classification: null } }));

      expect(result.code).toBe('classification_missing');
    });

    it('skips when onMissing is skip', () => {
      const result = makePolicy({ onMissing: 'skip' }).evaluate(makeContext({ metadata: {} }));

      expect(result.decision).toBe('SKIP');
      expect(result.code).toBeUndefined();
    });

    it('skips before looking up the agent', () => {
      const result = makePolicy({ onMissing: 'skip' }).evaluate(
        makeContext({ agentTokenHash: 'unknown-agent' }),
      );

      expect(result.decision).toBe('SKIP');
    });

    it('still denies an unknown level when onMissing is skip', () => {
      const result = makePolicy({ onMissing: 'skip' }).evaluate(
        makeContext({ metadata: { classification: 'bogus' } }),
      );

      expect(result.code).toBe('classification_unknown');
    });
  });

  describe('agent ceiling resolution', () => {
    it('denies an unknown agent', () => {
      const result = makePolicy().evaluate(
        makeContext({ agentTokenHash: 'other-agent', metadata: { classification: 'public' } }),
      );

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('ceiling_unknown');
    });

    it('looks up the ceiling by agentDid', () => {
      const policy = makePolicy({ agentCeilings: { 'did:web:agent.example': 'restricted' } });
      const result = policy.evaluate(
        makeContext({ agentDid: 'did:web:agent.example', metadata: { classification: 'restricted' } }),
      );

      expect(result.decision).toBe('ALLOW');
    });

    it('applies the lower ceiling when agentDid and agentTokenHash both match', () => {
      const policy = makePolicy({
        agentCeilings: { 'did:web:agent.example': 'restricted', 'agent-hash-123': 'internal' },
      });
      const result = policy.evaluate(
        makeContext({ agentDid: 'did:web:agent.example', metadata: { classification: 'confidential' } }),
      );

      expect(result.code).toBe('classification_exceeded');
      expect(result.reason).toContain('internal');
    });

    it('denies when the configured ceiling is not a known level', () => {
      const policy = makePolicy({ agentCeilings: { 'agent-hash-123': 'top-secret' } });
      const result = policy.evaluate(makeContext({ metadata: { classification: 'public' } }));

      expect(result.code).toBe('ceiling_unknown');
    });

    it('does not treat inherited object keys as agents', () => {
      const result = makePolicy().evaluate(
        makeContext({ agentTokenHash: 'constructor', metadata: { classification: 'public' } }),
      );

      expect(result.code).toBe('ceiling_unknown');
    });

    it('uses resolveAgentCeiling over the map', () => {
      const policy = makePolicy({ resolveAgentCeiling: () => 'restricted' });
      const result = policy.evaluate(makeContext({ metadata: { classification: 'restricted' } }));

      expect(result.decision).toBe('ALLOW');
    });

    it('denies when resolveAgentCeiling returns undefined', () => {
      const policy = makePolicy({ resolveAgentCeiling: () => undefined });
      const result = policy.evaluate(makeContext({ metadata: { classification: 'public' } }));

      expect(result.code).toBe('ceiling_unknown');
    });

    it('denies when resolveAgentCeiling throws', () => {
      const policy = makePolicy({
        resolveAgentCeiling: () => {
          throw new Error('directory down');
        },
      });
      const result = policy.evaluate(makeContext({ metadata: { classification: 'public' } }));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('ceiling_unknown');
      expect(result.reason).toContain('directory down');
    });
  });

  describe('resource level resolution', () => {
    it('uses resolveResourceLevel', () => {
      const policy = makePolicy({
        resolveResourceLevel: (ctx) => (ctx.targetUrl?.includes('/hr/') ? 'restricted' : 'public'),
      });

      expect(policy.evaluate(makeContext({ targetUrl: 'https://api.example.com/hr/1' })).code).toBe(
        'classification_exceeded',
      );
      expect(policy.evaluate(makeContext({ targetUrl: 'https://api.example.com/docs' })).decision).toBe(
        'ALLOW',
      );
    });

    it('denies when resolveResourceLevel throws', () => {
      const policy = makePolicy({
        resolveResourceLevel: () => {
          throw new Error('label service down');
        },
      });
      const result = policy.evaluate(makeContext());

      expect(result.code).toBe('classification_unknown');
    });
  });

  describe('noWriteDown', () => {
    const flow = (source: unknown, destination: unknown) =>
      makeContext({ metadata: { sourceClassification: source, destinationClassification: destination } });

    it('ignores flow metadata when noWriteDown is off', () => {
      const result = makePolicy().evaluate(
        makeContext({
          metadata: {
            classification: 'internal',
            sourceClassification: 'confidential',
            destinationClassification: 'public',
          },
        }),
      );

      expect(result.decision).toBe('ALLOW');
    });

    it('denies moving data from a higher level to a lower one', () => {
      const result = makePolicy({ noWriteDown: true }).evaluate(flow('confidential', 'public'));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('write_down_blocked');
    });

    it('allows a flow within the same level', () => {
      const result = makePolicy({ noWriteDown: true }).evaluate(flow('internal', 'internal'));

      expect(result.decision).toBe('ALLOW');
    });

    it('allows writing up to the ceiling', () => {
      const result = makePolicy({ noWriteDown: true }).evaluate(flow('public', 'confidential'));

      expect(result.decision).toBe('ALLOW');
    });

    it('checks the flow levels against the ceiling', () => {
      const result = makePolicy({ noWriteDown: true }).evaluate(flow('internal', 'restricted'));

      expect(result.code).toBe('classification_exceeded');
      expect(result.reason).toContain('Destination');
    });

    it('checks the resource level alongside the flow', () => {
      const result = makePolicy({ noWriteDown: true }).evaluate(
        makeContext({
          metadata: {
            classification: 'restricted',
            sourceClassification: 'public',
            destinationClassification: 'public',
          },
        }),
      );

      expect(result.code).toBe('classification_exceeded');
    });

    it('denies a flow that names only one side', () => {
      const result = makePolicy({ noWriteDown: true }).evaluate(flow('internal', undefined));

      expect(result.code).toBe('classification_missing');
    });

    it('denies an unknown flow level', () => {
      const result = makePolicy({ noWriteDown: true }).evaluate(flow('internal', 'nope'));

      expect(result.code).toBe('classification_unknown');
    });

    it('a flow counts as classification present for onMissing', () => {
      const result = makePolicy({ noWriteDown: true, onMissing: 'skip' }).evaluate(
        flow('confidential', 'public'),
      );

      expect(result.code).toBe('write_down_blocked');
    });

    it('uses resolveFlow', () => {
      const policy = makePolicy({
        noWriteDown: true,
        resolveFlow: (ctx) => ({ source: ctx.metadata?.from, destination: ctx.metadata?.to }),
      });
      const result = policy.evaluate(makeContext({ metadata: { from: 'confidential', to: 'internal' } }));

      expect(result.code).toBe('write_down_blocked');
    });
  });

  describe('configuration', () => {
    it('rejects an empty levels list', () => {
      expect(() => makePolicy({ levels: [] })).toThrow(TypeError);
    });

    it('rejects duplicate levels', () => {
      expect(() => makePolicy({ levels: ['a', 'b', 'a'] })).toThrow(/duplicate/);
    });

    it('requires a way to resolve the agent ceiling', () => {
      expect(
        () => new ClassificationCeilingPolicy({ levels: LEVELS }),
      ).toThrow(/agentCeilings or resolveAgentCeiling/);
    });
  });

  describe('factory function', () => {
    it('creates a policy via factory', () => {
      const policy = classificationCeilingPolicy({ levels: LEVELS, agentCeilings: {} });

      expect(policy).toBeInstanceOf(ClassificationCeilingPolicy);
      expect(policy.name).toBe('classification-ceiling');
    });
  });

  describe('with CredGuard', () => {
    it('surfaces the typed code on deniedBy', async () => {
      const guard = new CredGuard({ policies: [makePolicy()] });
      const decision = await guard.evaluate(makeContext({ metadata: { classification: 'restricted' } }));

      expect(decision.allowed).toBe(false);
      expect(decision.deniedBy?.code).toBe('classification_exceeded');
    });
  });
});
