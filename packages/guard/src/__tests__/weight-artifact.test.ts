import { describe, it, expect } from 'vitest';
import { weightArtifactPolicy } from '../policies/weight-artifact.js';
import type { GuardContext } from '../types.js';
import { CredGuard } from '../guard.js';
import { snapshotGuard, applyPatch, classifyPatch, materializePolicies, interpretSnapshot } from '../weightspace/index.js';

const DIGEST = 'a'.repeat(64);

function ctx(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'hf',
    agentTokenHash: 'h',
    requestedScopes: [],
    consentedScopes: [],
    timestamp: '2026-11-03T12:00:00.000Z',
    targetUrl: 'https://huggingface.co/org/model/resolve/main/model.safetensors',
    targetMethod: 'GET',
    ...overrides,
  };
}

describe('weightArtifactPolicy (experimental)', () => {
  const policy = weightArtifactPolicy({
    stores: {
      hf: { hosts: ['huggingface.co', '.hf.co'], allowWrite: true, writePathPrefixes: ['/api/models/org/'], pinnedDigests: [DIGEST], maxBytes: 10_000 },
      s3: { hosts: ['.s3.amazonaws.com'] },
    },
  });

  it('skips calls without a target or for unlisted providers', () => {
    expect(policy.evaluate(ctx({ targetUrl: undefined })).decision).toBe('SKIP');
    expect(policy.evaluate(ctx({ provider: 'github' })).decision).toBe('SKIP');
  });

  it('pins hosts, methods, write prefixes, digests and size', () => {
    const ok = policy.evaluate(ctx({ metadata: { artifactSha256: DIGEST, artifactBytes: 5000 } }));
    expect(ok.decision).toBe('ALLOW');

    expect(policy.evaluate(ctx({ targetUrl: 'https://evil.example/model.bin', metadata: { artifactSha256: DIGEST, artifactBytes: 1 } })).code).toBe('artifact_host_not_allowed');
    expect(policy.evaluate(ctx({ targetUrl: 'https://huggingface.co.evil.example/x', metadata: { artifactSha256: DIGEST, artifactBytes: 1 } })).code).toBe('artifact_host_not_allowed');
    expect(policy.evaluate(ctx({ targetUrl: 'https://cdn.hf.co/x', metadata: { artifactSha256: DIGEST, artifactBytes: 1 } })).decision).toBe('ALLOW');
    expect(policy.evaluate(ctx({ targetUrl: 'http://huggingface.co/x' })).code).toBe('artifact_url_invalid');

    expect(policy.evaluate(ctx({ metadata: { artifactBytes: 1 } })).code).toBe('artifact_digest_required');
    expect(policy.evaluate(ctx({ metadata: { artifactSha256: 'b'.repeat(64), artifactBytes: 1 } })).code).toBe('artifact_digest_not_pinned');
    expect(policy.evaluate(ctx({ metadata: { artifactSha256: DIGEST } })).code).toBe('artifact_size_required');
    expect(policy.evaluate(ctx({ metadata: { artifactSha256: DIGEST, artifactBytes: 20_000 } })).code).toBe('artifact_too_large');

    const write = (url: string) => policy.evaluate(ctx({ targetUrl: url, targetMethod: 'PUT', metadata: { artifactSha256: DIGEST, artifactBytes: 1 } }));
    expect(write('https://huggingface.co/api/models/org/model/upload').decision).toBe('ALLOW');
    expect(write('https://huggingface.co/api/models/other/model/upload').code).toBe('artifact_path_not_writable');
    expect(policy.evaluate(ctx({ provider: 's3', targetUrl: 'https://bucket.s3.amazonaws.com/ckpt.pt', targetMethod: 'PUT' })).code).toBe('artifact_write_not_allowed');
    expect(policy.evaluate(ctx({ provider: 's3', targetUrl: 'https://bucket.s3.amazonaws.com/ckpt.pt' })).decision).toBe('ALLOW');
  });

  it('validates its parameters', () => {
    expect(() => weightArtifactPolicy({ stores: { hf: { hosts: [] } } })).toThrow(/hosts/);
    expect(() => weightArtifactPolicy({ stores: { hf: { hosts: ['huggingface.co'], pinnedDigests: ['nope'] } } })).toThrow(/sha256/);
    expect(() => weightArtifactPolicy({ stores: { hf: { hosts: ['huggingface.co'], writePathPrefixes: ['api'] } } })).toThrow(/start with/);
  });

  it('is readable, patchable and classified in weight space', () => {
    const guard = new CredGuard({ policies: [policy] });
    const base = snapshotGuard(guard);
    expect(base.policies[0].descriptor.kind).toBe('weight-artifact');
    expect(interpretSnapshot(base).providers.find((p) => p.provider === 'hf')?.artifactStore).toEqual({ hosts: ['huggingface.co', '.hf.co'], allowWrite: true, pinnedDigests: 1, maxBytes: 10_000 });

    const pinAnother = [{ op: 'add' as const, path: '/weight-artifact/stores/hf/pinnedDigests/-', value: 'c'.repeat(64) }];
    expect(classifyPatch(base, pinAnother).effect).toBe('widening');
    const readOnly = [{ op: 'replace' as const, path: '/weight-artifact/stores/hf/allowWrite', value: false }];
    expect(classifyPatch(base, readOnly).effect).toBe('narrowing');
    expect(classifyPatch(base, [{ op: 'remove', path: '/weight-artifact/stores/s3' }]).effect).toBe('widening');

    const rebuilt = materializePolicies(applyPatch(base, readOnly), { previous: guard.getPolicies() });
    expect(rebuilt[0].evaluate(ctx({ targetMethod: 'PUT', targetUrl: 'https://huggingface.co/api/models/org/m', metadata: { artifactSha256: DIGEST, artifactBytes: 1 } })).code).toBe('artifact_write_not_allowed');
  });
});
