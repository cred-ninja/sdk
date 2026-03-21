import { createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAgentVault, generateKeypair } from '../index.js';

describe.each([
  { name: 'file', file: 'rotation.json' },
  { name: 'sqlite', file: 'rotation.sqlite' },
])('rotation (%s)', ({ name, file }) => {
  let tmpDir: string;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-21T12:00:00.000Z'));
    tmpDir = mkdtempSync(join(tmpdir(), 'tofu-rotation-'));
  });

  afterEach(() => {
    vi.useRealTimers();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('accepts the previous key during the grace window and expires it afterward', async () => {
    const vault = await createAgentVault({
      storage: name,
      path: join(tmpDir, file),
    });
    const original = await generateKeypair();
    const rotated = await generateKeypair();

    const originalPrivateKey = createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.from(original.privateKey),
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const rotatedPrivateKey = createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.from(rotated.privateKey),
      ]),
      format: 'der',
      type: 'pkcs8',
    });

    const registered = await vault.registerAgent({ publicKey: original.publicKey });
    const payload = Buffer.from('rotation payload');
    const oldSignature = sign(null, payload, originalPrivateKey);

    const rotation = await vault.rotateKey({
      fingerprint: registered.fingerprint,
      newPublicKey: rotated.publicKey,
      gracePeriodHours: 1,
    });

    expect(rotation.previousFingerprint).toBe(registered.fingerprint);
    expect(rotation.fingerprint).not.toBe(registered.fingerprint);

    expect(await vault.verifySignature(registered.fingerprint, payload, oldSignature)).toBe(true);
    const newSignature = sign(null, payload, rotatedPrivateKey);
    expect(await vault.verifySignature(rotation.fingerprint, payload, newSignature)).toBe(true);

    vi.setSystemTime(new Date('2026-03-21T13:01:00.000Z'));

    expect(await vault.verifySignature(registered.fingerprint, payload, oldSignature)).toBe(false);
    expect(await vault.getAgent(registered.fingerprint)).toBeNull();
    expect((await vault.getAgent(rotation.fingerprint))?.previousFingerprint).toBe(registered.fingerprint);
  });
});
