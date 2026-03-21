import { randomUUID } from 'node:crypto';
import { FileBackend } from './storage/file.js';
import { SQLiteBackend } from './storage/sqlite.js';
import type { AgentIdentityBackend } from './storage/interface.js';
import {
  fingerprintPublicKey,
  normalizePublicKey,
  publicKeyHexToBytes,
  verifySignature as verifySignatureWithPublicKey,
} from './keypair.js';
import { computeGraceExpiry } from './rotation.js';
import type {
  AgentIdentityRow,
  AgentIdentityStoredRow,
  AgentVaultOptions,
  ClaimAgentInput,
  RegisterAgentInput,
  RotateKeyInput,
  RotateKeyResult,
} from './types.js';

export class AgentVault {
  private readonly backend: AgentIdentityBackend;
  private initPromise: Promise<void> | null = null;
  private initialized = false;

  constructor(options: AgentVaultOptions) {
    if (options.storage === 'sqlite') {
      this.backend = new SQLiteBackend(options.path);
    } else if (options.storage === 'file') {
      this.backend = new FileBackend(options.path);
    } else {
      throw new Error(`Unknown storage backend: ${String(options.storage)}`);
    }
  }

  async init(): Promise<void> {
    await this.backend.init();
    this.initialized = true;
  }

  async registerAgent(input: RegisterAgentInput): Promise<{ agentId: string; fingerprint: string }> {
    await this.ensureInit();

    const now = new Date().toISOString();
    const publicKey = normalizePublicKey(input.publicKey);
    const fingerprint = fingerprintPublicKey(input.publicKey);
    const row: AgentIdentityStoredRow = {
      agentId: randomUUID(),
      publicKey,
      fingerprint,
      status: 'unclaimed',
      ownerUserId: null,
      initialScopes: JSON.stringify(input.initialScopes ?? []),
      metadata: JSON.stringify(input.metadata ?? {}),
      createdAt: now,
      updatedAt: now,
      claimedAt: null,
      revokedAt: null,
      previousPublicKey: null,
      previousFingerprint: null,
      rotationGraceExpiresAt: null,
    };

    await this.backend.insertAgent(row);
    return { agentId: row.agentId, fingerprint: row.fingerprint };
  }

  async getAgent(fingerprint: string): Promise<AgentIdentityRow | null> {
    await this.ensureInit();
    const row = await this.backend.getAgentByFingerprint(fingerprint, new Date().toISOString());
    if (!row) {
      return null;
    }
    return deserializeRow(row);
  }

  async claimAgent(input: ClaimAgentInput): Promise<void> {
    await this.ensureInit();
    const row = await this.getExistingAgent(input.fingerprint);

    if (row.status === 'revoked') {
      throw new Error('Revoked agents cannot be claimed');
    }
    if (row.status === 'claimed') {
      throw new Error('Agent is already claimed');
    }

    const now = new Date().toISOString();
    row.status = 'claimed';
    row.ownerUserId = input.ownerUserId;
    row.claimedAt = now;
    row.updatedAt = now;
    await this.backend.updateAgent(row);
  }

  async revokeAgent(fingerprint: string): Promise<void> {
    await this.ensureInit();
    const row = await this.getExistingAgent(fingerprint);
    if (row.status === 'revoked') {
      return;
    }

    const now = new Date().toISOString();
    row.status = 'revoked';
    row.revokedAt = now;
    row.updatedAt = now;
    await this.backend.updateAgent(row);
  }

  async verifySignature(
    fingerprint: string,
    payload: Uint8Array | Buffer,
    signature: Uint8Array | Buffer,
  ): Promise<boolean> {
    await this.ensureInit();
    const now = new Date();
    const row = await this.backend.getAgentByFingerprint(fingerprint, now.toISOString());
    if (!row || row.status === 'revoked') {
      return false;
    }

    const keyHex = this.resolvePublicKeyHex(row, fingerprint, now);
    if (!keyHex) {
      return false;
    }

    return verifySignatureWithPublicKey(publicKeyHexToBytes(keyHex), payload, signature);
  }

  async rotateKey(input: RotateKeyInput): Promise<RotateKeyResult> {
    await this.ensureInit();
    const row = await this.getExistingAgent(input.fingerprint);
    if (row.status === 'revoked') {
      throw new Error('Revoked agents cannot rotate keys');
    }
    if (row.fingerprint !== input.fingerprint) {
      throw new Error('Key rotation requires the current fingerprint');
    }

    const newFingerprint = fingerprintPublicKey(input.newPublicKey);
    if (newFingerprint === row.fingerprint) {
      throw new Error('New public key must differ from the current key');
    }

    const now = new Date();
    const graceExpiresAt = computeGraceExpiry(now, input.gracePeriodHours);
    const previousFingerprint = row.fingerprint;

    row.previousPublicKey = row.publicKey;
    row.previousFingerprint = row.fingerprint;
    row.publicKey = normalizePublicKey(input.newPublicKey);
    row.fingerprint = newFingerprint;
    row.rotationGraceExpiresAt = graceExpiresAt.toISOString();
    row.updatedAt = now.toISOString();

    await this.backend.updateAgent(row);

    return {
      agentId: row.agentId,
      fingerprint: row.fingerprint,
      previousFingerprint,
      graceExpiresAt,
    };
  }

  private async ensureInit(): Promise<void> {
    if (this.initialized) {
      return;
    }
    if (!this.initPromise) {
      this.initPromise = this.init();
    }
    await this.initPromise;
  }

  private async getExistingAgent(fingerprint: string): Promise<AgentIdentityStoredRow> {
    const row = await this.backend.getAgentByFingerprint(fingerprint, new Date().toISOString());
    if (!row) {
      throw new Error(`Agent not found for fingerprint ${fingerprint}`);
    }
    return row;
  }

  private resolvePublicKeyHex(
    row: AgentIdentityStoredRow,
    fingerprint: string,
    now: Date,
  ): string | null {
    if (row.fingerprint === fingerprint) {
      return row.publicKey;
    }

    if (
      row.previousFingerprint === fingerprint &&
      row.previousPublicKey &&
      row.rotationGraceExpiresAt &&
      row.rotationGraceExpiresAt > now.toISOString()
    ) {
      return row.previousPublicKey;
    }

    return null;
  }
}

export async function createAgentVault(options: AgentVaultOptions): Promise<AgentVault> {
  const vault = new AgentVault(options);
  await vault.init();
  return vault;
}

function deserializeRow(row: AgentIdentityStoredRow): AgentIdentityRow {
  return {
    agentId: row.agentId,
    publicKey: row.publicKey,
    fingerprint: row.fingerprint,
    status: row.status,
    ownerUserId: row.ownerUserId,
    initialScopes: JSON.parse(row.initialScopes) as string[],
    metadata: JSON.parse(row.metadata) as Record<string, unknown>,
    createdAt: new Date(row.createdAt),
    updatedAt: new Date(row.updatedAt),
    claimedAt: row.claimedAt ? new Date(row.claimedAt) : null,
    revokedAt: row.revokedAt ? new Date(row.revokedAt) : null,
    previousFingerprint: row.previousFingerprint,
    rotationGraceExpiresAt: row.rotationGraceExpiresAt ? new Date(row.rotationGraceExpiresAt) : null,
  };
}
