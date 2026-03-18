/**
 * AgentVault — TOFU (Trust-On-First-Use) agent identity vault.
 *
 * Stores Ed25519 public keys and fingerprints for agent identity management.
 * Public keys are NOT encrypted — they are not secret.
 * Uses the same backend infrastructure as CredVault.
 */

import { createHash, createPublicKey, verify, randomUUID } from 'node:crypto';
import { SQLiteBackend } from './storage/sqlite.js';
import { FileBackend } from './storage/file.js';
import type { StorageBackend, AgentIdentityStoredRow } from './storage/interface.js';
import type {
  VaultOptions,
  AgentIdentityRow,
  RegisterAgentInput,
  ClaimAgentInput,
} from './types.js';

/**
 * AgentVault — manages TOFU agent identities.
 *
 * Unlike CredVault, this does not encrypt stored data — public keys are not secret.
 * The passphrase is accepted for constructor compatibility with VaultOptions but
 * is not used for agent identity operations.
 */
export class AgentVault {
  private readonly backend: StorageBackend;
  private initPromise: Promise<void> | null = null;
  private initialized = false;

  constructor(options: VaultOptions) {
    if (options.storage === 'sqlite') {
      this.backend = new SQLiteBackend(options.path);
    } else if (options.storage === 'file') {
      this.backend = new FileBackend(options.path);
    } else {
      throw new Error(`Unknown storage backend: ${String(options.storage)}`);
    }
  }

  /**
   * Initialize the vault backend. Can be called explicitly, or will be called
   * automatically on first operation (lazy init).
   */
  async init(): Promise<void> {
    await this.backend.init();
    this.initialized = true;
  }

  /**
   * Lazy initialization — ensures init() has been called exactly once.
   */
  private async ensureInit(): Promise<void> {
    if (this.initialized) return;
    if (!this.initPromise) {
      this.initPromise = this.init();
    }
    await this.initPromise;
  }

  /**
   * Register a new agent identity.
   *
   * Generates a UUID agentId, computes the SHA-256 fingerprint of the
   * hex-encoded public key, and stores the identity in the backend.
   *
   * @param input - Public key and optional scopes/metadata
   * @returns The generated agentId and computed fingerprint
   */
  async registerAgent(input: RegisterAgentInput): Promise<{ agentId: string; fingerprint: string }> {
    await this.ensureInit();

    if (input.publicKey.length !== 32) {
      throw new Error('Invalid public key: must be 32 bytes (Ed25519)');
    }

    const agentId = randomUUID();
    const publicKeyHex = Buffer.from(input.publicKey).toString('hex');
    const fingerprint = createHash('sha256').update(publicKeyHex).digest('hex');
    const now = new Date().toISOString();

    const row: AgentIdentityStoredRow = {
      agentId,
      publicKey: publicKeyHex,
      fingerprint,
      status: 'unclaimed',
      ownerUserId: null,
      initialScopes: JSON.stringify(input.initialScopes ?? []),
      metadata: JSON.stringify(input.metadata ?? {}),
      createdAt: now,
      updatedAt: now,
    };

    await this.backend.registerAgent(row);

    return { agentId, fingerprint };
  }

  /**
   * Retrieve an agent identity by fingerprint.
   *
   * @param fingerprint - SHA-256 hex fingerprint of the public key
   * @returns Deserialized agent identity row, or null if not found
   */
  async getAgent(fingerprint: string): Promise<AgentIdentityRow | null> {
    await this.ensureInit();

    const row = await this.backend.getAgent(fingerprint);
    if (!row) return null;

    return deserializeAgent(row);
  }

  /**
   * Claim an agent identity — sets status to "claimed" and assigns an owner.
   *
   * @param input - Fingerprint and ownerUserId
   */
  async claimAgent(input: ClaimAgentInput): Promise<void> {
    await this.ensureInit();

    const now = new Date().toISOString();
    await this.backend.claimAgent(input.fingerprint, input.ownerUserId, now);
  }

  /**
   * Verify an Ed25519 signature against a stored agent's public key.
   *
   * Looks up the agent by fingerprint, reconstructs the Ed25519 public key,
   * and verifies the signature over the payload.
   *
   * @param fingerprint - SHA-256 hex fingerprint of the agent's public key
   * @param payload - The data that was signed
   * @param signature - The Ed25519 signature to verify
   * @returns true if valid, false if invalid or agent not found
   */
  async verifyAgentSignature(
    fingerprint: string,
    payload: Buffer,
    signature: Buffer,
  ): Promise<boolean> {
    await this.ensureInit();

    const row = await this.backend.getAgent(fingerprint);
    if (!row) return false;

    try {
      // Reconstruct Ed25519 public key from raw bytes
      // Same pattern as packages/sdk/src/identity.ts verifyDelegationReceipt
      const spkiDer = Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'), // Ed25519 SPKI prefix
        Buffer.from(row.publicKey, 'hex'),
      ]);
      const keyObj = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

      return verify(null, payload, keyObj, signature);
    } catch {
      return false;
    }
  }
}

/**
 * Deserialize a stored agent row into the public AgentIdentityRow type.
 */
function deserializeAgent(row: AgentIdentityStoredRow): AgentIdentityRow {
  return {
    agentId: row.agentId,
    publicKey: row.publicKey,
    fingerprint: row.fingerprint,
    status: row.status as 'unclaimed' | 'claimed',
    ownerUserId: row.ownerUserId,
    initialScopes: JSON.parse(row.initialScopes) as string[],
    metadata: JSON.parse(row.metadata) as Record<string, unknown>,
    createdAt: new Date(row.createdAt),
    updatedAt: new Date(row.updatedAt),
  };
}

/**
 * Factory: create and initialize an AgentVault in one async call.
 *
 * @example
 * const vault = await createAgentVault({
 *   passphrase: 'unused-for-agents',
 *   storage: 'sqlite',
 *   path: './agent-vault.db',
 * });
 */
export async function createAgentVault(options: VaultOptions): Promise<AgentVault> {
  const vault = new AgentVault(options);
  await vault.init();
  return vault;
}
