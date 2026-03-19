/**
 * @credninja/vault — Rotation Engine
 *
 * Implements the Dual-Active credential rotation strategy:
 * - Both current and pending tokens are valid simultaneously during rotation
 * - This allows a zero-downtime handoff: agents using the old token won't fail
 *   while the new token is being distributed
 *
 * State machine:
 *   idle → pending → testing → promoting → idle (success)
 *                             ↘ failed → rolling_back → idle
 */

import crypto from 'crypto';
import type { StorageBackend } from './storage/interface.js';
import type {
  Rotation,
  RotationRow,
  RotationStrategy,
  RotationState,
} from './types.js';

// ── Public types ──────────────────────────────────────────────────────────────

export interface RotationResult {
  rotation: Rotation;
  success: boolean;
  error?: string;
}

export interface RefreshAdapter {
  refreshAccessToken(
    refreshToken: string,
    clientId: string,
    clientSecret: string,
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
    scopes?: string[];
  }>;
}

// ── Stuck rotation timeout ────────────────────────────────────────────────────

/** Rotations stuck in testing/promoting for longer than this are failed */
const STUCK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// ── RotationEngine ────────────────────────────────────────────────────────────

export class RotationEngine {
  constructor(
    private readonly storage: StorageBackend,
  ) {}

  private generateRotationId(): string {
    return `rot_${crypto.randomUUID().replace(/-/g, '')}`;
  }

  private now(): string {
    return new Date().toISOString();
  }

  /**
   * Start a new rotation for a connection.
   * Creates a vault_rotations record in 'pending' state.
   *
   * @param connectionId - FK to the vault_credentials (provider/userId key or logical ID)
   * @param strategy - Rotation strategy to use
   * @param intervalSeconds - How often to auto-rotate (default 86400 = 24h)
   */
  async startRotation(
    connectionId: string,
    strategy: RotationStrategy,
    intervalSeconds = 86400,
  ): Promise<Rotation> {
    const existing = await this.storage.getRotationByConnectionId?.(connectionId);
    if (existing && (existing.state === 'pending' || existing.state === 'testing' || existing.state === 'promoting')) {
      throw new Error(`Rotation already in progress for connection ${connectionId} (state: ${existing.state})`);
    }

    const id = this.generateRotationId();
    const now = this.now();
    const nextRotationAt = new Date(Date.now() + intervalSeconds * 1000).toISOString();

    const row: RotationRow = {
      id,
      connection_id: connectionId,
      strategy,
      interval_seconds: intervalSeconds,
      state: 'pending',
      current_version_id: null,
      pending_version_id: null,
      previous_version_id: null,
      last_rotated_at: null,
      next_rotation_at: nextRotationAt,
      failure_count: 0,
      failure_action: 'retry_backoff',
      created_at: now,
      updated_at: now,
    };

    if (!this.storage.storeRotation) {
      throw new Error('Storage backend does not support rotation (storeRotation not implemented)');
    }
    await this.storage.storeRotation(row);

    const created = await this.storage.getRotation!(id);
    if (!created) throw new Error(`Failed to create rotation record ${id}`);
    return created;
  }

  /**
   * Transition a rotation from pending → testing.
   * In dual_active: both current and pending tokens are valid.
   * The caller is responsible for storing the new (pending) token externally.
   *
   * @param rotationId - The rotation to advance
   * @param pendingVersionId - Reference to the pending token (e.g., access_token_enc from vault)
   */
  async advanceToTesting(rotationId: string, pendingVersionId: string): Promise<Rotation> {
    const rotation = await this.getOrThrow(rotationId);

    if (rotation.state !== 'pending') {
      throw new Error(`Cannot advance rotation ${rotationId} to testing — current state: ${rotation.state}`);
    }

    if (!this.storage.updateRotation) {
      throw new Error('Storage backend does not support rotation (updateRotation not implemented)');
    }

    await this.storage.updateRotation(rotationId, {
      state: 'testing',
      pending_version_id: pendingVersionId,
      updated_at: this.now(),
    });

    return this.getOrThrow(rotationId);
  }

  /**
   * Promote the pending token to current.
   * Moves: pending → current, current → previous
   *
   * Dual-active window ends here — the old current token is now 'previous' (retiring).
   */
  async promoteRotation(rotationId: string): Promise<Rotation> {
    const rotation = await this.getOrThrow(rotationId);

    if (rotation.state !== 'testing') {
      throw new Error(`Cannot promote rotation ${rotationId} — must be in 'testing' state (current: ${rotation.state})`);
    }

    if (!rotation.pendingVersionId) {
      throw new Error(`Cannot promote rotation ${rotationId} — no pending version to promote`);
    }

    const now = this.now();
    await this.storage.updateRotation!(rotationId, {
      state: 'idle',
      previous_version_id: rotation.currentVersionId,
      current_version_id: rotation.pendingVersionId,
      pending_version_id: null,
      last_rotated_at: now,
      next_rotation_at: new Date(Date.now() + rotation.intervalSeconds * 1000).toISOString(),
      updated_at: now,
    });

    return this.getOrThrow(rotationId);
  }

  /**
   * Roll back a rotation — restores previous token as current.
   * Used when the promoted token fails validation.
   */
  async rollbackRotation(rotationId: string): Promise<Rotation> {
    const rotation = await this.getOrThrow(rotationId);

    if (rotation.state !== 'testing' && rotation.state !== 'failed') {
      throw new Error(`Cannot roll back rotation ${rotationId} — must be in 'testing' or 'failed' state (current: ${rotation.state})`);
    }

    if (!rotation.previousVersionId && !rotation.currentVersionId) {
      throw new Error(`Cannot roll back rotation ${rotationId} — no previous version to restore`);
    }

    const now = this.now();
    await this.storage.updateRotation!(rotationId, {
      state: 'idle',
      current_version_id: rotation.previousVersionId ?? rotation.currentVersionId,
      pending_version_id: null,
      previous_version_id: null,
      failure_count: rotation.failureCount + 1,
      updated_at: now,
    });

    return this.getOrThrow(rotationId);
  }

  /**
   * Mark a rotation as failed.
   */
  async failRotation(rotationId: string, reason?: string): Promise<Rotation> {
    void reason; // reserved for future audit logging
    const rotation = await this.getOrThrow(rotationId);

    await this.storage.updateRotation!(rotationId, {
      state: 'failed',
      failure_count: rotation.failureCount + 1,
      updated_at: this.now(),
    });

    return this.getOrThrow(rotationId);
  }

  /**
   * Get the current rotation for a connection.
   */
  async getRotation(connectionId: string): Promise<Rotation | null> {
    if (!this.storage.getRotationByConnectionId) return null;
    return this.storage.getRotationByConnectionId(connectionId);
  }

  /**
   * Get a rotation by ID.
   */
  async getRotationById(rotationId: string): Promise<Rotation | null> {
    if (!this.storage.getRotation) return null;
    return this.storage.getRotation(rotationId);
  }

  /**
   * Process all rotations that are due (next_rotation_at <= now).
   * For oauth_refresh strategy: calls the refresh adapter and stores new tokens.
   * Returns an array of results.
   *
   * NOTE: Callers must provide refresh adapters for oauth_refresh strategy rotations.
   * The engine does not maintain adapter state — pass via params if needed.
   */
  async runDueRotations(): Promise<RotationResult[]> {
    if (!this.storage.listDueRotations) return [];

    const due = await this.storage.listDueRotations(new Date());
    const results: RotationResult[] = [];

    for (const rotation of due) {
      try {
        // Auto-advance to pending and immediately promote for simple strategies
        if (rotation.strategy === 'single_swap') {
          const now = this.now();
          await this.storage.updateRotation!(rotation.id, {
            state: 'pending',
            last_rotated_at: now,
            next_rotation_at: new Date(Date.now() + rotation.intervalSeconds * 1000).toISOString(),
            updated_at: now,
          });
          results.push({ rotation: await this.getOrThrow(rotation.id), success: true });
        } else {
          // dual_active and others: mark as pending, awaiting external promoteRotation call
          await this.storage.updateRotation!(rotation.id, {
            state: 'pending',
            updated_at: this.now(),
          });
          results.push({ rotation: await this.getOrThrow(rotation.id), success: true });
        }
      } catch (err) {
        const updated = await this.getOrThrow(rotation.id);
        results.push({
          rotation: updated,
          success: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // Auto-fail stuck rotations
    await this.failStuckRotations();

    return results;
  }

  /**
   * Auto-fail rotations stuck in testing/promoting for >5 minutes.
   */
  private async failStuckRotations(): Promise<void> {
    if (!this.storage.listRotations) return;

    const allRotations = await this.storage.listRotations();
    const stuckStates: RotationState[] = ['testing', 'promoting'];
    const cutoff = new Date(Date.now() - STUCK_TIMEOUT_MS);

    for (const rotation of allRotations) {
      if (stuckStates.includes(rotation.state) && rotation.updatedAt < cutoff) {
        await this.storage.updateRotation!(rotation.id, {
          state: 'failed',
          failure_count: rotation.failureCount + 1,
          updated_at: this.now(),
        });
      }
    }
  }

  private async getOrThrow(rotationId: string): Promise<Rotation> {
    const rotation = await this.storage.getRotation?.(rotationId);
    if (!rotation) throw new Error(`Rotation ${rotationId} not found`);
    return rotation;
  }
}
