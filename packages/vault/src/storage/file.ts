import fs from 'fs';
import path from 'path';
import type { StorageBackend, AgentIdentityStoredRow } from './interface.js';
import type { StoredRow } from '../types.js';

/**
 * File-based storage backend — zero additional dependencies.
 *
 * Stores an encrypted JSON structure where each row's token fields
 * are individually encrypted. The file itself is JSON (readable structure),
 * but all sensitive values are AES-256-GCM ciphertext stored as hex strings.
 *
 * Atomic writes: data is written to a temp file and renamed, preventing
 * corrupt state if the process dies mid-write.
 */
export class FileBackend implements StorageBackend {
  private readonly filePath: string;
  private readonly tempPath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.tempPath = filePath + '.tmp';
  }

  init(): void {
    // Ensure parent directory exists
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    // File itself is created on first store() — nothing to do here
  }

  private readAll(): { credentials: Record<string, StoredRow>; agents: Record<string, AgentIdentityStoredRow> } {
    if (!fs.existsSync(this.filePath)) {
      return { credentials: {}, agents: {} };
    }

    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const parsed: unknown = JSON.parse(raw);

      // Backwards compatibility: old files are flat Record<string, StoredRow>
      if (parsed !== null && typeof parsed === 'object' && !('credentials' in (parsed as Record<string, unknown>))) {
        return { credentials: parsed as Record<string, StoredRow>, agents: {} };
      }

      const data = parsed as { credentials: Record<string, StoredRow>; agents?: Record<string, AgentIdentityStoredRow> };
      return { credentials: data.credentials, agents: data.agents ?? {} };
    } catch {
      throw new Error(`Failed to read vault file at ${this.filePath} — file may be corrupted`);
    }
  }

  private writeAll(data: { credentials: Record<string, StoredRow>; agents: Record<string, AgentIdentityStoredRow> }): void {
    const json = JSON.stringify(data, null, 2);

    // Atomic write: write to temp file, then rename
    fs.writeFileSync(this.tempPath, json, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(this.tempPath, this.filePath);
  }

  private rowKey(provider: string, userId: string): string {
    return `${provider}::${userId}`;
  }

  store(row: StoredRow): void {
    const data = this.readAll();
    data.credentials[this.rowKey(row.provider, row.userId)] = row;
    this.writeAll(data);
  }

  get(provider: string, userId: string): StoredRow | null {
    if (!fs.existsSync(this.filePath)) {
      return null;
    }

    const data = this.readAll();
    return data.credentials[this.rowKey(provider, userId)] ?? null;
  }

  delete(provider: string, userId: string): void {
    if (!fs.existsSync(this.filePath)) {
      return; // idempotent
    }

    const data = this.readAll();
    delete data.credentials[this.rowKey(provider, userId)];
    this.writeAll(data);
  }

  list(userId: string): StoredRow[] {
    if (!fs.existsSync(this.filePath)) {
      return [];
    }

    const data = this.readAll();
    return Object.values(data.credentials).filter((row) => row.userId === userId);
  }

  // ── Agent Identity (TOFU) ──────────────────────────────────────────────────

  registerAgent(row: AgentIdentityStoredRow): void {
    const data = this.readAll();
    data.agents[row.fingerprint] = row;
    this.writeAll(data);
  }

  getAgent(fingerprint: string): AgentIdentityStoredRow | null {
    if (!fs.existsSync(this.filePath)) {
      return null;
    }

    const data = this.readAll();
    return data.agents[fingerprint] ?? null;
  }

  claimAgent(fingerprint: string, ownerUserId: string, updatedAt: string): void {
    const data = this.readAll();
    const agent = data.agents[fingerprint];
    if (agent) {
      agent.status = 'claimed';
      agent.ownerUserId = ownerUserId;
      agent.updatedAt = updatedAt;
      this.writeAll(data);
    }
  }

  listAgents(ownerUserId: string): AgentIdentityStoredRow[] {
    if (!fs.existsSync(this.filePath)) {
      return [];
    }

    const data = this.readAll();
    return Object.values(data.agents).filter((row) => row.ownerUserId === ownerUserId);
  }
}
