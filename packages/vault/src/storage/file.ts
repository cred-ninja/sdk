import fs from 'fs';
import path from 'path';
import type { StorageBackend } from './interface.js';
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

  private readAll(): Record<string, StoredRow> {
    if (!fs.existsSync(this.filePath)) {
      return {};
    }

    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      return JSON.parse(raw) as Record<string, StoredRow>;
    } catch {
      // Corrupted file — treat as empty (don't silently leak)
      throw new Error(`Failed to read vault file at ${this.filePath} — file may be corrupted`);
    }
  }

  private writeAll(data: Record<string, StoredRow>): void {
    const json = JSON.stringify(data, null, 2);

    // Atomic write: write to temp file, then rename
    fs.writeFileSync(this.tempPath, json, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(this.tempPath, this.filePath);
  }

  private rowKey(provider: string, userId: string): string {
    return `${provider}::${userId}`;
  }

  store(row: StoredRow): void {
    const data = fs.existsSync(this.filePath) ? this.readAll() : {};
    data[this.rowKey(row.provider, row.userId)] = row;
    this.writeAll(data);
  }

  get(provider: string, userId: string): StoredRow | null {
    if (!fs.existsSync(this.filePath)) {
      return null;
    }

    const data = this.readAll();
    const row = data[this.rowKey(provider, userId)] ?? null;
    if (!row) return null;

    // Filter out expired rows that have no refresh token
    // (expired rows with refresh tokens are kept so vault can attempt auto-refresh)
    if (row.expiresAt) {
      const expiresAt = new Date(row.expiresAt);
      const hasRefreshToken = !!row.refreshTokenEnc;
      if (!isNaN(expiresAt.getTime()) && expiresAt <= new Date() && !hasRefreshToken) {
        return null;
      }
    }

    return row;
  }

  delete(provider: string, userId: string): void {
    if (!fs.existsSync(this.filePath)) {
      return; // idempotent
    }

    const data = this.readAll();
    delete data[this.rowKey(provider, userId)];
    this.writeAll(data);
  }

  list(userId: string): StoredRow[] {
    if (!fs.existsSync(this.filePath)) {
      return [];
    }

    const data = this.readAll();
    return Object.values(data).filter((row) => row.userId === userId);
  }
}
