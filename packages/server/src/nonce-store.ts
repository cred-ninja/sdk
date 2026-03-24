/**
 * @credninja/server — Web Bot Auth Nonce Store
 *
 * Supports process-local memory mode and shared SQLite mode for replay defense.
 */

export interface WebBotAuthNonceStore {
  remember(input: {
    signatureAgent: string;
    keyId: string;
    nonce: string;
    expiresAtSeconds: number;
  }): void;
}

class MemoryWebBotAuthNonceStore implements WebBotAuthNonceStore {
  private readonly nonces = new Map<string, number>();

  remember(input: {
    signatureAgent: string;
    keyId: string;
    nonce: string;
    expiresAtSeconds: number;
  }): void {
    const now = Date.now();
    for (const [cacheKey, cacheExpiresAt] of this.nonces) {
      if (cacheExpiresAt <= now) {
        this.nonces.delete(cacheKey);
      }
    }

    const nonceKey = `${input.signatureAgent}|${input.keyId}|${input.nonce}`;
    if (this.nonces.has(nonceKey)) {
      throw new Error('Web Bot Auth nonce has already been used');
    }

    this.nonces.set(nonceKey, input.expiresAtSeconds * 1000);
  }
}

class SQLiteWebBotAuthNonceStore implements WebBotAuthNonceStore {
  private readonly db: import('better-sqlite3').Database;

  constructor(dbPath: string) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const Database = require('better-sqlite3') as typeof import('better-sqlite3');
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS web_bot_auth_nonces (
        nonce_key    TEXT PRIMARY KEY,
        expires_at   INTEGER NOT NULL,
        created_at   INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_web_bot_auth_nonces_expires_at
      ON web_bot_auth_nonces(expires_at);
    `);
  }

  remember(input: {
    signatureAgent: string;
    keyId: string;
    nonce: string;
    expiresAtSeconds: number;
  }): void {
    const now = Date.now();
    const nonceKey = `${input.signatureAgent}|${input.keyId}|${input.nonce}`;
    const expiresAtMs = input.expiresAtSeconds * 1000;

    const tx = this.db.transaction(() => {
      this.db.prepare('DELETE FROM web_bot_auth_nonces WHERE expires_at <= ?').run(now);
      try {
        this.db.prepare(`
          INSERT INTO web_bot_auth_nonces (nonce_key, expires_at, created_at)
          VALUES (?, ?, ?)
        `).run(nonceKey, expiresAtMs, now);
      } catch (error) {
        if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
          throw new Error('Web Bot Auth nonce has already been used');
        }
        throw error;
      }
    });

    tx();
  }
}

export function createWebBotAuthNonceStore(config: {
  store: 'memory' | 'sqlite';
  path?: string;
}): WebBotAuthNonceStore {
  if (config.store === 'sqlite') {
    if (!config.path) {
      throw new Error('Web Bot Auth SQLite nonce store requires a path');
    }
    return new SQLiteWebBotAuthNonceStore(config.path);
  }

  return new MemoryWebBotAuthNonceStore();
}
