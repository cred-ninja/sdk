import fs from 'fs';
import path from 'path';
import type { AgentIdentityBackend } from './interface.js';
import type { AgentIdentityStoredRow } from '../types.js';

export class FileBackend implements AgentIdentityBackend {
  private readonly filePath: string;
  private readonly tempPath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.tempPath = `${filePath}.tmp`;
  }

  init(): void {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  insertAgent(row: AgentIdentityStoredRow): void {
    const data = this.readAll();
    data[row.agentId] = row;
    this.writeAll(data);
  }

  getAgentByFingerprint(fingerprint: string, nowIso: string): AgentIdentityStoredRow | null {
    const rows = Object.values(this.readAll());

    for (const row of rows) {
      if (row.fingerprint === fingerprint) {
        return row;
      }
      if (
        row.previousFingerprint === fingerprint &&
        row.rotationGraceExpiresAt !== null &&
        row.rotationGraceExpiresAt > nowIso
      ) {
        return row;
      }
    }

    return null;
  }

  listAgents(_nowIso: string): AgentIdentityStoredRow[] {
    return Object.values(this.readAll());
  }

  updateAgent(row: AgentIdentityStoredRow): void {
    const data = this.readAll();
    data[row.agentId] = row;
    this.writeAll(data);
  }

  private readAll(): Record<string, AgentIdentityStoredRow> {
    if (!fs.existsSync(this.filePath)) {
      return {};
    }

    try {
      return JSON.parse(fs.readFileSync(this.filePath, 'utf8')) as Record<string, AgentIdentityStoredRow>;
    } catch {
      throw new Error(`Failed to read TOFU identity file at ${this.filePath}`);
    }
  }

  private writeAll(data: Record<string, AgentIdentityStoredRow>): void {
    fs.writeFileSync(this.tempPath, JSON.stringify(data, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
    fs.renameSync(this.tempPath, this.filePath);
  }
}
