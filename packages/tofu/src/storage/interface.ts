import type { AgentIdentityStoredRow } from '../types.js';

export interface AgentIdentityBackend {
  init(): void | Promise<void>;
  insertAgent(row: AgentIdentityStoredRow): void | Promise<void>;
  getAgentByFingerprint(
    fingerprint: string,
    nowIso: string,
  ): AgentIdentityStoredRow | null | Promise<AgentIdentityStoredRow | null>;
  listAgents(nowIso: string): AgentIdentityStoredRow[] | Promise<AgentIdentityStoredRow[]>;
  updateAgent(row: AgentIdentityStoredRow): void | Promise<void>;
}
