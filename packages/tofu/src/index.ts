export { AgentVault, createAgentVault } from './agent-vault.js';
export { generateKeypair, fingerprintPublicKey, normalizePublicKey, verifySignature } from './keypair.js';
export { computeGraceExpiry, DEFAULT_ROTATION_GRACE_HOURS } from './rotation.js';
export { SQLiteBackend } from './storage/sqlite.js';
export { FileBackend } from './storage/file.js';
export type { AgentIdentityBackend } from './storage/interface.js';
export type {
  AgentStatus,
  AgentVaultOptions,
  RegisterAgentInput,
  ClaimAgentInput,
  RotateKeyInput,
  RotateKeyResult,
  AgentIdentityRow,
  AgentIdentityStoredRow,
  GeneratedKeypair,
} from './types.js';
