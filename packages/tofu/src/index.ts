export { AgentVault, createAgentVault, agentIdentityToDirectoryJwk, agentIdentityToDirectoryJwks } from './agent-vault.js';
export {
  generateKeypair,
  fingerprintPublicKey,
  normalizePublicKey,
  publicKeyToJwk,
  publicKeyToJwkThumbprint,
  publicKeyToJwkWithKid,
  jwkThumbprint,
  verifySignature,
} from './keypair.js';
export type { Ed25519Jwk, Ed25519JwkWithKid } from './keypair.js';
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
