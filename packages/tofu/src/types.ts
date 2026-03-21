export type AgentStatus = 'unclaimed' | 'claimed' | 'revoked';

export interface AgentVaultOptions {
  storage: 'sqlite' | 'file';
  path: string;
}

export interface RegisterAgentInput {
  publicKey: Uint8Array;
  initialScopes?: string[];
  metadata?: Record<string, unknown>;
}

export interface ClaimAgentInput {
  fingerprint: string;
  ownerUserId: string;
}

export interface RotateKeyInput {
  fingerprint: string;
  newPublicKey: Uint8Array;
  gracePeriodHours?: number;
}

export interface RotateKeyResult {
  agentId: string;
  fingerprint: string;
  previousFingerprint: string;
  graceExpiresAt: Date;
}

export interface AgentIdentityRow {
  agentId: string;
  publicKey: string;
  fingerprint: string;
  status: AgentStatus;
  ownerUserId: string | null;
  initialScopes: string[];
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
  claimedAt: Date | null;
  revokedAt: Date | null;
  previousFingerprint: string | null;
  rotationGraceExpiresAt: Date | null;
}

export interface AgentIdentityStoredRow {
  agentId: string;
  publicKey: string;
  fingerprint: string;
  status: AgentStatus;
  ownerUserId: string | null;
  initialScopes: string;
  metadata: string;
  createdAt: string;
  updatedAt: string;
  claimedAt: string | null;
  revokedAt: string | null;
  previousPublicKey: string | null;
  previousFingerprint: string | null;
  rotationGraceExpiresAt: string | null;
}

export interface GeneratedKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  fingerprint: string;
}
