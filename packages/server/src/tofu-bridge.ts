import { AgentVault } from '@credninja/tofu';
import type { AgentIdentityRow } from '@credninja/tofu';
import type { Permission } from '@credninja/vault';

export interface AgentPrincipal {
  type: 'tofu';
  principalId: string;
  agentId: string;
  fingerprint: string;
  status: 'unclaimed' | 'claimed' | 'revoked';
  ownerUserId: string | null;
  bootstrapScopes: string[];
}

export interface TofuProofInput {
  fingerprint: string;
  payloadBase64: string;
  signatureBase64: string;
}

export interface TofuDelegationPayload {
  service: string;
  userId: string;
  appClientId: string;
  scopes?: string[];
  timestamp: string;
}

export interface ResolvedTofuIdentity {
  principal: AgentPrincipal;
  payload: TofuDelegationPayload;
}

const MAX_PROOF_SKEW_MS = 5 * 60 * 1000;

export async function resolveTofuPrincipal(
  tofu: AgentVault,
  proof: TofuProofInput,
  expected: {
    service: string;
    userId: string;
    appClientId: string;
    requestedScopes?: string[];
  },
  now = new Date(),
): Promise<ResolvedTofuIdentity> {
  const payloadBuffer = decodeBase64(proof.payloadBase64, 'Invalid tofu_payload');
  const signatureBuffer = decodeBase64(proof.signatureBase64, 'Invalid tofu_signature');

  const valid = await tofu.verifySignature(proof.fingerprint, payloadBuffer, signatureBuffer);
  if (!valid) {
    throw new Error('Invalid TOFU signature');
  }

  const payload = parseDelegationPayload(payloadBuffer);
  assertPayloadMatchesExpectation(payload, expected, now);

  const identity = await tofu.getAgent(proof.fingerprint);
  if (!identity) {
    throw new Error('TOFU identity not found');
  }
  if (identity.status === 'revoked') {
    throw new Error('TOFU identity has been revoked');
  }

  return {
    principal: identityToPrincipal(identity),
    payload,
  };
}

export function computeTofuAuthorization(
  principal: AgentPrincipal,
  permission: Permission | null,
): { allowedScopes: string[]; permissionRequired: boolean } {
  if (principal.status === 'revoked') {
    throw new Error('TOFU identity has been revoked');
  }

  if (principal.status === 'claimed') {
    if (!permission) {
      throw new Error('Claimed TOFU identity has no permission');
    }
    return {
      allowedScopes: permission.allowedScopes,
      permissionRequired: true,
    };
  }

  if (principal.bootstrapScopes.length === 0 && !permission) {
    throw new Error('Unclaimed TOFU identity has no bootstrap scopes or permission');
  }

  const allowedScopes = permission
    ? principal.bootstrapScopes.length > 0
      ? permission.allowedScopes.filter((scope) => principal.bootstrapScopes.includes(scope))
      : permission.allowedScopes
    : principal.bootstrapScopes;

  return {
    allowedScopes,
    permissionRequired: false,
  };
}

export function identityToPrincipal(identity: AgentIdentityRow): AgentPrincipal {
  return {
    type: 'tofu',
    principalId: toTofuPrincipalId(identity.agentId),
    agentId: identity.agentId,
    fingerprint: identity.fingerprint,
    status: identity.status,
    ownerUserId: identity.ownerUserId,
    bootstrapScopes: identity.initialScopes,
  };
}

export function toTofuPrincipalId(agentId: string): string {
  return `tofu:${agentId}`;
}

function assertPayloadMatchesExpectation(
  payload: TofuDelegationPayload,
  expected: {
    service: string;
    userId: string;
    appClientId: string;
    requestedScopes?: string[];
  },
  now: Date,
): void {
  if (payload.service !== expected.service) {
    throw new Error('TOFU payload service does not match request');
  }
  if (payload.userId !== expected.userId) {
    throw new Error('TOFU payload userId does not match request');
  }
  if (payload.appClientId !== expected.appClientId) {
    throw new Error('TOFU payload appClientId does not match request');
  }

  const payloadScopes = normalizeScopes(payload.scopes);
  const expectedScopes = normalizeScopes(expected.requestedScopes);
  if (payloadScopes.length !== expectedScopes.length || payloadScopes.some((scope, idx) => scope !== expectedScopes[idx])) {
    throw new Error('TOFU payload scopes do not match request');
  }

  const timestamp = new Date(payload.timestamp);
  if (Number.isNaN(timestamp.getTime())) {
    throw new Error('TOFU payload timestamp is invalid');
  }
  if (Math.abs(now.getTime() - timestamp.getTime()) > MAX_PROOF_SKEW_MS) {
    throw new Error('TOFU payload timestamp is outside the allowed window');
  }
}

function parseDelegationPayload(payload: Buffer): TofuDelegationPayload {
  try {
    const parsed = JSON.parse(payload.toString('utf8')) as TofuDelegationPayload;
    if (
      !parsed ||
      typeof parsed.service !== 'string' ||
      typeof parsed.userId !== 'string' ||
      typeof parsed.appClientId !== 'string' ||
      typeof parsed.timestamp !== 'string'
    ) {
      throw new Error('invalid shape');
    }
    if (parsed.scopes !== undefined && !Array.isArray(parsed.scopes)) {
      throw new Error('invalid scopes');
    }
    return parsed;
  } catch {
    throw new Error('Invalid TOFU payload');
  }
}

function decodeBase64(value: string, errorMessage: string): Buffer {
  try {
    return Buffer.from(value, 'base64');
  } catch {
    throw new Error(errorMessage);
  }
}

function normalizeScopes(scopes?: string[]): string[] {
  return [...(scopes ?? [])].sort();
}
