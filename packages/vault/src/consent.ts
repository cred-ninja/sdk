/**
 * Consent records (draft-sweeney-wimse-credential-delegation-02 Section
 * 8.2): an immutable record of each consent event, which every root
 * Delegation Token names in `consent_id`. A record is written once and
 * never updated.
 */

/** How the consent was given. */
export type ConsentSource =
  /** An admin-created Permission authorized the delegation without a prompt. */
  | 'permission'
  /** The subject's stored provider connection authorized it (no Permission). */
  | 'connection'
  /** An approver approved a CIBA request for it. */
  | 'ciba'
  /** A delegating agent's hop from a parent with no recorded consent. */
  | 'delegation';

export interface ConsentRecord {
  id: string;
  /** The subject on whose behalf the delegation occurs. */
  subject: string;
  agentDid: string;
  service: string;
  /** The capabilities granted, as the token's `authorization_details`. */
  capabilities: unknown[];
  source: ConsentSource;
  /** Who approved: the subject, an admin, or the Permission's creator. */
  approvedBy: string;
  grantedAt: string;
  expiresAt: string | null;
  /** The delegation chain context at the time of consent. */
  chainContext: Record<string, unknown>;
}

export type RecordConsentInput = Omit<ConsentRecord, 'grantedAt'>;

/**
 * Which consents a security event revokes (draft Section 8.3, trigger 4):
 * by id, or every consent of a subject, an agent, or both together.
 */
export interface ConsentRevocationFilter {
  consentIds?: readonly string[];
  subject?: string;
  agentDid?: string;
}

/** A consent is never edited; its revocation is a separate, append-only record. */
export interface ConsentRevocation {
  consentId: string;
  revokedAt: string;
  reason: string;
}

/** Whether a record matches a revocation filter that names at least one condition. */
export function consentMatches(record: ConsentRecord, filter: ConsentRevocationFilter): boolean {
  if (!filter.consentIds?.length && !filter.subject && !filter.agentDid) return false;
  if (filter.consentIds?.length && !filter.consentIds.includes(record.id)) return false;
  if (filter.subject && record.subject !== filter.subject) return false;
  if (filter.agentDid && record.agentDid !== filter.agentDid) return false;
  return true;
}

/** Consent storage for backends without a consent table (the file backend). */
export class MemoryConsentStore {
  private readonly records = new Map<string, ConsentRecord>();

  storeConsent(input: RecordConsentInput, now: string): ConsentRecord {
    const existing = this.records.get(input.id);
    // Immutable: replaying an id never rewrites the record.
    if (existing) return existing;
    const record: ConsentRecord = { ...input, grantedAt: now };
    this.records.set(record.id, record);
    return record;
  }

  getConsent(id: string): ConsentRecord | null {
    return this.records.get(id) ?? null;
  }

  private readonly revocations = new Map<string, ConsentRevocation>();

  revokeConsents(filter: ConsentRevocationFilter, reason: string, now: string): string[] {
    const revoked: string[] = [];
    for (const record of this.records.values()) {
      if (!consentMatches(record, filter) || this.revocations.has(record.id)) continue;
      this.revocations.set(record.id, { consentId: record.id, revokedAt: now, reason });
      revoked.push(record.id);
    }
    return revoked;
  }

  getConsentRevocation(id: string): ConsentRevocation | null {
    return this.revocations.get(id) ?? null;
  }

  findConsents(filter: { subject: string; agentDid: string; service: string }): ConsentRecord[] {
    return [...this.records.values()].filter((r) => r.subject === filter.subject && r.agentDid === filter.agentDid && r.service === filter.service);
  }

  /** Remove records whose retention ended: granted and expired before `before`. */
  purgeConsents(before: string): number {
    let purged = 0;
    for (const [id, record] of this.records) {
      const end = record.expiresAt && record.expiresAt > record.grantedAt ? record.expiresAt : record.grantedAt;
      if (end < before) {
        this.records.delete(id);
        purged += 1;
      }
    }
    return purged;
  }
}
