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
  | 'ciba';

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
}
