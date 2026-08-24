/**
 * Audit trail - one structured line per authorization decision.
 *
 * This is the capability the bare x64dbg plugin has zero of. Every decision
 * (allow or deny) emits a line carrying, at minimum, the fields required by the
 * task: timestamp, delegated subject, tool name, required scope, decision, and
 * upstream status. The Cred guard event (from buildAuditEvent) is embedded
 * verbatim under `guard`.
 *
 * Audit lines are written to stdout as newline-delimited JSON. Human/diagnostic
 * logging goes to stderr, so stdout is a clean audit stream.
 */

import { appendFileSync } from 'node:fs';
import type { GuardAuditEvent } from '@credninja/guard';

export interface AuditLine {
  ts: string;
  event: 'x64dbg.proxy.decision';
  /** Delegated subject (agent DID), or null when the credential could not be identified. */
  subject: string | null;
  /** SHA-256 of the presented credential (never the raw token). */
  tokenHash: string | null;
  transport: 'streamable-http' | 'sse';
  method: string;
  tool: string | null;
  requiredScope: string | null;
  decision: 'allow' | 'deny';
  reason: string;
  /** Policy that decided, when a scope evaluation ran. */
  policy?: string;
  /** Upstream HTTP status for forwarded calls; null when the call was denied and never forwarded. */
  upstreamStatus: number | null;
  /** Full Cred guard event, when a scope evaluation ran. */
  guard?: GuardAuditEvent;
}

let auditLogPath: string | undefined;
let auditToStdout = true;

export function configureAudit(logPath?: string, opts?: { stdout?: boolean }): void {
  auditLogPath = logPath;
  auditToStdout = opts?.stdout ?? true;
}

export function emitAudit(line: AuditLine): void {
  const serialized = JSON.stringify(line);
  if (auditToStdout) process.stdout.write(serialized + '\n');
  if (auditLogPath) {
    try {
      appendFileSync(auditLogPath, serialized + '\n');
    } catch (err) {
      log(`audit file write failed: ${(err as Error).message}`);
    }
  }
}

/** Human/diagnostic logging -> stderr (keeps stdout a pure audit stream). */
export function log(message: string): void {
  process.stderr.write(`[x64dbg-proxy] ${message}\n`);
}
