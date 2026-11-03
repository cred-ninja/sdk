/**
 * @credninja/guard — Replay: dry-run a patch against recorded decisions
 *
 * Rebuilds the base chain and the patched chain in isolation and evaluates
 * every recorded decision against both. The report lists the requests whose
 * outcome flips, so a reviewer sees what a patch changes in practice before
 * applying it to configuration. Policies that hold runtime state
 * (rate-limit) are left out of both chains: their answer depends on history
 * the replay does not have. The running guard is never touched.
 */

import { CredGuard } from '../guard.js';
import type { CredPolicy, GuardContext } from '../types.js';
import { materializePolicies } from './snapshot.js';
import type { MaterializeOptions } from './snapshot.js';
import type { Observation, PolicySnapshot, ReplayFlip, ReplayReport } from './types.js';

export function contextFromObservation(event: Observation): GuardContext {
  return {
    provider: event.provider,
    agentTokenHash: event.agentTokenHash,
    requestedScopes: [...(event.requestedScopes ?? [])],
    // The consented scopes are not recorded on the event; the requested
    // scopes are the closest stand-in and only matter to policies that
    // compare the two, none of which are built in.
    consentedScopes: [...(event.requestedScopes ?? [])],
    timestamp: event.timestamp,
    ...(event.targetUrl ? { targetUrl: event.targetUrl } : {}),
    ...(event.targetMethod ? { targetMethod: event.targetMethod } : {}),
    ...(event.identitySource ? { identitySource: event.identitySource } : {}),
    ...(event.agentDid ? { agentDid: event.agentDid } : {}),
    ...(event.tofuFingerprint ? { tofuFingerprint: event.tofuFingerprint } : {}),
    ...(event.webBotAuthKeyId ? { webBotAuthKeyId: event.webBotAuthKeyId } : {}),
    ...(event.signatureAgent ? { signatureAgent: event.signatureAgent } : {}),
    ...(event.link ? { link: { ...event.link } } : {}),
  };
}

export interface ReplayOptions extends Pick<MaterializeOptions, 'previous' | 'factories'> {}

export async function replayDecisions(
  base: PolicySnapshot,
  patched: PolicySnapshot,
  events: Observation[],
  options: ReplayOptions = {},
): Promise<ReplayReport> {
  const materialize = (snapshot: PolicySnapshot): CredPolicy[] =>
    materializePolicies(snapshot, { ...options, excludeStateful: true });
  const excluded = new Set<string>();
  for (const entry of [...base.policies, ...patched.policies]) {
    if (entry.descriptor.stateful) excluded.add(entry.name);
  }
  const before = new CredGuard({ policies: materialize(base), onError: base.onError });
  const after = new CredGuard({ policies: materialize(patched), onError: patched.onError });

  const report: ReplayReport = { events: events.length, excludedPolicies: [...excluded].sort(), unchanged: 0, newlyAllowed: [], newlyDenied: [] };
  for (let index = 0; index < events.length; index += 1) {
    const ctx = contextFromObservation(events[index]);
    const [a, b] = await Promise.all([before.evaluate(ctx), after.evaluate(ctx)]);
    if (a.allowed === b.allowed) {
      report.unchanged += 1;
      continue;
    }
    const flip: ReplayFlip = {
      index,
      provider: ctx.provider,
      ...(ctx.targetUrl ? { targetUrl: ctx.targetUrl } : {}),
      requestedScopes: ctx.requestedScopes,
      before: { allowed: a.allowed, ...(a.deniedBy ? { deniedBy: a.deniedBy.policy } : {}) },
      after: { allowed: b.allowed, ...(b.deniedBy ? { deniedBy: b.deniedBy.policy } : {}) },
    };
    (b.allowed ? report.newlyAllowed : report.newlyDenied).push(flip);
  }
  return report;
}
