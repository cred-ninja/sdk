/**
 * Least-privilege report for a guard, from the decisions it recorded.
 *
 * Reads a guard's policy chain as data, interprets it, diagnoses it against
 * traffic, and dry-runs the smallest patch for one finding so an operator
 * can see what it would change before editing configuration. Nothing here
 * changes the guard.
 *
 * Run from the repo root after `npm run build`:
 *   npx tsx examples/policy-least-privilege-report.mts
 */

import {
  CredGuard,
  rateLimitPolicy,
  scopeFilterPolicy,
  urlAllowlistPolicy,
  snapshotGuard,
  interpretSnapshot,
  diagnosePolicies,
  applyPatch,
  classifyPatch,
  replayDecisions,
} from '@credninja/guard';

async function main() {
  const guard = new CredGuard({
    policies: [
      rateLimitPolicy({ maxRequests: 100, windowMs: 60_000 }),
      scopeFilterPolicy({ allowedScopes: { github: ['repo', 'read:user', 'gist'] } }),
      urlAllowlistPolicy({ allowedUrls: { github: ['https://api.github.com/repos/', 'https://api.github.com/gists'] } }),
    ],
    decisionHistorySize: 1000,
  });

  // Traffic: an agent that only ever reads repositories.
  for (let i = 0; i < 40; i += 1) {
    await guard.evaluate({
      provider: 'github',
      agentTokenHash: 'agent-a',
      requestedScopes: ['repo'],
      consentedScopes: ['repo'],
      targetUrl: 'https://api.github.com/repos/cred-ninja/sdk',
      targetMethod: 'GET',
      timestamp: new Date().toISOString(),
    });
  }

  // 1. Read the configuration and say what it does.
  const snapshot = snapshotGuard(guard);
  console.log('snapshot', snapshot.hash.slice(0, 16), `${snapshot.parameterCount} parameters`);
  for (const line of interpretSnapshot(snapshot).summary) console.log(' ', line);

  // 2. Findings against recorded decisions.
  const diagnosis = diagnosePolicies(snapshot, guard.recentDecisions());
  for (const finding of diagnosis.findings) {
    console.log(`finding ${finding.code} ${finding.path ?? ''} -> ${finding.suggestedEffect ?? 'no patch'}`);
  }
  const target = diagnosis.findings.find((finding) => finding.code === 'unused-allowed-scope');
  if (!target?.suggestedPatch) throw new Error('expected an unused-allowed-scope finding');

  // 3. Dry-run the suggested patch: effect, size, and what it would have decided differently.
  const classification = classifyPatch(snapshot, target.suggestedPatch);
  const patched = applyPatch(snapshot, target.suggestedPatch);
  const replay = await replayDecisions(snapshot, patched, guard.recentDecisions(), { previous: guard.getPolicies() });
  console.log('patch', JSON.stringify(target.suggestedPatch));
  console.log('effect', classification.effect, `touched ${classification.magnitude.touched} of ${classification.magnitude.total}`);
  console.log('replay', replay);
  console.log('the running guard is unchanged:', guard.getPolicyNames().join(', '));
  // Apply the patch to your configuration and redeploy if you agree with it.
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
