/**
 * Weight-space policy editing, end to end, in one process.
 *
 * Reads a guard's policy chain as data, interprets it, diagnoses it against
 * traffic, proposes the smallest patch for one finding, dry-runs it, signs the
 * proposal as an approver, and applies it. The approver key is generated here
 * for the demo; in a deployment it lives with the operator, never with the
 * agent that proposes.
 *
 * Run from the repo root after `npm run build`:
 *   npx tsx examples/weight-space-policy-editor.mts
 */

import {
  CredGuard,
  rateLimitPolicy,
  scopeFilterPolicy,
  urlAllowlistPolicy,
  PolicyWeightSpaceEditor,
  generateApproverKeyPair,
  signProposal,
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

  const approver = generateApproverKeyPair();
  const editor = new PolicyWeightSpaceEditor(guard, {
    approvers: [{ id: 'operator', publicKey: approver.publicKey }],
    onEvent: (event) => console.log(`[audit] ${event.type} ${event.proposalId} ${event.effect} ${event.magnitude.touched}/${event.magnitude.total}`),
  });

  // 1. Read the weights.
  const { snapshot, interpretation, diagnosis } = editor.inspect();
  console.log('snapshot', snapshot.hash.slice(0, 16), `${snapshot.parameterCount} parameters`);
  for (const line of interpretation.summary) console.log(' ', line);

  // 2. Diagnose.
  for (const finding of diagnosis.findings) {
    console.log(`finding ${finding.code} ${finding.path ?? ''} -> ${finding.suggestedEffect ?? 'no patch'}`);
  }
  const target = diagnosis.findings.find((finding) => finding.code === 'unused-allowed-scope');
  if (!target?.suggestedPatch) throw new Error('expected an unused-allowed-scope finding');

  // 3. Propose the surgical patch and dry-run it.
  const proposal = await editor.propose({
    patch: target.suggestedPatch,
    rationale: target.message,
    proposer: 'did:key:z6MkExampleAgent',
  });
  console.log('proposal', proposal.id, proposal.classification.effect, `touched ${proposal.classification.magnitude.touched} of ${proposal.classification.magnitude.total}`);
  console.log('dry run', proposal.dryRun);

  // 4. The operator reviews and signs the proposal hash (on their own machine).
  const approval = signProposal(proposal, 'operator', approver.privateKey);

  // 5. Apply: only scope-filter is rebuilt; rate-limit keeps its counters.
  const result = await editor.apply(proposal.id, [approval]);
  if (!result.applied) throw new Error(`${result.code}: ${result.message}`);
  console.log('applied', { rebuilt: result.rebuilt, kept: result.kept, hash: result.snapshot.hash.slice(0, 16) });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
