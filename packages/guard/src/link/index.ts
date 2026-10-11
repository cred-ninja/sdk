/**
 * @credninja/guard: Cred Link policy (hooks and the client grant policy).
 */

export { createLinkHooks, LINK_CHECK_ERROR_CODE } from './hooks.js';
export type { LinkHooksDeps, LinkHooksOptions } from './hooks.js';
export { clientGrantPolicy, CLIENT_GRANT_POLICY_NAME } from './client-grant-policy.js';
export type { ClientGrantPolicyConfig, ClientGrantPolicyResult } from './client-grant-policy.js';
