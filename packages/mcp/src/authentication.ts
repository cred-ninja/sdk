import type { CredMcpConfig } from './config.js';

/**
 * How this MCP instance authenticates to Cred, as reported by cred_capabilities
 * and cred_whoami. It describes this instance's own configuration only (the
 * server's is not visible from here), and never carries paths, keys or tokens.
 */
export interface AuthenticationSummary {
  /** `agent-token`: Bearer agent token. `wimse-workload`: WIT + HTTP Message Signature. `local`: no Cred server. */
  mode: 'agent-token' | 'wimse-workload' | 'local';
  /** A Txn-Token file is configured, so each request carries and signs a Txn-Token. */
  txnToken: boolean;
  /** Requests are also signed with Web Bot Auth. */
  webBotAuth: boolean;
}

export function describeAuthentication(config: CredMcpConfig): AuthenticationSummary {
  if (config.mode === 'local') return { mode: 'local', txnToken: false, webBotAuth: Boolean(config.webBotAuth) };
  if (config.wimse) return { mode: 'wimse-workload', txnToken: Boolean(config.wimse.txnTokenFile), webBotAuth: false };
  return { mode: 'agent-token', txnToken: false, webBotAuth: Boolean(config.webBotAuth) };
}
