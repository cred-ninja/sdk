/**
 * @credninja/server — programmatic API
 *
 * Use createServer() to embed the Cred server in your own application,
 * or run the CLI: npx @credninja/server
 */

export { createServer } from './server.js';
export { loadConfig } from './config.js';
export { verifyReceiptChain, receiptHash, parseReceiptPayload } from './receipt-chain.js';
export type { ReceiptChainResult, ReceiptChainReason, ParsedReceipt, VerifyReceiptChainOptions } from './receipt-chain.js';
export type {
  ServerConfig,
  ProviderConfig,
  RequestAgentPrincipal,
  AgentRequestAuthResult,
  AgentRequestVerifier,
} from './config.js';
export type { AgentPrincipal, TofuProofInput, TofuDelegationPayload, ResolvedTofuIdentity } from './tofu-bridge.js';

// Re-export guard for convenience — users can configure guard inline
export type { CredGuard, GuardConfig, CredPolicy } from '@credninja/guard';
