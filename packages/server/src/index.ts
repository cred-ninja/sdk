/**
 * @credninja/server — programmatic API
 *
 * Use createServer() to embed the Cred server in your own application,
 * or run the CLI: npx @credninja/server
 */

export { createServer } from './server.js';
export { loadConfig, resolveLinkStorePath } from './config.js';
export type { LinkService } from './link/index.js';
export { verifyReceiptChain, receiptHash, parseReceiptPayload } from './receipt-chain.js';
export type { ReceiptChainResult, ReceiptChainReason, ParsedReceipt, VerifyReceiptChainOptions, ReceiptVerificationKeys } from './receipt-chain.js';
export { createReceiptKeys, DEFAULT_RECEIPT_ACCEPTED_ALGS } from './receipt-signing.js';
export type { ReceiptKeys, ReceiptKeyOptions } from './receipt-signing.js';
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
