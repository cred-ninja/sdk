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
  ExternalIdentityConfig,
} from './config.js';

// External identity (opt-in): verified identities Cred does not issue.
export { createWimseIdentitySource, verifyWit, verifyWpt, validateWorkloadIdentifier } from './identity/wimse.js';
export type { WimseSourceConfig, WimseVerifyConfig, VerifiedWit, VerifiedWpt } from './identity/wimse.js';
export { loadTrustBundle, TrustBundleError } from './identity/trust-bundle.js';
export type { TrustAnchorKeys, TrustAnchorKey } from './identity/trust-bundle.js';
export { startTailscaleListener, checkListenerSocket, checkLocalApiSocket, DEFAULT_LOCALAPI_SOCKET } from './identity/tailscale.js';
export type { TailscaleSourceConfig, TailscaleListener, SocketCheck } from './identity/tailscale.js';
export { IdentityRefusal, createReplayCache, mappedAgentDid } from './identity/types.js';
// draft-ietf-wimse-http-signature-08 (RFC 9421 profile) and RFC 8941 parsing.
export {
  verifyWimseRequestSignature,
  verifyWimseResponseSignature,
  signWimseRequest,
  selectWimseSignature,
  signatureBase,
  WIMSE_SIGNATURE_TAG,
  WIMSE_PROBLEM_TYPES,
} from './identity/http-signature.js';
export type { HttpSigMessage, HttpSigVerifyConfig, VerifiedHttpSignature, SignRequestInput } from './identity/http-signature.js';
export { parseDictionary, parseItem, StructuredFieldError } from './identity/structured-fields.js';
// draft-ietf-oauth-transaction-tokens-11 at the final hop.
export { verifyTxnToken, checkTxnTokenTrust, mappedProviderScopes, TxnTokenRefusal } from './identity/txn-token.js';
export type { TxnTokenTrust, TxnUserSubjectRule, VerifiedTxnToken } from './identity/txn-token.js';
export type {
  ExternalIdentityKind,
  ExternalIdentitySource,
  ExternalIdentityMapping,
  IdentityRequest,
  VerifiedExternalIdentity,
  ReplayCache,
} from './identity/types.js';
export type { AgentPrincipal, TofuProofInput, TofuDelegationPayload, ResolvedTofuIdentity } from './tofu-bridge.js';

// Re-export guard for convenience — users can configure guard inline
export type { CredGuard, GuardConfig, CredPolicy } from '@credninja/guard';
