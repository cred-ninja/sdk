export { Cred } from './cred.js';
export { CRED_PROTOCOL_VERSION, CRED_PROTOCOL_VERSION_HEADER } from './protocol.js';
export { CredError, ConsentRequiredError } from './errors.js';
export { createWebBotAuthSigner, rawPrivateKeyToPublicKeyHex } from './web-bot-auth.js';
export {
  generateAgentIdentity,
  importAgentIdentity,
  verifyDelegationReceipt,
  CRED_PUBLIC_KEY_HEX,
} from './identity.js';
export type {
  AgentIdentity,
  AgentStatus,
  GenerateIdentityOptions,
  ExportedIdentity,
  ImportParams,
  VerifyReceiptOptions,
  DelegationReceiptPayload,
} from './identity.js';
export type { WebBotAuthSigner, WebBotAuthSignerConfig } from './web-bot-auth.js';
export type {
  CredConfig,
  CredCloudConfig,
  CredLocalConfig,
  CredLocalVaultConfig,
  CredProviderConfig,
  DelegationResult,
  DelegationHandleResult,
  BrokeredUseParams,
  BrokeredUseResult,
  DelegationChainLink,
  Connection,
  DelegateParams,
  TofuDelegateParams,
  SubDelegateParams,
  SubDelegationResult,
  SubDelegationHandleResult,
  GetConsentUrlParams,
  RevokeParams,
  AuditEntry,
  AuditParams,
  RegisterAgentParams,
  RevokeAgentParams,
  WebBotAuthIdentity,
  WebBotAuthDirectory,
  WebBotAuthDirectoryKey,
  RegisterWebBotAuthKeyParams,
  RotateWebBotAuthKeyParams,
  RotatedWebBotAuthIdentity,
  RotateParams,
  ScheduleRotationParams,
  RotationStatus,
} from './types.js';
