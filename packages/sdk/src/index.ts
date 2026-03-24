export { Cred } from './cred.js';
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
  DelegationChainLink,
  Connection,
  DelegateParams,
  TofuDelegateParams,
  SubDelegateParams,
  SubDelegationResult,
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
