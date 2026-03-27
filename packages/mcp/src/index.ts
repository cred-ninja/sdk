/**
 * @credninja/mcp — MCP server for Cred
 *
 * Model Context Protocol server that wraps Cred's delegation API.
 * Enables AI agents running in MCP-compatible runtimes
 * to request delegated OAuth2 access tokens.
 */

export { createCredMcpServer, startServer } from './server.js';
export { loadConfig } from './config.js';
export type { CredMcpConfig, CredMcpCloudConfig, CredMcpLocalConfig } from './config.js';
export { TokenCache, TokenEntry } from './token-cache.js';
export { createWebBotAuthSigner } from './web-bot-auth.js';
export type { WebBotAuthSigner } from './web-bot-auth.js';
export {
  DELEGATE_TOOL_NAME,
  DELEGATE_TOOL_DEFINITION,
  handleDelegate,
  DelegateToolInput,
  DelegateToolContext,
} from './tools/delegate.js';
export {
  SUBDELEGATE_TOOL_NAME,
  SUBDELEGATE_TOOL_DEFINITION,
  handleSubdelegate,
  SubdelegateToolInput,
  SubdelegateToolContext,
} from './tools/subdelegate.js';
export {
  USE_TOOL_NAME,
  USE_TOOL_DEFINITION,
  handleUse,
  UseToolInput,
  UseToolContext,
} from './tools/use.js';
export {
  STATUS_TOOL_NAME,
  STATUS_TOOL_DEFINITION,
  handleStatus,
  StatusToolInput,
  StatusToolContext,
} from './tools/status.js';
export {
  REVOKE_TOOL_NAME,
  REVOKE_TOOL_DEFINITION,
  handleRevoke,
  RevokeToolInput,
  RevokeToolContext,
} from './tools/revoke.js';
