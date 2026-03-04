/**
 * @credninja/mcp — MCP server for Cred
 *
 * Model Context Protocol server that wraps Cred's delegation API.
 * Enables AI agents running in Claude Desktop (or any MCP-compatible runtime)
 * to request delegated OAuth2 access tokens.
 */

export { createCredMcpServer, startServer } from './server.js';
export { loadConfig, CredMcpConfig } from './config.js';
export {
  DELEGATE_TOOL_NAME,
  DELEGATE_TOOL_DEFINITION,
  handleDelegate,
  DelegateToolInput,
  DelegateToolContext,
} from './tools/delegate.js';
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
