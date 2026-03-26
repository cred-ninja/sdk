/**
 * Cred MCP Server
 *
 * Model Context Protocol server that wraps Cred's delegation API.
 * Supports cloud mode (hosted Cred API) and local mode (local vault).
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';

import { CredMcpConfig, CredMcpCloudConfig, CredMcpLocalConfig } from './config.js';
import { TokenCache } from './token-cache.js';
import { createWebBotAuthSigner } from './web-bot-auth.js';
import {
  DELEGATE_TOOL_NAME,
  DELEGATE_TOOL_DEFINITION,
  handleDelegate,
  DelegateToolInput,
} from './tools/delegate.js';
import {
  STATUS_TOOL_NAME,
  STATUS_TOOL_DEFINITION,
  handleStatus,
  StatusToolInput,
} from './tools/status.js';
import {
  REVOKE_TOOL_NAME,
  REVOKE_TOOL_DEFINITION,
  handleRevoke,
  RevokeToolInput,
} from './tools/revoke.js';
import {
  USE_TOOL_NAME,
  USE_TOOL_DEFINITION,
  handleUse,
  UseToolInput,
} from './tools/use.js';
import {
  SUBDELEGATE_TOOL_NAME,
  SUBDELEGATE_TOOL_DEFINITION,
  handleSubdelegate,
  SubdelegateToolInput,
} from './tools/subdelegate.js';

function createCredClient(config: CredMcpConfig): Cred {
  if (config.mode === 'local') {
    return new Cred({
      mode: 'local',
      vault: {
        passphrase: config.vaultPassphrase,
        path: config.vaultPath,
        storage: config.vaultStorage,
      },
      providers: config.providers,
    });
  }
  return new Cred({
    agentToken: config.agentToken,
    baseUrl: config.baseUrl,
  });
}

/**
 * Create and configure the Cred MCP server.
 */
export function createCredMcpServer(config: CredMcpConfig): Server {
  const cred = createCredClient(config);
  const webBotAuthSigner = config.webBotAuth
    ? createWebBotAuthSigner(config.webBotAuth)
    : undefined;

  // In-process token cache — tokens never leave this process
  const tokenCache = new TokenCache();

  // Tool context passed to all handlers
  const toolContext = {
    cred,
    appClientId: config.mode === 'cloud' ? config.appClientId : 'local',
    agentDid: config.agentDid,
    tokenCache,
    webBotAuthSigner,
  };

  const server = new Server(
    {
      name: 'cred-mcp',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  // Register tool list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        DELEGATE_TOOL_DEFINITION,
        SUBDELEGATE_TOOL_DEFINITION,
        USE_TOOL_DEFINITION,
        STATUS_TOOL_DEFINITION,
        REVOKE_TOOL_DEFINITION,
      ],
    };
  });

  // Register tool call handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case DELEGATE_TOOL_NAME:
        return handleDelegate(args as unknown as DelegateToolInput, toolContext);

      case SUBDELEGATE_TOOL_NAME:
        return handleSubdelegate(args as unknown as SubdelegateToolInput, toolContext);

      case STATUS_TOOL_NAME:
        return handleStatus(args as unknown as StatusToolInput, toolContext);

      case REVOKE_TOOL_NAME:
        return handleRevoke(args as unknown as RevokeToolInput, toolContext);

      case USE_TOOL_NAME:
        return handleUse(args as unknown as UseToolInput, toolContext);

      default:
        return {
          content: [
            {
              type: 'text',
              text: `Unknown tool: ${name}`,
            },
          ],
          isError: true,
        };
    }
  });

  return server;
}

/**
 * Start the MCP server with stdio transport.
 * Handles SIGTERM/SIGINT for graceful shutdown and cache cleanup.
 */
export async function startServer(config: CredMcpConfig): Promise<void> {
  const cred = createCredClient(config);
  const webBotAuthSigner = config.webBotAuth
    ? createWebBotAuthSigner(config.webBotAuth)
    : undefined;

  const tokenCache = new TokenCache();

  const toolContext = {
    cred,
    appClientId: config.mode === 'cloud' ? config.appClientId : 'local',
    agentDid: config.agentDid,
    tokenCache,
    webBotAuthSigner,
  };

  const server = new Server(
    { name: 'cred-mcp', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [DELEGATE_TOOL_DEFINITION, SUBDELEGATE_TOOL_DEFINITION, USE_TOOL_DEFINITION, STATUS_TOOL_DEFINITION, REVOKE_TOOL_DEFINITION],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    switch (name) {
      case DELEGATE_TOOL_NAME: return handleDelegate(args as unknown as DelegateToolInput, toolContext);
      case SUBDELEGATE_TOOL_NAME: return handleSubdelegate(args as unknown as SubdelegateToolInput, toolContext);
      case USE_TOOL_NAME:      return handleUse(args as unknown as UseToolInput, toolContext);
      case STATUS_TOOL_NAME:   return handleStatus(args as unknown as StatusToolInput, toolContext);
      case REVOKE_TOOL_NAME:   return handleRevoke(args as unknown as RevokeToolInput, toolContext);
      default:
        return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    }
  });

  const transport = new StdioServerTransport();

  const shutdown = async () => {
    tokenCache.destroy();
    await server.close();
    process.exit(0);
  };

  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);

  await server.connect(transport);
  const modeLabel = config.mode === 'local' ? 'local vault' : 'cloud API';
  console.error(`Cred MCP server started in ${modeLabel} mode (tokens never enter LLM context)`);
}
