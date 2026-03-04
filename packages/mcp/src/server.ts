/**
 * Cred MCP Server
 *
 * Model Context Protocol server that wraps Cred's delegation API.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';

import { CredMcpConfig } from './config.js';
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

/**
 * Create and configure the Cred MCP server.
 */
export function createCredMcpServer(config: CredMcpConfig): Server {
  // Create Cred client from config
  const cred = new Cred({
    agentToken: config.agentToken,
    baseUrl: config.baseUrl,
  });

  // Tool context passed to all handlers
  const toolContext = {
    cred,
    appClientId: config.appClientId,
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

      case STATUS_TOOL_NAME:
        return handleStatus(args as unknown as StatusToolInput, toolContext);

      case REVOKE_TOOL_NAME:
        return handleRevoke(args as unknown as RevokeToolInput, toolContext);

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
 */
export async function startServer(config: CredMcpConfig): Promise<void> {
  const server = createCredMcpServer(config);
  const transport = new StdioServerTransport();

  await server.connect(transport);

  // Log to stderr so it doesn't interfere with stdio transport
  console.error('Cred MCP server started');
}
