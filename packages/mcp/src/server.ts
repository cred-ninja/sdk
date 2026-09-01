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
import type { CredGuard } from '@credninja/guard';

import { CredMcpConfig } from './config.js';
import { TokenCache } from './token-cache.js';
import { createWebBotAuthSigner } from './web-bot-auth.js';
import { agentTokenHashForLocalMode, wireGuardedTool, syntheticProvider } from './guard-wiring.js';
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
  UseToolContext,
} from './tools/use.js';
import {
  SUBDELEGATE_TOOL_NAME,
  SUBDELEGATE_TOOL_DEFINITION,
  handleSubdelegate,
  SubdelegateToolInput,
} from './tools/subdelegate.js';
import {
  REGISTER_IDENTITY_TOOL_NAME,
  REGISTER_IDENTITY_TOOL_DEFINITION,
  handleRegisterIdentity,
  RegisterIdentityToolInput,
} from './tools/register-identity.js';
import {
  ROTATE_KEY_TOOL_NAME,
  ROTATE_KEY_TOOL_DEFINITION,
  handleRotateKey,
  RotateKeyToolInput,
} from './tools/rotate-key.js';
import {
  REVOKE_IDENTITY_TOOL_NAME,
  REVOKE_IDENTITY_TOOL_DEFINITION,
  handleRevokeIdentity,
  RevokeIdentityToolInput,
} from './tools/revoke-identity.js';

const MCP_SERVER_VERSION = '1.0.0';

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
    ...(config.webBotAuth ? { webBotAuth: config.webBotAuth } : {}),
  });
}

/**
 * Shared per-server-instance state: the Cred client, token cache, and the
 * tool context object passed to every handler. Built once and consumed by
 * both `createCredMcpServer()` and `startServer()` so the two entry points
 * can never register a different tool set or wiring — see U1's Key Technical
 * Decisions on why the previous line-for-line-duplicated construction was a
 * drift risk.
 */
function buildServerState(config: CredMcpConfig) {
  const cred = createCredClient(config);
  const webBotAuthSigner = config.webBotAuth
    ? createWebBotAuthSigner(config.webBotAuth)
    : undefined;
  const tokenCache = new TokenCache();

  // Local mode has no agent token; wrapMcpToolHandler needs an identity to
  // hash rate limits against, so it's derived from agentDid instead. When
  // agentDid isn't configured, guard wrapping is skipped for this instance
  // entirely rather than every tool call failing with "Missing agent token".
  const guard: CredGuard | undefined =
    config.mode === 'local' && !config.agentDid ? undefined : config.guard;

  const toolContext = {
    cred,
    appClientId: config.mode === 'cloud' ? config.appClientId : 'local',
    agentDid: config.agentDid,
    selfAgentId: config.selfAgentId,
    tokenCache,
    webBotAuthSigner,
    useServerBroker: config.mode === 'cloud',
    ...(config.mode === 'cloud' ? { agentToken: config.agentToken } : {}),
    ...(config.mode === 'local' && config.agentDid
      ? { agentTokenHash: agentTokenHashForLocalMode(config.agentDid) }
      : {}),
  };

  return { cred, tokenCache, toolContext, guard, mode: config.mode };
}

/**
 * Registers the tool-list and tool-call handlers on `server`. The single
 * registration point both `createCredMcpServer()` and `startServer()` call
 * — see `buildServerState` for why this collapse matters.
 */
function registerTools(
  server: Server,
  toolContext: ReturnType<typeof buildServerState>['toolContext'],
  guard: CredGuard | undefined,
  mode: 'cloud' | 'local',
) {
  const guardedHandleDelegate = wireGuardedTool(
    DELEGATE_TOOL_NAME,
    mode,
    guard,
    handleDelegate,
    (input: DelegateToolInput) => ({ provider: input.service, scopes: input.scopes ?? [] }),
  );
  const guardedHandleSubdelegate = wireGuardedTool(
    SUBDELEGATE_TOOL_NAME,
    mode,
    guard,
    handleSubdelegate,
    (input: SubdelegateToolInput) => ({ provider: input.service, scopes: input.scopes ?? [] }),
  );
  const guardedHandleUse = wireGuardedTool(
    USE_TOOL_NAME,
    mode,
    guard,
    handleUse,
    (input: UseToolInput, ctx: UseToolContext) => ({
      provider: ctx.tokenCache.get(input.delegation_id)?.service ?? syntheticProvider(USE_TOOL_NAME),
      // The delegated scopes, not anything from this call's own input — UseToolInput
      // has no scopes field. UrlAllowlistPolicy's scopeGate hook (U2) needs the
      // scopes granted at delegation time to gate the target URL correctly.
      scopes: ctx.tokenCache.get(input.delegation_id)?.scopes ?? [],
      targetUrl: input.url,
      targetMethod: input.method,
      delegationId: input.delegation_id,
    }),
  );
  const guardedHandleStatus = wireGuardedTool(
    STATUS_TOOL_NAME,
    mode,
    guard,
    handleStatus,
    () => ({ provider: syntheticProvider(STATUS_TOOL_NAME) }),
  );
  const guardedHandleRevoke = wireGuardedTool(
    REVOKE_TOOL_NAME,
    mode,
    guard,
    handleRevoke,
    (input: RevokeToolInput) => ({ provider: input.service }),
  );
  const guardedHandleRegisterIdentity = wireGuardedTool(
    REGISTER_IDENTITY_TOOL_NAME,
    mode,
    guard,
    handleRegisterIdentity,
    () => ({ provider: syntheticProvider(REGISTER_IDENTITY_TOOL_NAME) }),
  );
  const guardedHandleRotateKey = wireGuardedTool(
    ROTATE_KEY_TOOL_NAME,
    mode,
    guard,
    handleRotateKey,
    () => ({ provider: syntheticProvider(ROTATE_KEY_TOOL_NAME) }),
  );
  const guardedHandleRevokeIdentity = wireGuardedTool(
    REVOKE_IDENTITY_TOOL_NAME,
    mode,
    guard,
    handleRevokeIdentity,
    () => ({ provider: syntheticProvider(REVOKE_IDENTITY_TOOL_NAME) }),
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      DELEGATE_TOOL_DEFINITION,
      SUBDELEGATE_TOOL_DEFINITION,
      USE_TOOL_DEFINITION,
      STATUS_TOOL_DEFINITION,
      REVOKE_TOOL_DEFINITION,
      REGISTER_IDENTITY_TOOL_DEFINITION,
      ROTATE_KEY_TOOL_DEFINITION,
      REVOKE_IDENTITY_TOOL_DEFINITION,
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case DELEGATE_TOOL_NAME:
        return guardedHandleDelegate(args as unknown as DelegateToolInput, toolContext);

      case SUBDELEGATE_TOOL_NAME:
        return guardedHandleSubdelegate(args as unknown as SubdelegateToolInput, toolContext);

      case STATUS_TOOL_NAME:
        return guardedHandleStatus(args as unknown as StatusToolInput, toolContext);

      case REVOKE_TOOL_NAME:
        return guardedHandleRevoke(args as unknown as RevokeToolInput, toolContext);

      case USE_TOOL_NAME:
        return guardedHandleUse(args as unknown as UseToolInput, toolContext);

      case REGISTER_IDENTITY_TOOL_NAME:
        return guardedHandleRegisterIdentity(args as unknown as RegisterIdentityToolInput, toolContext);

      case ROTATE_KEY_TOOL_NAME:
        return guardedHandleRotateKey(args as unknown as RotateKeyToolInput, toolContext);

      case REVOKE_IDENTITY_TOOL_NAME:
        return guardedHandleRevokeIdentity(args as unknown as RevokeIdentityToolInput, toolContext);

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
}

/**
 * Builds a fully-registered MCP `Server` instance plus the `tokenCache`
 * backing it, so a caller needing to clean up the cache on shutdown (see
 * `startServer`) has the exact instance wired into the running server, not a
 * second, independently constructed one. Both `createCredMcpServer()` and
 * `startServer()` call this single function — there is exactly one
 * registration path, not two independently maintained ones.
 */
export function buildMcpServer(config: CredMcpConfig): { server: Server; tokenCache: TokenCache } {
  const { toolContext, guard, mode, tokenCache } = buildServerState(config);

  const server = new Server(
    {
      name: 'cred-mcp',
      version: MCP_SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  registerTools(server, toolContext, guard, mode);

  return { server, tokenCache };
}

/**
 * Create and configure the Cred MCP server.
 */
export function createCredMcpServer(config: CredMcpConfig): Server {
  return buildMcpServer(config).server;
}

/**
 * Start the MCP server with stdio transport.
 * Handles SIGTERM/SIGINT for graceful shutdown and cache cleanup.
 */
export async function startServer(config: CredMcpConfig): Promise<void> {
  const { server, tokenCache } = buildMcpServer(config);

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
