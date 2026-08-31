/**
 * Cred Vercel AI SDK integration.
 *
 * Returns Vercel AI SDK tools that agents can call for delegated OAuth access.
 * The tool schema matches the Cred MCP tool spec:
 *
 *   name:   cred_delegate
 *   params: { service: string, scopes: string[] }
 *
 * userId and appClientId are pre-configured at factory time and are not
 * agent-controlled inputs.
 */

import { tool, type Tool } from 'ai';
import { z } from 'zod';
import { Cred } from '@credninja/sdk';

interface CredDelegateToolInput {
  service: string;
  scopes: string[];
}


export interface CredDelegateToolOptions {
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** The user whose credentials to delegate */
  userId: string;
  /** The Cred app client ID to delegate for */
  appClientId: string;
  /** Your Cred server URL (e.g. https://cred.example.com or http://localhost:3456) */
  baseUrl: string;
  /**
   * Token delivery mode. Defaults to `handle` (brokered): the provider access
   * token stays on the Cred server and only a delegation handle is returned to
   * the model — use it with `credUseTool`. Set to `raw` only if you explicitly
   * need the access token returned to the model; this exposes a live OAuth
   * token to the LLM context and defeats the brokered security model.
   */
  tokenFormat?: 'raw' | 'handle';
}

export interface CredUseToolOptions {
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** Your Cred server URL (e.g. https://cred.example.com or http://localhost:3456) */
  baseUrl: string;
}

interface CredUseToolInput {
  delegationId: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: Record<string, unknown>;
  extraHeaders?: Record<string, string>;
}

/**
 * Create a Vercel AI SDK tool for credential delegation.
 *
 * The returned tool is pre-configured with the user's identity and app context.
 * At runtime, the agent supplies `service` and `scopes`.
 *
 * @example
 * ```typescript
 * import { credDelegateTool } from '@credninja/ai';
 * import { generateText } from 'ai';
 *
 * const tool = credDelegateTool({
 *   agentToken: process.env.CRED_AGENT_TOKEN!,
 *   baseUrl: process.env.CRED_BASE_URL!,
 *   userId: 'user_123',
 *   appClientId: 'my_app',
 * });
 *
 * const result = await generateText({
 *   model: yourModel,
 *   tools: { cred_delegate: tool },
 *   prompt: 'Get my Google Calendar events',
 * });
 * ```
 */
export function credDelegateTool(options: CredDelegateToolOptions): Tool {
  const { agentToken, userId, appClientId, baseUrl, tokenFormat = 'handle' } = options;
  const inputSchema = z.object({
    service: z
      .string()
      .describe("Service slug to get a token for (e.g. 'google', 'github', 'google-calendar')."),
    scopes: z
      .array(z.string())
      .describe(
        "OAuth scopes to request (e.g. ['calendar.readonly']). " +
          'Pass an empty array to use all consented scopes.',
      ),
  }) as z.ZodType<CredDelegateToolInput>;

  const cred = new Cred({
    agentToken,
    baseUrl,
  });
  let cachedResult:
    | {
        accessToken?: string;
        tokenType: string;
        expiresIn: number;
        service: string;
        scopes: string[];
        delegationId: string;
        userId?: string;
        expiresAtMs: number;
        cacheKey: string;
      }
    | null = null;

  const toolDefinition = {
    description:
      (tokenFormat === 'handle'
        ? 'Get a brokered OAuth delegation handle for a third-party service '
        : 'Get a delegated OAuth access token for a third-party service ') +
      'on behalf of the current user. ' +
      (tokenFormat === 'handle'
        ? 'Returns token_type, expires_in, service, scopes, user_id, and delegation_id. Pass delegation_id to cred_use. '
        : 'Returns access_token, token_type, expires_in, service, scopes, and delegation_id. ') +
      'Raises an error with consent_url if the user has not connected the service.',
    inputSchema,
    execute: async ({ service, scopes }: CredDelegateToolInput) => {
      const resolvedScopes = scopes.length > 0 ? scopes : undefined;
      const cacheKey = JSON.stringify({ service, scopes: resolvedScopes ?? [] });
      const refreshCutoffMs = Date.now() + 60_000;

      if (cachedResult && cachedResult.cacheKey === cacheKey && cachedResult.expiresAtMs > refreshCutoffMs) {
        return {
          ...(cachedResult.accessToken ? { accessToken: cachedResult.accessToken } : {}),
          tokenType: cachedResult.tokenType,
          expiresIn: cachedResult.expiresIn,
          service: cachedResult.service,
          scopes: cachedResult.scopes,
          delegationId: cachedResult.delegationId,
          ...(cachedResult.userId ? { userId: cachedResult.userId } : {}),
          ...(tokenFormat === 'handle' ? { note: 'Pass delegationId to cred_use to make authenticated API calls.' } : {}),
        };
      }

      const result = tokenFormat === 'handle'
        ? await cred.delegateHandle({
            service,
            userId,
            appClientId,
            scopes: resolvedScopes,
          })
        : await cred.delegate({
            service,
            userId,
            appClientId,
            scopes: resolvedScopes,
          });

      const expiresAtMs = result.expiresAt instanceof Date
        ? result.expiresAt.getTime()
        : Date.now() + result.expiresIn * 1000;
      cachedResult = {
        ...('accessToken' in result ? { accessToken: result.accessToken } : {}),
        tokenType: result.tokenType,
        expiresIn: result.expiresIn,
        service: result.service,
        scopes: result.scopes,
        delegationId: result.delegationId,
        ...('userId' in result ? { userId: result.userId } : {}),
        expiresAtMs,
        cacheKey,
      };

      return {
        ...('accessToken' in result ? { accessToken: result.accessToken } : {}),
        tokenType: result.tokenType,
        expiresIn: result.expiresIn,
        service: result.service,
        scopes: result.scopes,
        delegationId: result.delegationId,
        ...('userId' in result ? { userId: result.userId } : {}),
        ...(tokenFormat === 'handle' ? { note: 'Pass delegationId to cred_use to make authenticated API calls.' } : {}),
      };
    },
  };

  return tool(toolDefinition as any);
}

/**
 * Create a Vercel AI SDK tool that brokers an upstream API request through Cred.
 *
 * Use this with `credDelegateTool({ tokenFormat: 'handle', ... })`.
 */
export function credUseTool(options: CredUseToolOptions): Tool {
  const { agentToken, baseUrl } = options;
  const cred = new Cred({
    agentToken,
    baseUrl,
  });

  const inputSchema = z.object({
    delegationId: z.string().describe('Delegation handle returned by cred_delegate.'),
    url: z.string().url().describe('Full HTTPS API URL to call. The Cred server enforces service allowlists.'),
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).describe('HTTP method.'),
    body: z.record(z.string(), z.unknown()).optional().describe('JSON request body for POST, PUT, or PATCH.'),
    extraHeaders: z.record(z.string(), z.string()).optional().describe('Optional service-specific headers.'),
  }) as z.ZodType<CredUseToolInput>;

  return tool({
    description:
      'Make an authenticated API call through Cred using a brokered delegation handle. ' +
      'The provider access token stays on the Cred server.',
    inputSchema,
    execute: async ({ delegationId, url, method, body, extraHeaders }: CredUseToolInput) => {
      return cred.use({
        delegationId,
        url,
        method,
        body,
        extraHeaders,
      });
    },
  } as any);
}
