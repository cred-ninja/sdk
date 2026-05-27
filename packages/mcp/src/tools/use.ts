/**
 * cred_use Tool
 *
 * Makes an authenticated upstream API call using a cached delegation handle.
 * The raw OAuth token never leaves this process — it's used server-side and
 * only the API response is returned to the LLM.
 *
 * Security properties:
 *  - Token is looked up from in-process cache, not passed in by the LLM
 *  - Target URL is validated against a per-service allowlist (SSRF protection)
 *  - Response is truncated at 32KB to prevent context flooding
 *  - Authorization header is never echoed back in responses or errors
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';
import { TokenCache } from '../token-cache.js';
import type { WebBotAuthSigner } from '../web-bot-auth.js';

export const USE_TOOL_NAME = 'cred_use';

const MAX_RESPONSE_BYTES = 32_768; // 32KB — keeps responses LLM-friendly

const BLOCKED_EXTRA_HEADERS = new Set([
  'authorization',
  'connection',
  'content-length',
  'cookie',
  'forwarded',
  'host',
  'proxy-authenticate',
  'proxy-authorization',
  'set-cookie',
  'signature',
  'signature-agent',
  'signature-input',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
]);

function isForwardableExtraHeader(key: string, value: unknown): value is string {
  if (typeof value !== 'string') return false;
  return !BLOCKED_EXTRA_HEADERS.has(key.toLowerCase());
}

export const USE_TOOL_DEFINITION = {
  name: USE_TOOL_NAME,
  description:
    'Make an authenticated API call to a service using a delegation handle from cred_delegate. ' +
    'The token is used server-side; only the API response is returned. ' +
    'The url must be a valid API endpoint for the service (e.g. https://api.github.com/repos/org/repo/issues).',
  inputSchema: {
    type: 'object' as const,
    properties: {
      delegation_id: {
        type: 'string',
        description: 'The delegation handle returned by cred_delegate.',
      },
      url: {
        type: 'string',
        description: 'The full API URL to call (must be an HTTPS endpoint for the delegated service).',
      },
      method: {
        type: 'string',
        enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        description: 'HTTP method.',
      },
      body: {
        type: 'object',
        description: 'Request body for POST, PUT, or PATCH calls. Optional.',
      },
      extra_headers: {
        type: 'object',
        description: 'Additional headers to include (e.g. GitHub-Version, Notion-Version). Optional.',
        additionalProperties: { type: 'string' },
      },
    },
    required: ['delegation_id', 'url', 'method'],
  },
};

export interface UseToolInput {
  delegation_id: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: Record<string, unknown>;
  extra_headers?: Record<string, string>;
}

export interface UseToolContext {
  tokenCache: TokenCache;
  cred?: Cred;
  webBotAuthSigner?: WebBotAuthSigner;
}

export async function handleUse(
  input: UseToolInput,
  context: UseToolContext,
): Promise<CallToolResult> {
  // ── 1. Look up delegation handle ──────────────────────────────────────────
  const entry = context.tokenCache.get(input.delegation_id);
  if (!entry) {
    return {
      content: [{ type: 'text', text: 'Error: delegation handle not found or expired. Call cred_delegate again.' }],
      isError: true,
    };
  }

  if (entry.brokered) {
    if (!context.cred) {
      return {
        content: [{ type: 'text', text: 'Error: brokered delegation requires a Cred client.' }],
        isError: true,
      };
    }
    try {
      const result = await context.cred.use({
        delegationId: entry.serverDelegationId ?? input.delegation_id,
        url: input.url,
        method: input.method,
        body: input.body,
        extraHeaders: input.extra_headers,
      });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Brokered upstream request failed';
      return {
        content: [{ type: 'text', text: `Error: ${message}` }],
        isError: true,
      };
    }
  }

  if (!entry.accessToken) {
    return {
      content: [{ type: 'text', text: 'Error: delegation handle has no usable token.' }],
      isError: true,
    };
  }

  // ── 2. Validate target URL (SSRF protection) ───────────────────────────────
  if (!context.tokenCache.isAllowedUrl(entry.service, input.url, entry.scopes)) {
    return {
      content: [{
        type: 'text',
        text: `Error: URL is not a valid ${entry.service} API endpoint. ` +
              `Only known ${entry.service} API base URLs allowed by the delegated scopes are allowed.`,
      }],
      isError: true,
    };
  }

  // ── 3. Validate method vs body ─────────────────────────────────────────────
  const hasBody = input.body !== undefined;
  if (hasBody && input.method === 'GET') {
    return {
      content: [{ type: 'text', text: 'Error: GET requests cannot have a body.' }],
      isError: true,
    };
  }

  // ── 4. Build and execute the upstream request ──────────────────────────────
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${entry.accessToken}`,
    'Accept': 'application/json',
    'User-Agent': 'Cred-MCP/1.0',
    ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
    // Sanitize extra_headers — strip Authorization and Web Bot Auth signature
    // fields to prevent caller-controlled spoofing or override.
    ...(input.extra_headers
      ? Object.fromEntries(
          Object.entries(input.extra_headers).filter(
            ([key, value]) => isForwardableExtraHeader(key, value),
          ),
        )
      : {}),
  };

  const signedHeaders = context.webBotAuthSigner
    ? context.webBotAuthSigner.signRequest({
        url: input.url,
        method: input.method,
        headers,
      })
    : headers;

  let response: Response;
  try {
    response = await fetch(input.url, {
      method: input.method,
      headers: signedHeaders,
      body: hasBody ? JSON.stringify(input.body) : undefined,
    });
  } catch (err) {
    // Network error — don't include the URL in the message to avoid reflecting
    // any injected URL back into LLM context
    const message = err instanceof Error ? err.message : 'Network error';
    return {
      content: [{ type: 'text', text: `Error: upstream request failed — ${message}` }],
      isError: true,
    };
  }

  // ── 5. Read and truncate response ──────────────────────────────────────────
  const contentType = response.headers.get('content-type') ?? '';
  const raw = await response.text();
  const truncated = raw.length > MAX_RESPONSE_BYTES;
  const body = truncated ? raw.slice(0, MAX_RESPONSE_BYTES) : raw;

  // Try to parse as JSON for cleaner LLM output
  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(body);
  } catch {
    parsedBody = body;
  }

  const result = {
    status: response.status,
    ok: response.ok,
    contentType: contentType.split(';')[0].trim(),
    body: parsedBody,
    ...(truncated ? { truncated: true, truncatedAt: MAX_RESPONSE_BYTES } : {}),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    isError: !response.ok,
  };
}
