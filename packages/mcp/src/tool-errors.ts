/**
 * Structured error responses for MCP tool catch blocks.
 *
 * @credninja/sdk's CredError carries a machine-readable `code` and
 * `statusCode`, computed at the SDK boundary, but every tool's catch block
 * used to flatten it to `error.message` prose — discarding the very thing
 * an agent would branch on. See U3 in
 * docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { CredError } from '@credninja/sdk';

/**
 * When `error` is a CredError, includes its `code` and `statusCode`
 * alongside `message` as structured JSON. Non-CredError failures keep the
 * flattened-message-only shape (existing behavior, unchanged), falling back
 * to `nonErrorFallbackMessage` (default: `String(error)`) when a non-Error
 * value was thrown — callers with a more specific fallback for their own
 * call site (e.g. "Brokered upstream request failed") can supply one instead
 * of a raw stringified value.
 */
export function toolErrorResult(error: unknown, nonErrorFallbackMessage?: string): CallToolResult {
  if (error instanceof CredError) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ error: error.code, message: error.message, statusCode: error.statusCode }),
        },
      ],
      isError: true,
    };
  }

  const message = error instanceof Error ? error.message : (nonErrorFallbackMessage ?? String(error));
  return {
    content: [{ type: 'text', text: `Error: ${message}` }],
    isError: true,
  };
}
