/**
 * Scope map loader and resolver.
 *
 * The map is data, loaded from config/scope-map.json. Resolution is
 * fail-closed: an unmapped tool resolves to `deny` (when unmappedPolicy=deny),
 * and an explicit `{ deny: true }` disposition always denies.
 */

import { readFileSync } from 'node:fs';
import type { ArgConstraints } from './arg-policy.js';

export type ToolDisposition =
  | { kind: 'scope'; scope: string }
  | { kind: 'deny'; reason: string }
  | { kind: 'unknown' };

type ToolEntry = string | { deny?: boolean; scope?: string; reason?: string; args?: ArgConstraints };

interface RawScopeMap {
  service: string;
  unmappedPolicy: 'deny' | 'allow';
  scopes?: Record<string, string>;
  tools: Record<string, ToolEntry>;
}

export class ScopeMap {
  readonly service: string;
  readonly unmappedPolicy: 'deny' | 'allow';
  readonly scopeNames: string[];
  private readonly tools: Record<string, ToolEntry>;

  private constructor(raw: RawScopeMap) {
    this.service = raw.service;
    this.unmappedPolicy = raw.unmappedPolicy;
    this.scopeNames = Object.keys(raw.scopes ?? {});
    this.tools = raw.tools;
  }

  static load(path: string): ScopeMap {
    let raw: RawScopeMap;
    try {
      raw = JSON.parse(readFileSync(path, 'utf8')) as RawScopeMap;
    } catch (err) {
      throw new Error(`Failed to load scope map at ${path}: ${(err as Error).message}`);
    }
    if (!raw.tools || typeof raw.tools !== 'object') {
      throw new Error(`Scope map at ${path} has no "tools" object`);
    }
    if (raw.unmappedPolicy !== 'deny' && raw.unmappedPolicy !== 'allow') {
      throw new Error(`Scope map at ${path} must set "unmappedPolicy" to "deny" or "allow"`);
    }
    return new ScopeMap(raw);
  }

  /** Number of tools placed in the map (excludes deny-only entries from scope totals). */
  toolCount(): number {
    return Object.keys(this.tools).length;
  }

  /**
   * Resolve the disposition for a tool name.
   * - explicit { deny: true }  -> deny
   * - string scope             -> scope
   * - object with scope        -> scope
   * - not present + deny policy -> deny (fail-closed)
   * - not present + allow policy -> unknown (caller may forward)
   */
  resolve(tool: string): ToolDisposition {
    const entry = this.tools[tool];
    if (entry === undefined) {
      if (this.unmappedPolicy === 'deny') {
        return { kind: 'deny', reason: `unmapped tool "${tool}" (unmappedPolicy=deny)` };
      }
      return { kind: 'unknown' };
    }
    if (typeof entry === 'string') {
      return { kind: 'scope', scope: entry };
    }
    if (entry.deny) {
      return { kind: 'deny', reason: entry.reason ?? `tool "${tool}" is denied by scope map` };
    }
    if (entry.scope) {
      return { kind: 'scope', scope: entry.scope };
    }
    // Malformed entry -> fail closed.
    return { kind: 'deny', reason: `tool "${tool}" has a malformed scope-map entry` };
  }

  /** Per-argument constraints declared for a tool, if any. */
  argConstraints(tool: string): ArgConstraints | undefined {
    const entry = this.tools[tool];
    if (entry && typeof entry === 'object') return entry.args;
    return undefined;
  }
}
