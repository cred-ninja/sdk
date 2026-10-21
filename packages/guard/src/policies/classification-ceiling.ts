/**
 * @credninja/guard: Classification Ceiling Policy
 *
 * Deny access to resources classified above the agent's ceiling, and
 * optionally deny moving data from a higher level to a lower one.
 * Fails closed: unknown levels, unknown agents and resolver errors are DENY,
 * and the policy never throws, so GuardConfig.onError: 'allow' cannot turn
 * an error into access.
 */

import type {
  ClassificationCeilingDenyCode,
  ClassificationCeilingPolicyConfig,
  CredPolicy,
  GuardContext,
  PolicyResult,
} from '../types.js';

export interface ClassificationCeilingPolicyResult extends PolicyResult {
  /** Set on every DENY */
  code?: ClassificationCeilingDenyCode;
}

/** A level read from the context: absent, or present with its rank (-1 when unknown) */
type ReadLevel = { present: false } | { present: true; value: unknown; rank: number };

export class ClassificationCeilingPolicy implements CredPolicy {
  readonly name = 'classification-ceiling';
  private readonly config: ClassificationCeilingPolicyConfig;
  private readonly ranks: Map<string, number>;

  constructor(config: ClassificationCeilingPolicyConfig) {
    if (!Array.isArray(config?.levels) || config.levels.length === 0) {
      throw new TypeError('classificationCeilingPolicy requires a non-empty levels array');
    }
    const ranks = new Map<string, number>();
    config.levels.forEach((level, index) => {
      if (typeof level !== 'string' || level.length === 0) {
        throw new TypeError('classificationCeilingPolicy: levels must be non-empty strings');
      }
      if (ranks.has(level)) {
        throw new TypeError(`classificationCeilingPolicy: duplicate level "${level}"`);
      }
      ranks.set(level, index);
    });
    if (!config.agentCeilings && !config.resolveAgentCeiling) {
      throw new TypeError('classificationCeilingPolicy requires agentCeilings or resolveAgentCeiling');
    }
    this.config = config;
    this.ranks = ranks;
  }

  evaluate(ctx: GuardContext): ClassificationCeilingPolicyResult {
    const { noWriteDown = false, onMissing = 'deny' } = this.config;

    // Read every level the request names before looking at the agent
    let resource: ReadLevel;
    let source: ReadLevel = { present: false };
    let destination: ReadLevel = { present: false };
    try {
      resource = this.readLevel(
        this.config.resolveResourceLevel
          ? this.config.resolveResourceLevel(ctx)
          : ctx.metadata?.classification,
      );
      if (noWriteDown) {
        const flow = this.config.resolveFlow
          ? this.config.resolveFlow(ctx)
          : {
              source: ctx.metadata?.sourceClassification,
              destination: ctx.metadata?.destinationClassification,
            };
        source = this.readLevel(flow?.source);
        destination = this.readLevel(flow?.destination);
      }
    } catch (error) {
      return this.deny('classification_unknown', `Classification resolver failed: ${errorMessage(error)}`);
    }

    // SKIP only when nothing is classified and the config allows it
    if (!resource.present && !source.present && !destination.present) {
      if (onMissing === 'skip') {
        return { decision: 'SKIP', policy: this.name, reason: 'No classification present' };
      }
      return this.deny('classification_missing', 'No classification present');
    }

    for (const level of [resource, source, destination]) {
      if (level.present && level.rank < 0) {
        return this.deny('classification_unknown', `Unknown classification level: ${describe(level.value)}`);
      }
    }

    // A flow that names only one side cannot be checked for write-down
    if (noWriteDown && source.present !== destination.present) {
      return this.deny(
        'classification_missing',
        'Data flow names only one of source and destination classification',
      );
    }

    const ceiling = this.resolveCeiling(ctx);
    if (typeof ceiling !== 'number') {
      return this.deny('ceiling_unknown', ceiling.reason);
    }
    const ceilingLevel = this.config.levels[ceiling];

    const checks: Array<[string, ReadLevel]> = [
      ['Resource', resource],
      ['Source', source],
      ['Destination', destination],
    ];
    for (const [label, level] of checks) {
      if (level.present && level.rank > ceiling) {
        return this.deny(
          'classification_exceeded',
          `${label} classification ${describe(level.value)} exceeds agent ceiling ${ceilingLevel}`,
        );
      }
    }

    if (source.present && destination.present && source.rank > destination.rank) {
      return this.deny(
        'write_down_blocked',
        `Write-down blocked: ${describe(source.value)} to ${describe(destination.value)}`,
      );
    }

    return {
      decision: 'ALLOW',
      policy: this.name,
      reason: `Within agent ceiling ${ceilingLevel}`,
    };
  }

  private readLevel(value: unknown): ReadLevel {
    if (value === undefined || value === null) return { present: false };
    const rank = typeof value === 'string' ? this.ranks.get(value) : undefined;
    return { present: true, value, rank: rank ?? -1 };
  }

  /**
   * Resolve the agent's ceiling rank. A resolver wins over the map; with the
   * map, the agentTokenHash entry applies, or with trustAgentDid the lower of
   * the agentDid and agentTokenHash entries.
   */
  private resolveCeiling(ctx: GuardContext): number | { reason: string } {
    let candidates: unknown[];
    try {
      if (this.config.resolveAgentCeiling) {
        candidates = [this.config.resolveAgentCeiling(ctx)];
      } else {
        const ceilings = this.config.agentCeilings ?? {};
        const ids = this.config.trustAgentDid ? [ctx.agentDid, ctx.agentTokenHash] : [ctx.agentTokenHash];
        candidates = ids
          .filter((id): id is string => typeof id === 'string' && Object.hasOwn(ceilings, id))
          .map((id) => ceilings[id]);
      }
    } catch (error) {
      return { reason: `Agent ceiling resolver failed: ${errorMessage(error)}` };
    }

    const defined = candidates.filter((c) => c !== undefined && c !== null);
    if (defined.length === 0) {
      return { reason: 'No classification ceiling for agent' };
    }
    let lowest = Infinity;
    for (const candidate of defined) {
      const rank = typeof candidate === 'string' ? this.ranks.get(candidate) : undefined;
      if (rank === undefined) {
        return { reason: `Agent ceiling is not a known level: ${describe(candidate)}` };
      }
      lowest = Math.min(lowest, rank);
    }
    return lowest;
  }

  private deny(code: ClassificationCeilingDenyCode, reason: string): ClassificationCeilingPolicyResult {
    return { decision: 'DENY', policy: this.name, reason, code };
  }
}

function describe(value: unknown): string {
  return typeof value === 'string' ? `"${value}"` : `(${typeof value})`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Factory function to create a classification ceiling policy.
 */
export function classificationCeilingPolicy(config: ClassificationCeilingPolicyConfig): ClassificationCeilingPolicy {
  return new ClassificationCeilingPolicy(config);
}
