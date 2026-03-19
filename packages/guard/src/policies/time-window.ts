/**
 * @credninja/guard — Time Window Policy
 *
 * Restrict when delegations can occur based on time of day and day of week.
 */

import type { CredPolicy, GuardContext, PolicyResult, TimeWindowPolicyConfig } from '../types.js';

export class TimeWindowPolicy implements CredPolicy {
  readonly name = 'time-window';
  private readonly config: TimeWindowPolicyConfig;

  constructor(config: TimeWindowPolicyConfig) {
    this.config = config;
  }

  evaluate(ctx: GuardContext): PolicyResult {
    const { timestamp } = ctx;
    const { allowedHours, timezone = 'UTC', allowedDays } = this.config;

    // Parse timestamp
    const date = new Date(timestamp);
    if (isNaN(date.getTime())) {
      return {
        decision: 'DENY',
        policy: this.name,
        reason: 'Invalid timestamp',
      };
    }

    // Get hour and day in the configured timezone
    const { hour, dayOfWeek } = this.getTimeInTimezone(date, timezone);

    // Check day of week (if configured)
    if (allowedDays && allowedDays.length > 0) {
      if (!allowedDays.includes(dayOfWeek)) {
        return {
          decision: 'DENY',
          policy: this.name,
          reason: `Day ${dayOfWeek} not in allowed days: ${allowedDays.join(', ')}`,
        };
      }
    }

    // Check hour window
    const inWindow = this.isHourInWindow(hour, allowedHours.start, allowedHours.end);
    if (!inWindow) {
      return {
        decision: 'DENY',
        policy: this.name,
        reason: `Hour ${hour} not in allowed window: ${allowedHours.start}-${allowedHours.end} (${timezone})`,
      };
    }

    return {
      decision: 'ALLOW',
      policy: this.name,
      reason: `Within allowed time window: ${allowedHours.start}-${allowedHours.end} (${timezone})`,
    };
  }

  private getTimeInTimezone(date: Date, timezone: string): { hour: number; dayOfWeek: number } {
    try {
      // Use Intl.DateTimeFormat to get time parts in the target timezone
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: timezone,
        hour: 'numeric',
        hour12: false,
        weekday: 'short',
      });

      const parts = formatter.formatToParts(date);
      const hourPart = parts.find((p) => p.type === 'hour');
      const weekdayPart = parts.find((p) => p.type === 'weekday');

      // Some ICU/Node versions return "24" for midnight with hour12:false — normalize
      const rawHour = hourPart ? parseInt(hourPart.value, 10) : date.getUTCHours();
      const hour = rawHour % 24;

      // Map weekday names to numbers (0=Sunday)
      const weekdayMap: Record<string, number> = {
        Sun: 0,
        Mon: 1,
        Tue: 2,
        Wed: 3,
        Thu: 4,
        Fri: 5,
        Sat: 6,
      };
      const dayOfWeek = weekdayPart ? weekdayMap[weekdayPart.value] ?? 0 : date.getUTCDay();

      return { hour, dayOfWeek };
    } catch {
      // Fallback to UTC if timezone is invalid
      return {
        hour: date.getUTCHours(),
        dayOfWeek: date.getUTCDay(),
      };
    }
  }

  private isHourInWindow(hour: number, start: number, end: number): boolean {
    // Full day window (0-24) is always open
    if (start === 0 && end === 24) return true;
    // Handle wrap-around (e.g., 22-6 for overnight window)
    if (start <= end) {
      // Normal case: 9-17 means 9:00 to 16:59
      return hour >= start && hour < end;
    } else {
      // Wrap-around case: 22-6 means 22:00 to 05:59
      return hour >= start || hour < end;
    }
  }
}

/**
 * Factory function to create a time window policy.
 */
export function timeWindowPolicy(config: TimeWindowPolicyConfig): TimeWindowPolicy {
  return new TimeWindowPolicy(config);
}
