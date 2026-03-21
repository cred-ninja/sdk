export const DEFAULT_ROTATION_GRACE_HOURS = 24;

export function computeGraceExpiry(now: Date, gracePeriodHours = DEFAULT_ROTATION_GRACE_HOURS): Date {
  if (!Number.isFinite(gracePeriodHours) || gracePeriodHours <= 0) {
    throw new Error('gracePeriodHours must be a positive number');
  }

  return new Date(now.getTime() + gracePeriodHours * 60 * 60 * 1000);
}
