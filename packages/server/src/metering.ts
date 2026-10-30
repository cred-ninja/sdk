/**
 * Server-side metering (draft-sweeney-wimse-credential-delegation-02
 * Sections 5.3 and 6.1). The Delegation Server measures every exercise
 * itself; an agent never reports its own quantities. A constraint key is
 * one of the keys below or it cannot be decided: an exercise under a key
 * with no meter is denied, as an unimplemented constraint type is.
 *
 * Request-side keys are measured before the upstream call and decided
 * there. Response-side keys are only known once the provider answers: an
 * over-limit response is withheld from the agent (the read happened, the
 * agent gets nothing) and audited. A catalogue operation with a page-size
 * parameter is capped up front instead, so the provider never returns more.
 */

export interface RequestMeasure {
  method: string;
  /** The resolved upstream URL. */
  destination: string;
  /** Bytes of the JSON body sent upstream (0 without one). */
  requestBytes: number;
}

export interface ResponseMeasure {
  responseBytes: number;
  /** Records in the response, or null when it is not JSON. */
  items: number | null;
}

/** Keys measured before the upstream call. */
export const REQUEST_METERS: Readonly<Record<string, (m: RequestMeasure) => number | string>> = Object.freeze({
  // Running counts: every exercise is one call.
  calls: () => 1,
  max_calls: () => 1,
  method: (m) => m.method,
  destination: (m) => m.destination,
  request_bytes: (m) => m.requestBytes,
});

/** Keys measured from the upstream response. */
export const RESPONSE_METERS: Readonly<Record<string, (m: ResponseMeasure) => number | null>> = Object.freeze({
  response_bytes: (m) => m.responseBytes,
  items: (m) => m.items,
  rows: (m) => m.items,
  max_rows: (m) => m.items,
  max_results: (m) => m.items,
});

/** Response-side keys that count records: the ones a page-size cap can bound. */
export const ITEM_KEYS: readonly string[] = ['items', 'rows', 'max_rows', 'max_results'];

export type MeterSide = 'request' | 'response';

export function meterSide(key: string): MeterSide | null {
  if (Object.prototype.hasOwnProperty.call(REQUEST_METERS, key)) return 'request';
  if (Object.prototype.hasOwnProperty.call(RESPONSE_METERS, key)) return 'response';
  return null;
}

/** Array members a provider wraps a listing in. */
const LIST_MEMBERS = ['items', 'files', 'data', 'results', 'records', 'values', 'value', 'workflow_runs', 'repositories'];

/**
 * Records in a parsed response: an array's length, the length of the one
 * listing member a wrapped list carries, else 1 for any other JSON value
 * (one resource). Null for a body that is not JSON.
 */
export function countItems(parsed: unknown, isJson: boolean): number | null {
  if (!isJson) return null;
  if (Array.isArray(parsed)) return parsed.length;
  if (typeof parsed === 'object' && parsed !== null) {
    const lists = LIST_MEMBERS.filter((member) => Array.isArray((parsed as Record<string, unknown>)[member]));
    if (lists.length === 1) return ((parsed as Record<string, unknown>)[lists[0]!] as unknown[]).length;
    // More than one listing member: the largest, so a cap is never undercounted.
    if (lists.length > 1) return Math.max(...lists.map((m) => ((parsed as Record<string, unknown>)[m] as unknown[]).length));
  }
  return 1;
}
