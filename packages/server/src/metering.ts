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

/**
 * Records in a parsed response, without trusting a provider's member
 * names: the total length of every array reachable through objects alone
 * (a top-level array, `files`, `messages`, GraphQL `data.x.nodes`, and so
 * on), not counting arrays inside the records themselves. A JSON value with
 * no such array is one resource. An empty body is no records; any other
 * body that is not JSON cannot be measured (null).
 */
export function countItems(parsed: unknown, isJson: boolean, empty = false): number | null {
  if (empty) return 0;
  if (!isJson) return null;
  let total = 0;
  let found = false;
  const visit = (value: unknown, depth: number): void => {
    if (depth > 32) return;
    if (Array.isArray(value)) {
      found = true;
      total += value.length;
      return;
    }
    if (typeof value === 'object' && value !== null) {
      for (const member of Object.values(value)) visit(member, depth + 1);
    }
  };
  visit(parsed, 0);
  return found ? total : 1;
}

/**
 * Whether `value` is within a destination prefix at a URL boundary: the
 * prefix ends in '/', '?' or '#', or is followed in `value` by one of them
 * or by nothing. Stricter than the generic string prefix, so a narrowing
 * that held stays narrowing: `files/abc` admits `files/abc?x` and
 * `files/abc/export`, never `files/abcXYZ`.
 */
export function destinationWithinPrefix(value: string, prefix: string): boolean {
  if (!value.startsWith(prefix)) return false;
  if (value.length === prefix.length || /[/?#]$/.test(prefix)) return true;
  return '/?#'.includes(value[prefix.length]!);
}
