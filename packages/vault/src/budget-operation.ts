import { createHash } from 'node:crypto';

/** Opaque prepared handle. Only prepareBudgetOperation can create a usable one. */
declare const preparedBrand: unique symbol;
export interface PreparedBudgetOperation { readonly [preparedBrand]: true }
export interface FrozenBudgetOperation {
  readonly method: string;
  readonly target: string;
  readonly headers: Readonly<Record<string, string>>;
  /** Detached, frozen exact bytes; transport can use Buffer.from(body). */
  readonly body: readonly number[];
}
export interface BudgetOperationInput {
  method: string;
  target: string;
  headers?: Readonly<Record<string, string>>;
  body?: Uint8Array;
}
const prepared = new WeakMap<PreparedBudgetOperation, FrozenBudgetOperation>();

export function closedFields(value: unknown, allowed: readonly string[]): void {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('invalid_object');
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.includes(key)) throw new TypeError('unsupported_field');
    if (!('value' in Object.getOwnPropertyDescriptor(value, key)!)) throw new TypeError('invalid_accessor');
  }
}

const FORWARDED_HEADERS = ['accept', 'content-type', 'if-match', 'if-none-match', 'idempotency-key'];

export function prepareBudgetOperation(input: BudgetOperationInput): PreparedBudgetOperation {
  closedFields(input, ['method', 'target', 'headers', 'body']);
  const { method: inputMethod, target, headers: inputHeaders, body: inputBody } = input;
  if (typeof inputMethod !== 'string' || !/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/i.test(inputMethod)) throw new TypeError('invalid_method');
  if (typeof target !== 'string') throw new TypeError('invalid_target');
  const url = new URL(target);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash
    || [...url.searchParams.keys()].some(key => /^(access_token|token|api_key|apikey|key|authorization|client_secret)$/i.test(key))) throw new TypeError('invalid_target');
  if (inputBody !== undefined && !(inputBody instanceof Uint8Array)) throw new TypeError('invalid_body');
  // The intrinsic iterator reads typed-array slots, not caller-defined iteration,
  // length, buffer or coercion hooks, and yields only primitive numeric bytes.
  const body = Object.freeze(inputBody === undefined ? [] : Array.from(Uint8Array.prototype.values.call(inputBody)));
  const method = inputMethod.toUpperCase();
  if (['GET', 'HEAD'].includes(method) && body.length) throw new TypeError('invalid_body');
  const headers: Record<string, string> = {};
  if (inputHeaders !== undefined) {
    closedFields(inputHeaders, Object.keys(inputHeaders));
    for (const [key, value] of Object.entries(inputHeaders)) {
      const name = key.toLowerCase();
      if (!FORWARDED_HEADERS.includes(name)) throw new TypeError('unsupported_header');
      if (Object.prototype.hasOwnProperty.call(headers, name)) throw new TypeError('duplicate_header');
      if (typeof value !== 'string' || /[^\x20-\x7e]/u.test(value)) throw new TypeError('invalid_header');
      headers[name] = value.trim();
    }
  }
  const operation = Object.freeze({
    method,
    target: url.href,
    headers: Object.freeze(Object.fromEntries(Object.entries(headers).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))),
    body,
  });
  const handle = Object.freeze({}) as PreparedBudgetOperation;
  prepared.set(handle, operation);
  return handle;
}

export function frozenOperation(handle: PreparedBudgetOperation): FrozenBudgetOperation {
  const operation = prepared.get(handle);
  if (!operation) throw new Error('invalid_prepared_operation');
  return operation;
}

/** Internal only: never return a request digest to the caller. */
export function operationFingerprint(context: unknown, handle: PreparedBudgetOperation): string {
  const operation = frozenOperation(handle);
  const hash = createHash('sha256');
  hash.update(JSON.stringify([context, operation.method, operation.target, operation.headers, operation.body.length]));
  hash.update(Buffer.from(operation.body));
  return hash.digest('hex');
}
