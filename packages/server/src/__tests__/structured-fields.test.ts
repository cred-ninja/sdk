import { describe, it, expect } from 'vitest';
import {
  parseDictionary,
  parseItem,
  serializeInnerList,
  serializeBareItem,
  StructuredFieldError,
  SF_LIMITS,
  type InnerList,
} from '../identity/structured-fields.js';

describe('RFC 8941 structured fields', () => {
  it('parses a two-member dictionary of inner lists with parameters, in order', () => {
    const d = parseDictionary('sig1=("@method" "@path";req);created=1;tag="t", sig2=("x")');
    expect([...d.keys()]).toEqual(['sig1', 'sig2']);
    const m = d.get('sig1') as InnerList;
    expect(m.kind).toBe('inner-list');
    expect(m.items.map((i) => i.value)).toEqual([{ type: 'string', value: '@method' }, { type: 'string', value: '@path' }]);
    expect(m.items[1].params.get('req')).toEqual({ type: 'boolean', value: true });
    expect(m.params.get('created')).toEqual({ type: 'integer', value: 1 });
  });

  it('round-trips an inner list exactly (the @signature-params serialization)', () => {
    const text = '("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="7f3a";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/x";wimse-sign-response';
    const d = parseDictionary(`sig1=${text}`);
    expect(serializeInnerList(d.get('sig1') as InnerList)).toBe(text);
  });

  it('decodes string escapes and re-escapes them', () => {
    const item = parseItem('"a\\"b\\\\c"');
    expect(item.value).toEqual({ type: 'string', value: 'a"b\\c' });
    expect(serializeBareItem(item.value)).toBe('"a\\"b\\\\c"');
  });

  it.each([
    ['an invalid escape', '"a\\nb"'],
    ['an unterminated string', '"abc'],
    ['a non-ASCII character', '"café"'],
    ['an invalid boolean', '?2'],
    ['a decimal with four fractional digits', '1.2345'],
    ['an integer with 16 digits', '1234567890123456'],
    ['a key starting with a digit', '1a=1'],
  ])('refuses %s', (_why, input) => {
    expect(() => (input.includes('=') ? parseDictionary(input) : parseItem(input))).toThrow(StructuredFieldError);
  });

  it('decodes byte sequences and refuses bad base64 characters or misplaced padding', () => {
    expect(parseItem(':aGVsbG8=:').value).toEqual({ type: 'bytes', value: Buffer.from('hello') });
    expect(() => parseItem(':aGV$bG8=:')).toThrow(StructuredFieldError);
    expect(() => parseItem(':aG=Vs:')).toThrow(StructuredFieldError);
  });

  it('a dictionary member without a value is Boolean true, and a repeated key keeps the last value', () => {
    const d = parseDictionary('a, b=2, a=3');
    expect([...d.keys()]).toEqual(['a', 'b']);
    expect(d.get('a')).toMatchObject({ value: { type: 'integer', value: 3 } });
  });

  it('refuses a trailing comma and a missing separator', () => {
    expect(() => parseDictionary('a=1,')).toThrow(StructuredFieldError);
    expect(() => parseDictionary('a=1 b=2')).toThrow(StructuredFieldError);
  });

  it('caps input size and member count in linear time', () => {
    expect(() => parseDictionary('a=1'.padEnd(SF_LIMITS.maxInputLength + 1, ' '))).toThrow(/too long/);
    const many = Array.from({ length: SF_LIMITS.maxMembers + 1 }, (_, i) => `k${i}=1`).join(', ');
    expect(() => parseDictionary(many)).toThrow(/too many/);
    // A pathological unterminated inner list fails fast rather than backtracking.
    const t0 = Date.now();
    expect(() => parseDictionary(`a=(${'"x" '.repeat(60)}`)).toThrow(StructuredFieldError);
    expect(Date.now() - t0).toBeLessThan(200);
  });
});
