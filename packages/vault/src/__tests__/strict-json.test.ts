import { describe, it, expect } from 'vitest';
import { parseStrictJson, StrictJsonError } from '../strict-json.js';

function codeOf(text: string): string | null {
  try {
    parseStrictJson(text);
    return null;
  } catch (err) {
    if (err instanceof StrictJsonError) return err.code;
    throw err;
  }
}

describe('parseStrictJson', () => {
  it('parses ordinary JSON values identically to JSON.parse', () => {
    const samples = [
      '{"a":1,"b":[true,false,null],"c":{"d":"e"}}',
      ' \n\t[1, -2, 3.5, 1e3, -0.25E-2, 0] ',
      '"plain"',
      '"esc \\" \\\\ \\/ \\b \\f \\n \\r \\t \\u00e9 \\ud83d\\ude00"',
      'null', 'true', '0', '-0', '9007199254740991', '-9007199254740991',
      '{"aud":null,"authorization_details":[{"constraints":[],"scopes":["probe.read"],"type":"agent_delegation"}],"del_depth":0,"del_max_depth":2,"exp":60,"iat":0,"iss":"attenu-guard","jti":"chain:n0","sub":"parser-probe"}',
      '{"ключ":"значение","emoji":"😀"}',
    ];
    for (const s of samples) expect(parseStrictJson(s)).toEqual(JSON.parse(s));
  });

  it('rejects duplicate member names at any depth', () => {
    expect(codeOf('{"del_depth":0,"del_depth":0}')).toBe('duplicate_member');
    expect(codeOf('{"a":{"x":1,"x":2}}')).toBe('duplicate_member');
    expect(codeOf('[{"k":1},{"k":2,"k":3}]')).toBe('duplicate_member');
    expect(codeOf('{"a":1,"b":{"a":2}}')).toBeNull(); // same name in different objects is fine
  });

  it('rejects integers outside the binary64 exact range without rounding', () => {
    expect(codeOf('9007199254740992')).toBe('unsafe_integer');
    expect(codeOf('-9007199254740992')).toBe('unsafe_integer');
    expect(codeOf('{"exp":9007199254740992}')).toBe('unsafe_integer');
    expect(codeOf('123456789012345678901234567890')).toBe('unsafe_integer');
    expect(codeOf('9007199254740991')).toBeNull();
    // Non-integer forms are not subject to the check (binary64 rounding is expected for them).
    expect(codeOf('9007199254740992.0')).toBeNull();
    expect(codeOf('9.007199254740992e15')).toBeNull();
  });

  it('rejects what RFC 8259 rejects', () => {
    for (const bad of [
      '', ' ', '{', '[1,]', '{"a":1,}', "{'a':1}", '{a:1}', 'NaN', 'Infinity', '-Infinity',
      '01', '1.', '.5', '+1', '1e', '"\u0001"', '"unterminated', '"\\x41"', '"\\u12"',
      'tru', 'nul', '{"a":1} x', '[1] [2]', '{"a" 1}', '//c\n1',
    ]) {
      expect(codeOf(bad), JSON.stringify(bad)).toBe('syntax');
    }
  });

  it('returns null-prototype objects so wire keys cannot shadow Object.prototype', () => {
    const v = parseStrictJson('{"__proto__":{"polluted":true},"constructor":1}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(v)).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(v, '__proto__')).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('bounds nesting at 256 containers, empty or not', () => {
    expect(codeOf('['.repeat(256) + ']'.repeat(256))).toBeNull();
    expect(codeOf('['.repeat(256) + '1' + ']'.repeat(256))).toBeNull();
    expect(codeOf('['.repeat(257) + ']'.repeat(257))).toBe('syntax');
    expect(codeOf('['.repeat(257) + '1' + ']'.repeat(257))).toBe('syntax');
    expect(codeOf('{"a":'.repeat(256) + '1' + '}'.repeat(256))).toBeNull();
    expect(codeOf('{"a":'.repeat(257) + '1' + '}'.repeat(257))).toBe('syntax');
    expect(codeOf('['.repeat(300) + ']'.repeat(300))).toBe('syntax');
  });

  it('reports the offset of the failure', () => {
    try {
      parseStrictJson('{"a":1,"a":2}');
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(StrictJsonError);
      expect((err as StrictJsonError).offset).toBe(10);
    }
  });
});
