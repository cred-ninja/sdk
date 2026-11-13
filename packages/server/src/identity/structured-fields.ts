/**
 * Structured Field Values for HTTP (RFC 8941), the subset HTTP Message
 * Signatures (RFC 9421) needs: Dictionaries whose members are Items or Inner
 * Lists, each with Parameters, and the bare item types Integer, Decimal,
 * String, Token, Byte Sequence and Boolean.
 *
 * Parsing follows the algorithms of RFC 8941 §4.2 exactly, one character at a
 * time with no regular expressions over the whole input, so attacker-supplied
 * Signature-Input and Signature fields cost linear time. Input length and
 * member counts are capped. Anything outside the grammar throws
 * StructuredFieldError; a caller treats that as a malformed field.
 *
 * Serialization follows RFC 8941 §4.1 and is canonical: RFC 9421 §2.3 builds
 * the `@signature-params` line by serializing the parsed parameters.
 */

export class StructuredFieldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StructuredFieldError';
  }
}

export type BareItem =
  | { type: 'integer'; value: number }
  | { type: 'decimal'; value: number }
  | { type: 'string'; value: string }
  | { type: 'token'; value: string }
  | { type: 'bytes'; value: Buffer }
  | { type: 'boolean'; value: boolean };

/** Ordered parameters; a repeated key keeps its first position and its last value (RFC 8941 §4.2.3.2). */
export type Parameters = Map<string, BareItem>;

export interface Item {
  kind: 'item';
  value: BareItem;
  params: Parameters;
}

export interface InnerList {
  kind: 'inner-list';
  items: Item[];
  params: Parameters;
}

export type Dictionary = Map<string, Item | InnerList>;

/** Bounds on attacker-controlled input. */
export const SF_LIMITS = {
  maxInputLength: 16_384,
  maxMembers: 64,
  maxInnerListItems: 64,
  maxParameters: 32,
} as const;

const DIGIT = (c: string) => c >= '0' && c <= '9';
const LCALPHA = (c: string) => c >= 'a' && c <= 'z';
const ALPHA = (c: string) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
/** RFC 9110 tchar. */
const TCHAR = (c: string) => ALPHA(c) || DIGIT(c) || "!#$%&'*+-.^_`|~".includes(c);

class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  fail(why: string): never {
    throw new StructuredFieldError(`${why} at offset ${this.i}`);
  }
  peek(): string {
    return this.s[this.i] ?? '';
  }
  eof(): boolean {
    return this.i >= this.s.length;
  }
  skipSP(): void {
    while (this.s[this.i] === ' ') this.i++;
  }
  /** OWS = *( SP / HTAB ) */
  skipOWS(): void {
    while (this.s[this.i] === ' ' || this.s[this.i] === '\t') this.i++;
  }

  // RFC 8941 §4.2.2
  dictionary(): Dictionary {
    const dict: Dictionary = new Map();
    while (!this.eof()) {
      const key = this.key();
      let member: Item | InnerList;
      if (this.peek() === '=') {
        this.i++;
        member = this.itemOrInnerList();
      } else {
        member = { kind: 'item', value: { type: 'boolean', value: true }, params: this.parameters() };
      }
      // A repeated key overwrites the value; Map.set keeps the first position.
      dict.set(key, member);
      if (dict.size > SF_LIMITS.maxMembers) this.fail('too many dictionary members');
      this.skipOWS();
      if (this.eof()) return dict;
      if (this.peek() !== ',') this.fail('expected "," between dictionary members');
      this.i++;
      this.skipOWS();
      if (this.eof()) this.fail('trailing comma in dictionary');
    }
    return dict;
  }

  itemOrInnerList(): Item | InnerList {
    return this.peek() === '(' ? this.innerList() : this.item();
  }

  // RFC 8941 §4.2.1.2
  innerList(): InnerList {
    if (this.peek() !== '(') this.fail('expected "("');
    this.i++;
    const items: Item[] = [];
    while (!this.eof()) {
      this.skipSP();
      if (this.peek() === ')') {
        this.i++;
        return { kind: 'inner-list', items, params: this.parameters() };
      }
      items.push(this.item());
      if (items.length > SF_LIMITS.maxInnerListItems) this.fail('too many inner list items');
      const c = this.peek();
      if (c !== ' ' && c !== ')') this.fail('expected SP or ")" in inner list');
    }
    this.fail('unterminated inner list');
  }

  // RFC 8941 §4.2.3
  item(): Item {
    const value = this.bareItem();
    return { kind: 'item', value, params: this.parameters() };
  }

  // RFC 8941 §4.2.3.1
  bareItem(): BareItem {
    const c = this.peek();
    if (c === '-' || DIGIT(c)) return this.number();
    if (c === '"') return this.string();
    if (c === '*' || ALPHA(c)) return this.token();
    if (c === ':') return this.bytes();
    if (c === '?') return this.boolean();
    this.fail('unrecognized bare item');
  }

  // RFC 8941 §4.2.3.2
  parameters(): Parameters {
    const params: Parameters = new Map();
    while (this.peek() === ';') {
      this.i++;
      this.skipSP();
      const key = this.key();
      let value: BareItem = { type: 'boolean', value: true };
      if (this.peek() === '=') {
        this.i++;
        value = this.bareItem();
      }
      params.set(key, value);
      if (params.size > SF_LIMITS.maxParameters) this.fail('too many parameters');
    }
    return params;
  }

  // RFC 8941 §4.2.3.3
  key(): string {
    const c = this.peek();
    if (!(LCALPHA(c) || c === '*')) this.fail('key must start with lcalpha or "*"');
    const start = this.i;
    while (!this.eof()) {
      const d = this.peek();
      if (!(LCALPHA(d) || DIGIT(d) || d === '_' || d === '-' || d === '.' || d === '*')) break;
      this.i++;
    }
    return this.s.slice(start, this.i);
  }

  // RFC 8941 §4.2.4
  number(): BareItem {
    let sign = 1;
    let isDecimal = false;
    let digits = '';
    if (this.peek() === '-') {
      sign = -1;
      this.i++;
    }
    if (!DIGIT(this.peek())) this.fail('number needs a digit');
    while (!this.eof()) {
      const c = this.peek();
      if (DIGIT(c)) {
        digits += c;
      } else if (!isDecimal && c === '.') {
        if (digits.length > 12) this.fail('decimal integer part too long');
        digits += c;
        isDecimal = true;
      } else {
        break;
      }
      this.i++;
      if (!isDecimal && digits.length > 15) this.fail('integer too long');
      if (isDecimal && digits.length > 16) this.fail('decimal too long');
    }
    if (!isDecimal) return { type: 'integer', value: sign * Number(digits) };
    if (digits.endsWith('.')) this.fail('decimal ends with "."');
    if (digits.length - digits.indexOf('.') - 1 > 3) this.fail('decimal has more than 3 fractional digits');
    return { type: 'decimal', value: sign * Number(digits) };
  }

  // RFC 8941 §4.2.5
  string(): BareItem {
    this.i++; // opening DQUOTE
    let out = '';
    while (!this.eof()) {
      const c = this.s[this.i++];
      if (c === '\\') {
        if (this.eof()) this.fail('string ends after backslash');
        const n = this.s[this.i++];
        if (n !== '"' && n !== '\\') this.fail('invalid escape in string');
        out += n;
      } else if (c === '"') {
        return { type: 'string', value: out };
      } else {
        const code = c.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) this.fail('string has a character outside VCHAR/SP');
        out += c;
      }
    }
    this.fail('unterminated string');
  }

  // RFC 8941 §4.2.6
  token(): BareItem {
    const start = this.i;
    this.i++; // first char already checked
    while (!this.eof()) {
      const c = this.peek();
      if (!(TCHAR(c) || c === ':' || c === '/')) break;
      this.i++;
    }
    return { type: 'token', value: this.s.slice(start, this.i) };
  }

  // RFC 8941 §4.2.7
  bytes(): BareItem {
    this.i++; // opening ":"
    const start = this.i;
    while (!this.eof() && this.peek() !== ':') {
      const c = this.peek();
      if (!(ALPHA(c) || DIGIT(c) || c === '+' || c === '/' || c === '=')) this.fail('invalid byte sequence character');
      this.i++;
    }
    if (this.eof()) this.fail('unterminated byte sequence');
    const b64 = this.s.slice(start, this.i);
    this.i++; // closing ":"
    // "=" may appear only as trailing padding.
    const firstPad = b64.indexOf('=');
    if (firstPad !== -1 && (/[^=]/.test(b64.slice(firstPad)) || b64.length - firstPad > 2)) this.fail('invalid base64 padding');
    if (b64.length % 4 === 1) this.fail('invalid base64 length');
    return { type: 'bytes', value: Buffer.from(b64, 'base64') };
  }

  // RFC 8941 §4.2.8
  boolean(): BareItem {
    this.i++; // "?"
    const c = this.s[this.i++];
    if (c === '1') return { type: 'boolean', value: true };
    if (c === '0') return { type: 'boolean', value: false };
    this.fail('invalid boolean');
  }
}

function checkInput(input: string): void {
  if (typeof input !== 'string') throw new StructuredFieldError('field value is not a string');
  if (input.length > SF_LIMITS.maxInputLength) throw new StructuredFieldError('field value too long');
  // Field values are ASCII here; anything else is outside the grammar.
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code > 0x7e || (code < 0x20 && code !== 0x09)) throw new StructuredFieldError('field value has a non-ASCII or control character');
  }
}

/** Parse a Dictionary field value (RFC 8941 §4.2 with field_type "dictionary"). */
export function parseDictionary(input: string): Dictionary {
  checkInput(input);
  const p = new Parser(input);
  p.skipSP();
  const dict = p.dictionary();
  // §4.2 step 5-6: after the top-level value only SP may remain; the
  // dictionary loop already consumed to end of input or failed.
  return dict;
}

/** Parse an Item field value, e.g. a single component identifier. */
export function parseItem(input: string): Item {
  checkInput(input);
  const p = new Parser(input);
  p.skipSP();
  const item = p.item();
  p.skipSP();
  if (!p.eof()) p.fail('trailing characters after item');
  return item;
}

// ── Serialization (RFC 8941 §4.1) ────────────────────────────────────────────

export function serializeBareItem(item: BareItem): string {
  switch (item.type) {
    case 'integer':
      if (!Number.isInteger(item.value) || Math.abs(item.value) > 999_999_999_999_999) {
        throw new StructuredFieldError('integer out of range');
      }
      return String(item.value);
    case 'decimal': {
      const rounded = Math.round(item.value * 1000) / 1000;
      if (Math.abs(Math.trunc(rounded)) > 999_999_999_999) throw new StructuredFieldError('decimal out of range');
      const s = rounded.toFixed(3).replace(/0+$/, '');
      return s.endsWith('.') ? `${s}0` : s;
    }
    case 'string': {
      let out = '"';
      for (const c of item.value) {
        const code = c.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) throw new StructuredFieldError('string has a character outside VCHAR/SP');
        out += c === '"' || c === '\\' ? `\\${c}` : c;
      }
      return `${out}"`;
    }
    case 'token': {
      const v = item.value;
      if (v.length === 0 || !(ALPHA(v[0]) || v[0] === '*') || [...v.slice(1)].some((c) => !(TCHAR(c) || c === ':' || c === '/'))) {
        throw new StructuredFieldError('invalid token');
      }
      return v;
    }
    case 'bytes':
      return `:${item.value.toString('base64')}:`;
    case 'boolean':
      return item.value ? '?1' : '?0';
  }
}

export function serializeParameters(params: Parameters): string {
  let out = '';
  for (const [key, value] of params) {
    out += `;${key}`;
    if (!(value.type === 'boolean' && value.value === true)) out += `=${serializeBareItem(value)}`;
  }
  return out;
}

export function serializeItem(item: Item): string {
  return serializeBareItem(item.value) + serializeParameters(item.params);
}

export function serializeInnerList(list: InnerList): string {
  return `(${list.items.map(serializeItem).join(' ')})${serializeParameters(list.params)}`;
}

/** Convenience constructors for the signer side. */
export const sf = {
  str: (value: string): BareItem => ({ type: 'string', value }),
  int: (value: number): BareItem => ({ type: 'integer', value }),
  bool: (value: boolean): BareItem => ({ type: 'boolean', value }),
  token: (value: string): BareItem => ({ type: 'token', value }),
};
