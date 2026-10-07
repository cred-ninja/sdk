/**
 * Strict JSON text parser for token payloads.
 *
 * `JSON.parse` is lenient in two ways that matter for signed delegation
 * tokens whose canonical form is JCS (RFC 8785, used by
 * draft-asor-wimse-agent-delegation-chain and by Cred receipts):
 *
 * - Duplicate member names resolve silently to the last value. A verifier
 *   that compares a hash over the canonical bytes against a value parsed
 *   last-wins can be made to accept a token whose signed `del_depth` differs
 *   from the one it enforces. RFC 8259 Section 4 leaves duplicates
 *   unspecified; I-JSON (RFC 7493) forbids them. We reject them.
 * - Integers beyond the IEEE 754 binary64 exact range (|n| > 2^53 - 1) are
 *   rounded. Two distinct tokens then canonicalize to the same bytes, so an
 *   `exp` of 2^53 collides with its neighbours once hashed. We reject them.
 *
 * Everything else follows RFC 8259: the parser accepts exactly the JSON
 * value grammar, leading/trailing whitespace included, and nothing else
 * (no comments, no trailing commas, no single quotes, no bare NaN or
 * Infinity, no control characters inside strings).
 */

export type StrictJsonErrorCode = 'syntax' | 'duplicate_member' | 'unsafe_integer';

export class StrictJsonError extends Error {
  constructor(
    message: string,
    public readonly code: StrictJsonErrorCode,
    public readonly offset: number,
  ) {
    super(message);
    this.name = 'StrictJsonError';
  }
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const MAX_DEPTH = 256;

class Parser {
  private i = 0;

  constructor(private readonly text: string) {}

  parse(): unknown {
    this.skipWs();
    const value = this.value(0);
    this.skipWs();
    if (this.i !== this.text.length) this.fail('syntax', 'unexpected trailing characters');
    return value;
  }

  private fail(code: StrictJsonErrorCode, message: string): never {
    throw new StrictJsonError(`${message} at offset ${this.i}`, code, this.i);
  }

  private skipWs(): void {
    while (this.i < this.text.length) {
      const c = this.text.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  private value(depth: number): unknown {
    if (depth > MAX_DEPTH) this.fail('syntax', 'nesting too deep');
    if (this.i >= this.text.length) this.fail('syntax', 'unexpected end of input');
    const c = this.text[this.i];
    switch (c) {
      case '{': return this.object(depth);
      case '[': return this.array(depth);
      case '"': return this.string();
      case 't': return this.literal('true', true);
      case 'f': return this.literal('false', false);
      case 'n': return this.literal('null', null);
      default:
        if (c === '-' || (c! >= '0' && c! <= '9')) return this.number();
        return this.fail('syntax', `unexpected character ${JSON.stringify(c)}`);
    }
  }

  private literal<T>(word: string, result: T): T {
    if (this.text.startsWith(word, this.i)) {
      this.i += word.length;
      return result;
    }
    return this.fail('syntax', `invalid literal, expected ${word}`);
  }

  private object(depth: number): Record<string, unknown> {
    this.i++; // {
    const out: Record<string, unknown> = Object.create(null);
    const seen = new Set<string>();
    this.skipWs();
    if (this.text[this.i] === '}') {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWs();
      if (this.text[this.i] !== '"') this.fail('syntax', 'expected string member name');
      const key = this.string();
      if (seen.has(key)) this.fail('duplicate_member', `duplicate member name ${JSON.stringify(key)}`);
      seen.add(key);
      this.skipWs();
      if (this.text[this.i] !== ':') this.fail('syntax', 'expected ":" after member name');
      this.i++;
      this.skipWs();
      out[key] = this.value(depth + 1);
      this.skipWs();
      const c = this.text[this.i];
      if (c === ',') { this.i++; continue; }
      if (c === '}') { this.i++; return out; }
      this.fail('syntax', 'expected "," or "}" in object');
    }
  }

  private array(depth: number): unknown[] {
    this.i++; // [
    const out: unknown[] = [];
    this.skipWs();
    if (this.text[this.i] === ']') {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWs();
      out.push(this.value(depth + 1));
      this.skipWs();
      const c = this.text[this.i];
      if (c === ',') { this.i++; continue; }
      if (c === ']') { this.i++; return out; }
      this.fail('syntax', 'expected "," or "]" in array');
    }
  }

  private string(): string {
    this.i++; // opening quote
    let out = '';
    for (;;) {
      if (this.i >= this.text.length) this.fail('syntax', 'unterminated string');
      const c = this.text[this.i]!;
      const code = c.charCodeAt(0);
      if (c === '"') { this.i++; return out; }
      if (c === '\\') {
        const e = this.text[this.i + 1];
        this.i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const hex = this.text.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail('syntax', 'invalid \\u escape');
            out += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default: this.fail('syntax', 'invalid escape sequence');
        }
        continue;
      }
      if (code < 0x20) this.fail('syntax', 'control character in string');
      out += c;
      this.i++;
    }
  }

  private number(): number {
    const start = this.i;
    const m = /^-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.text.slice(this.i));
    if (!m) this.fail('syntax', 'invalid number');
    const lexeme = m[0];
    this.i += lexeme.length;
    const isInteger = m[1] === undefined && m[2] === undefined;
    if (isInteger) {
      // Compare as a decimal string so the check does not itself round.
      const digits = lexeme.startsWith('-') ? lexeme.slice(1) : lexeme;
      const limit = String(MAX_SAFE);
      const tooBig = digits.length > limit.length || (digits.length === limit.length && digits > limit);
      if (tooBig) {
        this.i = start;
        this.fail('unsafe_integer', `integer ${lexeme} is outside the binary64 exact range`);
      }
    }
    const n = Number(lexeme);
    if (!Number.isFinite(n)) {
      this.i = start;
      this.fail('syntax', `number ${lexeme} is not finite`);
    }
    return n;
  }
}

/**
 * Parse `text` as RFC 8259 JSON, rejecting duplicate member names and
 * integers outside the binary64 exact range. Throws StrictJsonError with
 * `code` set to 'syntax', 'duplicate_member', or 'unsafe_integer'.
 *
 * Objects are returned with a null prototype so wire keys such as
 * "__proto__" or "constructor" cannot shadow anything.
 */
export function parseStrictJson(text: string): unknown {
  return new Parser(text).parse();
}
