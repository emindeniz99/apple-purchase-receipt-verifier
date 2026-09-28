/**
 * A strict, bounded JSON reader, hand-written rather than built on
 * `JSON.parse`: the design's Bounds table needs a nesting-depth cap, a
 * member-name-length cap and a number-digit-length cap that `JSON.parse` does
 * not enforce, duplicate object members must keep the *last* one, and callers
 * need to tell "not JSON" apart from "valid JSON, wrong shape" apart from
 * "trailing content after an otherwise well-formed value". Shared by both
 * builds; it touches no cryptography and no Node API.
 */

export class JsonError extends Error {}

export const MAX_NESTING_DEPTH = 64;
export const MAX_NAME_LENGTH = 50_000;
export const MAX_NUMBER_LENGTH = 1000;

export type JsonValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'bool'; readonly value: boolean }
  | { readonly kind: 'number'; readonly text: string }
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'array'; readonly items: readonly JsonValue[] }
  | { readonly kind: 'object'; readonly members: ReadonlyMap<string, JsonValue> };

interface Cursor {
  readonly text: string;
  pos: number;
}

function fail(message: string): never {
  throw new JsonError(message);
}

function isWs(c: string): boolean {
  return c === ' ' || c === '\t' || c === '\n' || c === '\r';
}

function skipWs(c: Cursor): void {
  while (c.pos < c.text.length && isWs(c.text[c.pos]!)) {
    c.pos++;
  }
}

function expectLiteral(c: Cursor, literal: string, value: JsonValue): JsonValue {
  if (c.text.startsWith(literal, c.pos)) {
    c.pos += literal.length;
    return value;
  }
  fail(`expected "${literal}"`);
}

function parseString(c: Cursor, maxLength: number): string {
  // c.pos is at the opening quote.
  c.pos++;
  const start = c.pos;
  let out = '';
  let sinceLastEscape = start;
  let length = 0;
  for (;;) {
    if (c.pos >= c.text.length) {
      fail('unterminated string');
    }
    const ch = c.text[c.pos]!;
    const code = c.text.charCodeAt(c.pos);
    if (ch === '"') {
      out += c.text.slice(sinceLastEscape, c.pos);
      c.pos++;
      if (length > maxLength) {
        fail(`string exceeds the maximum length of ${maxLength} characters`);
      }
      return out;
    }
    if (code < 0x20) {
      fail('control character in string');
    }
    if (ch === '\\') {
      out += c.text.slice(sinceLastEscape, c.pos);
      c.pos++;
      const esc = c.text[c.pos];
      if (esc === undefined) {
        fail('unterminated escape');
      }
      switch (esc) {
        case '"':
          out += '"';
          break;
        case '\\':
          out += '\\';
          break;
        case '/':
          out += '/';
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'u': {
          const hex = c.text.slice(c.pos + 1, c.pos + 5);
          if (hex.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(hex)) {
            fail('invalid \\u escape');
          }
          out += String.fromCharCode(Number.parseInt(hex, 16));
          c.pos += 4;
          break;
        }
        default:
          fail(`invalid escape \\${esc}`);
      }
      c.pos++;
      sinceLastEscape = c.pos;
      length += 1;
      continue;
    }
    c.pos++;
    length += 1;
  }
}

function parseNumber(c: Cursor, maxLength: number): string {
  const start = c.pos;
  if (c.text[c.pos] === '-') {
    c.pos++;
  }
  if (c.text[c.pos] === '0') {
    c.pos++;
  } else if (c.text[c.pos] !== undefined && c.text[c.pos]! >= '1' && c.text[c.pos]! <= '9') {
    while (c.text[c.pos] !== undefined && c.text[c.pos]! >= '0' && c.text[c.pos]! <= '9') {
      c.pos++;
    }
  } else {
    fail('invalid number');
  }
  if (c.text[c.pos] === '.') {
    c.pos++;
    const fracStart = c.pos;
    while (c.text[c.pos] !== undefined && c.text[c.pos]! >= '0' && c.text[c.pos]! <= '9') {
      c.pos++;
    }
    if (c.pos === fracStart) {
      fail('invalid number');
    }
  }
  if (c.text[c.pos] === 'e' || c.text[c.pos] === 'E') {
    c.pos++;
    if (c.text[c.pos] === '+' || c.text[c.pos] === '-') {
      c.pos++;
    }
    const expStart = c.pos;
    while (c.text[c.pos] !== undefined && c.text[c.pos]! >= '0' && c.text[c.pos]! <= '9') {
      c.pos++;
    }
    if (c.pos === expStart) {
      fail('invalid number');
    }
  }
  const text = c.text.slice(start, c.pos);
  if (text.length > maxLength) {
    fail(`number exceeds the maximum length of ${maxLength} digits`);
  }
  return text;
}

function parseValue(c: Cursor, depth: number): JsonValue {
  skipWs(c);
  const ch = c.text[c.pos];
  if (ch === undefined) {
    fail('unexpected end of input');
  }
  if (ch === '{') {
    return parseObject(c, depth);
  }
  if (ch === '[') {
    return parseArray(c, depth);
  }
  if (ch === '"') {
    return { kind: 'string', value: parseString(c, Number.POSITIVE_INFINITY) };
  }
  if (ch === 't') {
    return expectLiteral(c, 'true', { kind: 'bool', value: true });
  }
  if (ch === 'f') {
    return expectLiteral(c, 'false', { kind: 'bool', value: false });
  }
  if (ch === 'n') {
    return expectLiteral(c, 'null', { kind: 'null' });
  }
  if (ch === '-' || (ch >= '0' && ch <= '9')) {
    return { kind: 'number', text: parseNumber(c, MAX_NUMBER_LENGTH) };
  }
  fail(`unexpected character ${JSON.stringify(ch)}`);
}

function parseObject(c: Cursor, depth: number): JsonValue {
  if (depth > MAX_NESTING_DEPTH) {
    fail(`nests deeper than ${MAX_NESTING_DEPTH} values`);
  }
  c.pos++; // {
  const members = new Map<string, JsonValue>();
  skipWs(c);
  if (c.text[c.pos] === '}') {
    c.pos++;
    return { kind: 'object', members };
  }
  for (;;) {
    skipWs(c);
    if (c.text[c.pos] !== '"') {
      fail('expected a string member name');
    }
    const name = parseString(c, MAX_NAME_LENGTH);
    skipWs(c);
    if (c.text[c.pos] !== ':') {
      fail('expected ":"');
    }
    c.pos++;
    const value = parseValue(c, depth + 1);
    // Duplicate member: the last occurrence wins.
    members.set(name, value);
    skipWs(c);
    const next = c.text[c.pos];
    if (next === ',') {
      c.pos++;
      continue;
    }
    if (next === '}') {
      c.pos++;
      return { kind: 'object', members };
    }
    fail('expected "," or "}"');
  }
}

function parseArray(c: Cursor, depth: number): JsonValue {
  if (depth > MAX_NESTING_DEPTH) {
    fail(`nests deeper than ${MAX_NESTING_DEPTH} values`);
  }
  c.pos++; // [
  const items: JsonValue[] = [];
  skipWs(c);
  if (c.text[c.pos] === ']') {
    c.pos++;
    return { kind: 'array', items };
  }
  for (;;) {
    items.push(parseValue(c, depth + 1));
    skipWs(c);
    const next = c.text[c.pos];
    if (next === ',') {
      c.pos++;
      continue;
    }
    if (next === ']') {
      c.pos++;
      return { kind: 'array', items };
    }
    fail('expected "," or "]"');
  }
}

/**
 * Parses one JSON value from the start of `text` and returns it with the
 * cursor position just past it (before any trailing whitespace or content).
 * Depth starts at 1 for the outermost value.
 */
export function parseOneValue(text: string): { value: JsonValue; end: number } {
  const c: Cursor = { text, pos: 0 };
  const value = parseValue(c, 1);
  return { value, end: c.pos };
}

/** Whether only whitespace remains in `text` from `from` to the end. */
export function onlyWhitespaceAfter(text: string, from: number): boolean {
  for (let i = from; i < text.length; i++) {
    if (!isWs(text[i]!)) {
      return false;
    }
  }
  return true;
}

/**
 * Parses `text` as a JSON object with nothing but whitespace before or
 * after it (no BOM: a leading U+FEFF is not whitespace and so is refused
 * here). Throws {@link JsonError} for anything else.
 */
export function parseWholeObject(text: string): ReadonlyMap<string, JsonValue> {
  const { value, end } = parseOneValue(text);
  if (value.kind !== 'object') {
    fail('not a JSON object');
  }
  if (!onlyWhitespaceAfter(text, end)) {
    fail('content after the object');
  }
  return value.members;
}

// --- convenience accessors ----------------------------------------------

export function asString(value: JsonValue | undefined): string | null {
  return value !== undefined && value.kind === 'string' ? value.value : null;
}

export function asStringArray(value: JsonValue | undefined): string[] | null {
  if (value === undefined || value.kind !== 'array') {
    return null;
  }
  const out: string[] = [];
  for (const item of value.items) {
    if (item.kind !== 'string') {
      return null;
    }
    out.push(item.value);
  }
  return out;
}

/**
 * A number member as epoch milliseconds, the conversion `docs/design/0.7-api.md`
 * pins: an integer literal must fit a signed 64-bit value (as a `bigint`,
 * exact); a literal with a fraction or exponent is read as a double and
 * truncated toward zero when it lies within the 64-bit range. A literal no
 * 64-bit value or double can represent (`1e300`) is not an instant: `null`.
 */
export function asInstantMs(value: JsonValue | undefined): bigint | null {
  if (value === undefined || value.kind !== 'number') {
    return null;
  }
  const text = value.text;
  if (!/[.eE]/.test(text)) {
    try {
      const n = BigInt(text);
      const MIN = -9223372036854775808n;
      const MAX = 9223372036854775807n;
      return n >= MIN && n <= MAX ? n : null;
    } catch {
      return null;
    }
  }
  const d = Number(text);
  if (!Number.isFinite(d)) {
    return null;
  }
  const MAX_I64 = 9223372036854775807n;
  const MIN_AS_DOUBLE = -9223372036854775808; // exactly representable
  const MAX_AS_DOUBLE = 9223372036854775808; // 2^63, the double nearest MAX_I64
  if (d < MIN_AS_DOUBLE || d > MAX_AS_DOUBLE) {
    return null;
  }
  // A double exactly at 2^63 is not a representable i64, but a narrowing
  // int64 conversion of it saturates to the maximum rather than overflowing
  // — the same behaviour a Java `(long)` cast of Long.MAX_VALUE-as-double
  // has, mirrored here for cross-port parity.
  if (d === MAX_AS_DOUBLE) {
    return MAX_I64;
  }
  return BigInt(Math.trunc(d));
}
