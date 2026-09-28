/**
 * Renders attacker-controlled input for a {@link Failure} message. Every
 * message that quotes something out of the input goes through here first:
 * truncation keeps a huge claim from making the message huge, and replacing
 * control and bidi-override characters keeps a newline or a reordering
 * override in the input from forging the next log line.
 */

/** Longer input is cut here: long enough to identify a claim, short enough to be free. */
const MAX_LENGTH = 64;

/** The cut for {@link detail}: a longer message (a third-party error) still fits. */
const MAX_DETAIL_LENGTH = 256;

/** Stands in for a character that must not reach a log line as itself. */
const PLACEHOLDER = '�';

/**
 * C0 and C1 controls, DEL, and the Unicode line/paragraph separators —
 * everything a log viewer may treat as a break — plus the bidirectional
 * formatting characters (U+061C, U+200E, U+200F, U+202A-U+202E,
 * U+2066-U+2069), which can make a log line display in an order other than
 * the one it was written in.
 */
function unsafeInALogLine(code: number): boolean {
  return (
    code < 0x20 ||
    (code >= 0x7f && code <= 0x9f) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x061c ||
    code === 0x200e ||
    code === 0x200f ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

function render(value: string | null | undefined, maxLength: number): string {
  if (value === null || value === undefined) {
    return 'null';
  }
  let cut = Math.min(value.length, maxLength);
  // Never between the two halves of a surrogate pair, which would leave a
  // lone surrogate at the end of the message.
  if (
    cut < value.length &&
    cut > 0 &&
    value.charCodeAt(cut - 1) >= 0xd800 &&
    value.charCodeAt(cut - 1) <= 0xdbff &&
    value.charCodeAt(cut) >= 0xdc00 &&
    value.charCodeAt(cut) <= 0xdfff
  ) {
    cut -= 1;
  }
  let out = '';
  for (let i = 0; i < cut; i++) {
    const code = value.charCodeAt(i);
    out += unsafeInALogLine(code) ? PLACEHOLDER : value[i];
  }
  if (value.length > maxLength) {
    out += `... (${value.length} characters)`;
  }
  return out;
}

/** A claim quoted from the input, at most 64 characters and carrying no control character. */
export function quote(value: string | null | undefined): string {
  return render(value, MAX_LENGTH);
}

/**
 * A third-party error message, rendered as {@link quote} renders a claim,
 * with a longer cut. Such a message can itself quote the input (a
 * distinguished name out of a certificate, say), so it is attacker
 * controlled too.
 */
export function detail(message: string | null | undefined): string {
  return render(message, MAX_DETAIL_LENGTH);
}
