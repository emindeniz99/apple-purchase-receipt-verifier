/**
 * Extracts a certificate's base64 body from a PEM block, shared by both
 * builds' trust-root normalisation.
 *
 * Scanned with `indexOf` rather than matched with a regular expression: the
 * obvious spelling — a lazy unbounded quantifier between two literals — is
 * quadratic on an input with many `BEGIN` lines and no matching `END`
 * (measured on V8, 2026-09-22: 112 KB took 130 ms, 448 KB took 1.7 s). Two
 * `indexOf` calls find exactly the same leftmost block in one pass.
 */

const PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const PEM_END = '-----END CERTIFICATE-----';

/**
 * The base64 between the first BEGIN line and the first END line after it,
 * or null when the input is not a certificate block. Whitespace is left in
 * place; the base64 decoder skips everything outside its alphabet, which is
 * what makes 64-column line breaks, CRLF and surrounding blank lines all
 * decode.
 */
export function pemBody(text: string): string | null {
  const begin = text.indexOf(PEM_BEGIN);
  if (begin < 0) {
    return null;
  }
  const bodyStart = begin + PEM_BEGIN.length;
  const end = text.indexOf(PEM_END, bodyStart);
  return end < 0 ? null : text.slice(bodyStart, end);
}
