/**
 * Shared harness for the fuzz targets: the fixture bytes they anchor on, and
 * the two assertions every target repeats.
 *
 * The fixtures are read from the repository's shared `fixtures/` directory
 * rather than copied here, so a regenerated fixture reseeds the fuzzer
 * without a second copy to keep in step. Nothing under `fixtures/` is
 * written to.
 */
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { VerificationError, appleJwsRoots, appleReceiptRoots } from '../dist/index.js';
import { ParseError } from '../dist/der.js';

const fixture = (relative) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/${relative}`, import.meta.url)));

/**
 * The receipt anchor set: the pinned Apple roots plus the generated fixture
 * root, so both the shared fixture receipts and the two public Apple
 * receipts get past the chain check and the fuzzer can explore what lies
 * beyond it. Roots are converted once — `normalizeRoots` would otherwise
 * re-parse a DER buffer on every single execution.
 */
export const RECEIPT_ANCHORS = [
  ...appleReceiptRoots(),
  new X509Certificate(fixture('generated/receipt-root.der')),
];

/** The unrelated anchor set the accept-invariant re-runs against. */
export const UNRELATED_ANCHORS = [new X509Certificate(fixture('generated/jws-root.der'))];

/** The fixture JWS root, the anchor the generated `.jws` fixtures chain to. */
export const JWS_ANCHORS = [new X509Certificate(fixture('generated/jws-root.der'))];

/** Apple's production JWS roots — the unrelated set for the JWS target. */
export const APPLE_JWS_ANCHORS = appleJwsRoots();

/**
 * Every failure a caller can see must be the library's own typed error.
 * A `TypeError` or a `RangeError` escaping means a hand-written parser
 * indexed past the end of its input instead of rejecting it, which is the
 * class of bug these targets exist to find — so it is reported, not
 * tolerated.
 */
export function requireTypedError(error, what, allowed = [VerificationError]) {
  if (allowed.some((type) => error instanceof type)) {
    return;
  }
  const name = error?.constructor?.name ?? typeof error;
  throw new Error(`${what} escaped as ${name}: ${error?.message}`, { cause: error });
}

/** `requireTypedError`'s allow-list for the DER reader, whose error is its own. */
export const PARSE_ERRORS = [ParseError];

/** The CMS readers throw either — `parseCms` wraps, the attribute readers do not. */
export const CMS_ERRORS = [VerificationError, ParseError];

const UTF8 = new TextDecoder('utf-8', { fatal: true });

/**
 * The string an API taking `string` would actually receive, or null when the
 * bytes are not UTF-8. Decoding leniently would map every invalid byte onto
 * U+FFFD and hide the input the fuzzer built, so those runs are skipped
 * instead — the same rule the Rust targets use.
 */
export function asUtf8(data) {
  try {
    return UTF8.decode(data);
  } catch {
    return null;
  }
}
