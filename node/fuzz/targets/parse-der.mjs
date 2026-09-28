/**
 * The bounded DER/BER reader, on its own. Every other target reaches it
 * through a structure walk; this one hands it arbitrary bytes directly so a
 * length or depth bug shows up without a CMS or certificate shape around it.
 *
 * The X.509 helpers `der.ts`/`x509.ts` hand-write are exercised on the same
 * bytes. They slice the input a second time from offsets parsing chose,
 * which is exactly the state a mutated length can leave wrong. Since 0.7
 * both builds parse certificate structure with this repository's own
 * `x509.ts` (no `node:crypto` `X509Certificate`), `parseCertificate` is
 * fuzzed here too — the one target the Node port now shares with Rust and
 * the web build rather than delegating to OpenSSL.
 *
 * Invariant: one well-formed value or a `ParseError`, never a `TypeError`
 * or a `RangeError` from indexing past the end of the input.
 */
import {
  Tag,
  hasExtension,
  isOctetString,
  octetStringValue,
  parse,
  tbsParts,
} from '../../dist/der.js';
import { parseCertificate } from '../../dist/x509.js';
import { PARSE_ERRORS, requireTypedError } from '../harness.mjs';

// The Apple receipt-signing marker OID, i.e. the extension lookup the
// receipt path actually performs.
const RECEIPT_SIGNER_OID = '1.2.840.113635.100.6.11.1';

export function fuzz(data) {
  let node;
  try {
    node = parse(data);
  } catch (error) {
    requireTypedError(error, 'parse', PARSE_ERRORS);
    return;
  }
  try {
    if (isOctetString(node)) {
      octetStringValue(node);
    }
    if (node.tag === Tag.SEQUENCE) {
      tbsParts(data);
      hasExtension(data, RECEIPT_SIGNER_OID);
      parseCertificate(data);
    }
  } catch (error) {
    requireTypedError(error, 'der accessors', PARSE_ERRORS);
  }
}
