/**
 * The CMS `SignedData` walk, plus the signed-attribute readers each
 * SignerInfo feeds. It gets its own target rather than only being reached
 * through `verify-receipt` because this is the walk that reads child lists
 * positionally on attacker-supplied shapes, for every SignerInfo a receipt
 * carries (0.7 allows up to four).
 *
 * Invariant: `parseCms` and `requireAttributeSetSyntax` fail only as a
 * `ParseError`; `signedAttributeValues` and `signedAttrsSignedBytes` never
 * throw for a signedAttrs that already passed `requireAttributeSetSyntax`.
 * Nothing else may escape.
 */
import {
  parseCms,
  requireAttributeSetSyntax,
  signedAttributeValues,
  signedAttrsSignedBytes,
} from '../../dist/cms.js';
import { ParseError } from '../../dist/der.js';
import { PARSE_ERRORS, requireTypedError } from '../harness.mjs';

export function fuzz(data) {
  let cms;
  try {
    cms = parseCms(data);
  } catch (error) {
    requireTypedError(error, 'parseCms', PARSE_ERRORS);
    return;
  }
  for (const info of cms.signerInfos) {
    if (info.signedAttrs === null) {
      continue;
    }
    try {
      requireAttributeSetSyntax(info.signedAttrs);
    } catch (error) {
      requireTypedError(error, 'requireAttributeSetSyntax', PARSE_ERRORS);
      continue;
    }
    try {
      signedAttributeValues(info.signedAttrs);
      signedAttrsSignedBytes(info.signedAttrs.raw);
    } catch (error) {
      if (error instanceof ParseError) {
        throw new Error(
          'a signedAttrs that passed requireAttributeSetSyntax must not fail the readers',
          { cause: error },
        );
      }
      throw error;
    }
  }
}
