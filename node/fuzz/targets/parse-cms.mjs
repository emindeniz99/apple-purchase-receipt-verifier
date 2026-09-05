/**
 * The CMS `SignedData` walk, plus the signer lookup and the two
 * signed-attribute readers a parsed structure feeds. It gets its own target
 * rather than only being reached through `verify-receipt` because this is
 * the walk that reads child lists positionally — `signedData[2]`,
 * `fields[index]` — on attacker-supplied shapes.
 *
 * Invariant: `parseCms` fails only as a `VerificationError`; the attribute
 * readers, which the receipt path calls inside its own wrapping try, may
 * also fail as a `ParseError`. Nothing else may escape.
 */
import {
  findMessageDigestAttribute,
  findSignerCertIndex,
  parseCms,
  signedAttrsSignedBytes,
} from '../../dist/cms.js';
import { CMS_ERRORS, requireTypedError } from '../harness.mjs';

export function fuzz(data) {
  let cms;
  try {
    cms = parseCms(data);
  } catch (error) {
    requireTypedError(error, 'parseCms');
    return;
  }
  try {
    findSignerCertIndex(cms);
    if (cms.signerInfo.signedAttrs !== null) {
      findMessageDigestAttribute(cms.signerInfo.signedAttrs);
      signedAttrsSignedBytes(cms.signerInfo.signedAttrs);
    }
  } catch (error) {
    requireTypedError(error, 'signed-attribute readers', CMS_ERRORS);
  }
}
