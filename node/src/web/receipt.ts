import { Reason, VerificationError } from '../errors.js';
import { concatBytes, receiptBase64DecodeStrict, timingSafeBytesEqual } from '../bytes.js';
import {
  findMessageDigestAttribute,
  findSignerCertIndex,
  parseCms,
  signedAttrsSignedBytes,
  type ParsedCms,
} from '../cms.js';
import { parseReceiptPayload } from '../receipt-payload.js';
import { requireDecodableExtensions } from '../der.js';
import { parseCertificate, type ParsedCertificate } from '../x509.js';
import { buildAndValidatePath, normalizeRoots, type RootInput } from './chain.js';
import { digest, verifyRsaPkcs1 } from './crypto.js';
import { OID_RSA_ENCRYPTION, requireBuildablePublicKey } from './jwk.js';

export type {
  RawAppReceipt as AppReceipt,
  RawInAppPurchase as InAppPurchase,
} from '../receipt-payload.js';

import type { RawAppReceipt } from '../receipt-payload.js';

// Apple marker OID on the receipt-signing leaf. Without this purpose check,
// any developer cert chaining to the same pinned root could sign a forged
// receipt (the chain check alone does not distinguish signer purpose).
const RECEIPT_SIGNER_OID = '1.2.840.113635.100.6.11.1';

// Same bound as the Node build: genuine receipts embed 1 to 3 certificates,
// and every embedded one is parsed and then signature-checked as a candidate
// issuer before anything about the receipt has been verified.
const MAX_EMBEDDED_CERTIFICATES = 10;

export interface ReceiptVerifierOptions {
  /** Pinned roots (production: `appleReceiptRoots()`). */
  trustedRoots: RootInput[];
  /** Bundle id the receipt must carry. */
  bundleId: string;
}

/**
 * Decodes a client-supplied `receipt-data` string to DER per the
 * receipt-data contract, throwing {@link Reason.INVALID_RECEIPT_FORMAT}
 * (rather than silently skipping bad characters) when it does not conform.
 * Matches the Node build's function of the same name in `../receipt.js`.
 */
function decodeReceiptDataString(text: string): Uint8Array {
  const decoded = receiptBase64DecodeStrict(text);
  if (decoded === null) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'receipt-data is not valid base64');
  }
  return decoded;
}

/**
 * Chain + signature verification WITHOUT the bundle-id claim check — the
 * primitive under {@link ReceiptVerifier}, matching the Node build's
 * `verifyReceiptCore`. Callers that unlock products must check `bundleId`
 * themselves or use ReceiptVerifier.
 */
export async function verifyReceiptCore(
  der: Uint8Array,
  trustedRoots: RootInput[],
): Promise<RawAppReceipt> {
  const roots = normalizeRoots(trustedRoots);
  if (!(der instanceof Uint8Array) || der.length === 0) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'receipt is empty');
  }
  const cms = parseCms(der);

  // Parsed before signature verification only to learn the creation date
  // (chain validity anchors at signing time); nothing from it is trusted
  // until the chain + signature checks pass.
  const fields = parseReceiptPayload(cms.content);
  // A receipt with no creation date falls back to the SYSTEM clock, never to
  // an injected one: a caller injecting a clock (to test staleness, or to
  // work around skew) must not thereby accept an expired chain. That is why
  // the receipt path takes no clock option at all.
  const at = fields.creationDate === null ? new Date() : fields.creationDate;

  // Everything below walks attacker-supplied DER through the certificate
  // parser and through child lists that may be any shape. Callers
  // discriminate on VerificationError.reason, so no foreign error type may
  // escape from here.
  try {
    // The embedded certificates are attacker-supplied and are walked into a
    // path below, before anything about the receipt has been verified, so a
    // receipt carrying more of them than a chain can hold is rejected here
    // rather than parsed and searched.
    if (cms.certificates.length > MAX_EMBEDDED_CERTIFICATES) {
      throw new VerificationError(
        Reason.INVALID_CHAIN,
        `receipt embeds more than ${MAX_EMBEDDED_CERTIFICATES} certificates`,
      );
    }
    const signerIndex = findSignerCertIndex(cms);
    if (signerIndex < 0) {
      throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'signer certificate not embedded');
    }
    // Read strictly, and before the rest of the bag: which certificate is
    // unreadable changes the verdict. See the Node build's
    // readSignerCertificate for the whole of the reasoning.
    const signerCert = readSignerCertificate(cms.certificates[signerIndex]!);
    const embedded = cms.certificates.map((raw) => parseCertificate(raw));
    await buildAndValidatePath(signerCert, embedded, roots, at);
    if (!signerCert.hasExtension(RECEIPT_SIGNER_OID)) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE_PURPOSE,
        `receipt signer certificate lacks Apple receipt-signing marker OID ${RECEIPT_SIGNER_OID}`,
      );
    }
    await verifyCmsSignature(cms, signerCert);
  } catch (cause) {
    if (cause instanceof VerificationError) {
      throw cause;
    }
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'malformed CMS structure', cause);
  }
  return fields;
}

/**
 * The WebCrypto twin of the Node build's {@link ReceiptVerifier}: same
 * options, same checks in the same order, same {@link VerificationError}
 * reasons — `verify` returns a Promise because `crypto.subtle` is async.
 */
export class ReceiptVerifier {
  #roots: RootInput[];
  #bundleId: string;

  constructor({ trustedRoots, bundleId }: ReceiptVerifierOptions) {
    normalizeRoots(trustedRoots); // validate eagerly
    if (typeof bundleId !== 'string' || bundleId.length === 0) {
      throw new TypeError('bundleId is required');
    }
    this.#roots = trustedRoots;
    this.#bundleId = bundleId;
  }

  /**
   * Verifies a receipt (DER bytes, or its base64 string — the usual client
   * transport form). A string is decoded per the receipt-data contract
   * (RFC 4648, standard or base64url alphabet, not mixed, padding optional —
   * see {@link receiptBase64DecodeStrict}, matching the Node build); anything
   * that decode rejects throws {@link Reason.INVALID_RECEIPT_FORMAT}. Passing
   * `deviceGuid` additionally enforces the device-hash binding:
   * SHA1(guid ‖ opaqueValue ‖ bundleIdBytes) must equal attribute 5
   * (optional — PLAN.md D4).
   */
  async verify(
    receipt: Uint8Array | string,
    deviceGuid: Uint8Array | null = null,
  ): Promise<RawAppReceipt> {
    const der = typeof receipt === 'string' ? decodeReceiptDataString(receipt) : receipt;
    const fields = await verifyReceiptCore(der, this.#roots);
    if (fields.bundleId !== this.#bundleId) {
      throw new VerificationError(
        Reason.WRONG_BUNDLE_ID,
        `expected ${this.#bundleId} but receipt has ${fields.bundleId}`,
      );
    }
    if (deviceGuid !== null) {
      await verifyDeviceHash(fields, deviceGuid);
    }
    return fields;
  }
}

/** The signer certificate, or INVALID_CERTIFICATE — see the Node build. */
function readSignerCertificate(raw: Uint8Array): ParsedCertificate {
  try {
    const certificate = parseCertificate(raw);
    // parseCertificate settles the version and a repeated extension; these
    // two are what it leaves. Decoding every extension VALUE is what makes
    // reading a certificate different from scanning it for a marker OID,
    // and building the key is the only way to learn that it sits on a curve
    // this build cannot import — the web build's equivalents of the Node
    // build's requireDecodableExtensions and `.publicKey`. Like `.publicKey`,
    // the key check refuses an RSA or EC key that will not build and says
    // nothing about a key of another algorithm: a readable DSA signer is a
    // verdict about the SIGNATURE, and verifyCmsSignature below makes it.
    requireDecodableExtensions(raw);
    requireBuildablePublicKey(certificate.publicKeyAlgorithmOid, certificate.spki);
    return certificate;
  } catch (cause) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'receipt signer certificate is not a valid certificate',
      cause,
    );
  }
}

async function verifyCmsSignature(cms: ParsedCms, signerCert: ParsedCertificate): Promise<void> {
  const { digest: digestName, signedAttrs, signature } = cms.signerInfo;
  if (signerCert.publicKeyAlgorithmOid !== OID_RSA_ENCRYPTION) {
    throw new VerificationError(Reason.INVALID_SIGNATURE, 'receipt signer key is not RSA');
  }
  let valid: boolean;
  if (signedAttrs !== null) {
    const contentDigest = await digest(digestName, cms.content);
    const messageDigest = findMessageDigestAttribute(signedAttrs);
    if (messageDigest === null || !timingSafeBytesEqual(messageDigest, contentDigest)) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'messageDigest attribute does not match content',
      );
    }
    valid = await verifyRsaPkcs1(
      signerCert.spki,
      digestName,
      signature,
      signedAttrsSignedBytes(signedAttrs),
    );
  } else {
    valid = await verifyRsaPkcs1(signerCert.spki, digestName, signature, cms.content);
  }
  if (!valid) {
    throw new VerificationError(Reason.INVALID_SIGNATURE, 'CMS signature check failed');
  }
}

async function verifyDeviceHash(fields: RawAppReceipt, deviceGuid: Uint8Array): Promise<void> {
  if (fields.opaqueValue === null || fields.sha1Hash === null || fields.bundleIdBytes === null) {
    throw new VerificationError(
      Reason.DEVICE_HASH_MISMATCH,
      'receipt lacks the attributes needed for the device-hash check',
    );
  }
  const computed = await digest(
    'sha1',
    concatBytes([deviceGuid, fields.opaqueValue, fields.bundleIdBytes]),
  );
  if (!timingSafeBytesEqual(computed, fields.sha1Hash)) {
    throw new VerificationError(
      Reason.DEVICE_HASH_MISMATCH,
      'computed device hash does not match attribute 5',
    );
  }
}
