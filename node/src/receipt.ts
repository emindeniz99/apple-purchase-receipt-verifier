import { X509Certificate, createHash, timingSafeEqual, verify as cryptoVerify } from 'node:crypto';
import { Reason, VerificationError } from './errors.js';
import {
  findMessageDigestAttribute,
  findSignerCertIndex,
  parseCms,
  signedAttrsSignedBytes,
  type ParsedCms,
} from './cms.js';
import {
  hasExtension,
  requireDecodableExtensions,
  requireKnownVersion,
  requireNoDuplicateExtensions,
} from './der.js';
import { receiptBase64DecodeStrict } from './bytes.js';
import {
  parseReceiptPayload,
  type RawAppReceipt,
  type RawInAppPurchase,
} from './receipt-payload.js';
import { buildAndValidatePath, normalizeRoots, type RootInput } from './chain.js';

// Apple marker OID on the receipt-signing leaf. Without this purpose check,
// any developer cert chaining to the same pinned root could sign a forged
// receipt (the chain check alone does not distinguish signer purpose).
const RECEIPT_SIGNER_OID = '1.2.840.113635.100.6.11.1';

// Genuine receipts embed a leaf, an intermediate and (for the legacy SHA-1
// chain) a root: the public fixtures carry 1, 3 and 3. Ten leaves room for a
// longer Apple chain while bounding what rejecting a receipt costs, because
// every embedded certificate is converted and then RSA-checked as a candidate
// issuer before any signature is checked: a 722 KB receipt carrying 1057 of
// them measured 122-172 ms to reject, 26 to 45 times the cost of verifying
// the genuine 79 KB legacy receipt.
const MAX_EMBEDDED_CERTIFICATES = 10;

/** One in-app purchase from a legacy app receipt (attribute 17). */
export interface InAppPurchase {
  /** Raw unmodeled attributes by type — forward compatibility (PLAN D10). */
  unknownAttributes: Map<number, Buffer[]>;
  quantity: number | null;
  productId: string | null;
  transactionId: string | null;
  originalTransactionId: string | null;
  purchaseDate: Date | null;
  originalPurchaseDate: Date | null;
  expiresDate: Date | null;
  cancellationDate: Date | null;
  webOrderLineItemId: number | null;
  isInIntroOfferPeriod: number | null;
}

/**
 * A verified legacy app receipt. Only receipts returned by
 * {@link ReceiptVerifier} (or {@link verifyReceiptCore}) should be trusted.
 */
export interface AppReceipt {
  /**
   * Raw values of attribute types this library does not model, keyed by
   * type — forward compatibility for fields Apple may add (PLAN D10).
   * Values are the raw octet-string contents, verified but undecoded.
   */
  unknownAttributes: Map<number, Buffer[]>;
  /** Attribute 0, e.g. "Production" / "ProductionSandbox" (undocumented). */
  receiptType: string | null;
  bundleId: string | null;
  /** Raw DER bytes of attribute 2 — input to the device-hash check. */
  bundleIdBytes: Buffer | null;
  appVersion: string | null;
  opaqueValue: Buffer | null;
  sha1Hash: Buffer | null;
  creationDate: Date | null;
  /** Attribute 18 (undocumented; community-established). */
  originalPurchaseDate: Date | null;
  originalAppVersion: string | null;
  expirationDate: Date | null;
  inAppPurchases: InAppPurchase[];
}

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
 * Shared by {@link ReceiptVerifier.verify} and {@link VerifyReceiptEndpoint}.
 */
export function decodeReceiptDataString(text: string): Buffer {
  const decoded = receiptBase64DecodeStrict(text);
  if (decoded === null) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'receipt-data is not valid base64');
  }
  return asBuffer(decoded);
}

/** Zero-copy Buffer view over shared-parser output, which is Uint8Array. */
function asBuffer(bytes: Uint8Array): Buffer {
  return Buffer.isBuffer(bytes)
    ? bytes
    : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function bufferValues(unknown: Map<number, Uint8Array[]>): Map<number, Buffer[]> {
  return new Map([...unknown].map(([type, values]) => [type, values.map(asBuffer)]));
}

function toAppReceipt(raw: RawAppReceipt): AppReceipt {
  return {
    ...raw,
    unknownAttributes: bufferValues(raw.unknownAttributes),
    bundleIdBytes: raw.bundleIdBytes === null ? null : asBuffer(raw.bundleIdBytes),
    opaqueValue: raw.opaqueValue === null ? null : asBuffer(raw.opaqueValue),
    sha1Hash: raw.sha1Hash === null ? null : asBuffer(raw.sha1Hash),
    inAppPurchases: raw.inAppPurchases.map((purchase: RawInAppPurchase): InAppPurchase => ({
      ...purchase,
      unknownAttributes: bufferValues(purchase.unknownAttributes),
    })),
  };
}

/**
 * Chain + signature verification WITHOUT the bundle-id claim check — the
 * primitive under both {@link ReceiptVerifier} and the verifyReceipt-compat
 * endpoint (which, like Apple's endpoint, accepts any bundle). Callers that
 * unlock products must check `bundleId` themselves or use ReceiptVerifier.
 */
export function verifyReceiptCore(der: Buffer, trustedRoots: RootInput[]): AppReceipt {
  const roots = normalizeRoots(trustedRoots);
  if (!Buffer.isBuffer(der) || der.length === 0) {
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

  // Everything below walks attacker-supplied DER through OpenSSL and through
  // child lists that may be any shape. Callers discriminate on
  // VerificationError.reason, and an OpenSSL Error carries a `.reason` of its
  // own, so no foreign error type may escape from here.
  try {
    // The embedded certificates are attacker-supplied and are walked into a
    // path below, before anything about the receipt has been verified, so a
    // receipt carrying more of them than a chain can hold is rejected here
    // rather than converted and searched.
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
    // The signer is read strictly, and before the rest of the bag, because
    // WHICH certificate is unreadable changes the verdict. A stranger the
    // receipt merely carries is a defect of the receipt (the bag is
    // unsigned, so bytes that cannot be read are fatal but are the
    // receipt's problem). The signer being unreadable is a defect of a
    // certificate, and gets the verdict an unreadable x5c entry gets on the
    // JWS path — receipt/reject-signer-* pins the four spellings of it.
    const signerCert = readSignerCertificate(cms.certificates[signerIndex]!);
    const embedded = cms.certificates.map((raw) => new X509Certificate(raw));
    buildAndValidatePath(signerCert, embedded, roots, at);
    let signerHasOid = false;
    try {
      signerHasOid = hasExtension(signerCert.raw, RECEIPT_SIGNER_OID);
    } catch {
      signerHasOid = false;
    }
    if (!signerHasOid) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE_PURPOSE,
        `receipt signer certificate lacks Apple receipt-signing marker OID ${RECEIPT_SIGNER_OID}`,
      );
    }
    verifyCmsSignature(cms, signerCert);
  } catch (cause) {
    if (cause instanceof VerificationError) {
      throw cause;
    }
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'malformed CMS structure', cause);
  }
  return toAppReceipt(fields);
}

/**
 * Verifies legacy PKCS#7 app receipts completely offline against the pinned
 * Apple Inc. Root CA — the server-side port of Apple's "Validating receipts
 * on the device" procedure (PLAN.md §2.2), mirroring the Java implementation.
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
   * Verifies a receipt (DER Buffer, or its base64 string — the usual client
   * transport form). A string is decoded per the receipt-data contract
   * (RFC 4648, standard or base64url alphabet, not mixed, padding optional —
   * see {@link receiptBase64DecodeStrict}); anything that decode rejects
   * throws {@link Reason.INVALID_RECEIPT_FORMAT}. Passing `deviceGuid`
   * additionally enforces the device-hash binding: SHA1(guid ‖ opaqueValue ‖
   * bundleIdBytes) must equal attribute 5 (optional — PLAN.md D4).
   */
  verify(receipt: Buffer | string, deviceGuid: Buffer | null = null): AppReceipt {
    const der = typeof receipt === 'string' ? decodeReceiptDataString(receipt) : receipt;
    const fields = verifyReceiptCore(der, this.#roots);
    if (fields.bundleId !== this.#bundleId) {
      throw new VerificationError(
        Reason.WRONG_BUNDLE_ID,
        `expected ${this.#bundleId} but receipt has ${fields.bundleId}`,
      );
    }
    if (deviceGuid !== null) {
      verifyDeviceHash(fields, deviceGuid);
    }
    return fields;
  }
}

/**
 * The signer certificate, or INVALID_CERTIFICATE. Everything OpenSSL lets
 * past that the checks below assume is settled here, exactly as the JWS path
 * settles it for an x5c entry: an unknown X.509 version, a repeated
 * extension, an extension value that stops decoding, and a public key this
 * runtime cannot build — the last of which must be answered here rather than
 * left to `verifyCmsSignature`, whose "not RSA" verdict is about a readable
 * key of the wrong kind.
 */
function readSignerCertificate(raw: Uint8Array): X509Certificate {
  try {
    const certificate = new X509Certificate(raw);
    requireKnownVersion(certificate.raw);
    requireNoDuplicateExtensions(certificate.raw);
    requireDecodableExtensions(certificate.raw);
    void certificate.publicKey;
    return certificate;
  } catch (cause) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'receipt signer certificate is not a valid certificate',
      cause,
    );
  }
}

function verifyCmsSignature(cms: ParsedCms, signerCert: X509Certificate): void {
  const { digest, signedAttrs, signature } = cms.signerInfo;
  if (signerCert.publicKey.asymmetricKeyType !== 'rsa') {
    throw new VerificationError(Reason.INVALID_SIGNATURE, 'receipt signer key is not RSA');
  }
  let valid: boolean;
  if (signedAttrs !== null) {
    const contentDigest = createHash(digest).update(cms.content).digest();
    const messageDigest = findMessageDigestAttribute(signedAttrs);
    if (messageDigest === null || !timingSafeEqualPadded(asBuffer(messageDigest), contentDigest)) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'messageDigest attribute does not match content',
      );
    }
    valid = cryptoVerify(
      digest,
      signedAttrsSignedBytes(signedAttrs),
      signerCert.publicKey,
      signature,
    );
  } else {
    valid = cryptoVerify(digest, cms.content, signerCert.publicKey, signature);
  }
  if (!valid) {
    throw new VerificationError(Reason.INVALID_SIGNATURE, 'CMS signature check failed');
  }
}

function timingSafeEqualPadded(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function verifyDeviceHash(fields: AppReceipt, deviceGuid: Buffer): void {
  if (fields.opaqueValue === null || fields.sha1Hash === null || fields.bundleIdBytes === null) {
    throw new VerificationError(
      Reason.DEVICE_HASH_MISMATCH,
      'receipt lacks the attributes needed for the device-hash check',
    );
  }
  const computed = createHash('sha1')
    .update(deviceGuid)
    .update(fields.opaqueValue)
    .update(fields.bundleIdBytes)
    .digest();
  if (!timingSafeEqualPadded(computed, fields.sha1Hash)) {
    throw new VerificationError(
      Reason.DEVICE_HASH_MISMATCH,
      'computed device hash does not match attribute 5',
    );
  }
}
