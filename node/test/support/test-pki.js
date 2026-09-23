// A receipt PKI minted at test time, for tests whose subject is the payload
// parser. The full payload parse runs only after the chain and the CMS
// signature have passed, so a payload spliced into a genuine receipt stops
// at INVALID_SIGNATURE (or at INVALID_CHAIN when the splice makes the
// creation date unusable) and never reaches the parser. Signing it here, under
// a chain the test then trusts, is what lets such a test keep reaching it.
//
// Imports nothing from this package, so both builds can be driven with it.
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

/** One DER TLV with a definite length. */
export function tlv(tag, ...parts) {
  const contents = Buffer.concat(parts);
  const n = contents.length;
  const length =
    n < 0x80
      ? [n]
      : n < 0x100
        ? [0x81, n]
        : n < 0x10000
          ? [0x82, n >> 8, n & 0xff]
          : [0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), contents]);
}

const BOOLEAN = 0x01;
const INTEGER = 0x02;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const NULL = 0x05;
const OID = 0x06;
const UTF8_STRING = 0x0c;
const UTC_TIME = 0x17;
const SEQUENCE = 0x30;
const SET = 0x31;
const CONTEXT_0 = 0xa0;
const CONTEXT_3 = 0xa3;

const OID_SIGNED_DATA = Buffer.from('2a864886f70d010702', 'hex');
const OID_DATA = Buffer.from('2a864886f70d010701', 'hex');
const OID_SHA256_RSA = Buffer.from('2a864886f70d01010b', 'hex');
const OID_RSA_ENCRYPTION = Buffer.from('2a864886f70d010101', 'hex');
const OID_SHA256 = Buffer.from('608648016503040201', 'hex');
const OID_COMMON_NAME = Buffer.from('550403', 'hex');
const OID_BASIC_CONSTRAINTS = Buffer.from('551d13', 'hex');
// 1.2.840.113635.100.6.11.1, the Apple receipt-signing marker.
const OID_RECEIPT_SIGNER = Buffer.from('2a864886f76364060b01', 'hex');

const SHA256_RSA = tlv(SEQUENCE, tlv(OID, OID_SHA256_RSA), tlv(NULL));
const name = (commonName) =>
  tlv(
    SEQUENCE,
    tlv(
      SET,
      tlv(SEQUENCE, tlv(OID, OID_COMMON_NAME), tlv(UTF8_STRING, Buffer.from(commonName, 'utf8'))),
    ),
  );
// 2024-01-01 to 2049-12-31, the window the shared generated fixtures use:
// "now" is inside it on every run until then.
const VALIDITY = tlv(
  SEQUENCE,
  tlv(UTC_TIME, Buffer.from('240101000000Z', 'ascii')),
  tlv(UTC_TIME, Buffer.from('491231235959Z', 'ascii')),
);

function extensions(...entries) {
  return tlv(CONTEXT_3, tlv(SEQUENCE, ...entries));
}
const CA_TRUE = tlv(
  SEQUENCE,
  tlv(OID, OID_BASIC_CONSTRAINTS),
  tlv(BOOLEAN, Buffer.from([0xff])),
  tlv(OCTET_STRING, tlv(SEQUENCE, tlv(BOOLEAN, Buffer.from([0xff])))),
);
const RECEIPT_SIGNER = tlv(SEQUENCE, tlv(OID, OID_RECEIPT_SIGNER), tlv(OCTET_STRING, tlv(NULL)));

let nextSerial = 1;

function certificate({ subject, issuer, subjectKey, issuerKey, extension }) {
  const serial = Buffer.from([nextSerial++]);
  const tbs = tlv(
    SEQUENCE,
    tlv(CONTEXT_0, tlv(INTEGER, Buffer.from([2]))),
    tlv(INTEGER, serial),
    SHA256_RSA,
    name(issuer),
    VALIDITY,
    name(subject),
    subjectKey.publicKey.export({ type: 'spki', format: 'der' }),
    extensions(extension),
  );
  return {
    der: tlv(
      SEQUENCE,
      tbs,
      SHA256_RSA,
      tlv(BIT_STRING, Buffer.from([0]), cryptoSign('sha256', tbs, issuerKey.privateKey)),
    ),
    sid: tlv(SEQUENCE, name(issuer), tlv(INTEGER, serial)),
  };
}

const rsaKey = () => generateKeyPairSync('rsa', { modulusLength: 2048 });

/**
 * A root, an intermediate and a receipt-signing leaf carrying the Apple
 * marker OID, all valid 2024-2049. `root` is the anchor to trust; `sign`
 * wraps a payload in a CMS SignedData the leaf really signed (no signed
 * attributes, SHA-256 with RSA, as Apple's receipts are shaped).
 */
export function mintReceiptPki() {
  const [rootKey, intermediateKey, leafKey] = [rsaKey(), rsaKey(), rsaKey()];
  const root = certificate({
    subject: 'Test Receipt Root',
    issuer: 'Test Receipt Root',
    subjectKey: rootKey,
    issuerKey: rootKey,
    extension: CA_TRUE,
  });
  const intermediate = certificate({
    subject: 'Test Receipt CA',
    issuer: 'Test Receipt Root',
    subjectKey: intermediateKey,
    issuerKey: rootKey,
    extension: CA_TRUE,
  });
  const leaf = certificate({
    subject: 'Test Receipt Signing',
    issuer: 'Test Receipt CA',
    subjectKey: leafKey,
    issuerKey: intermediateKey,
    extension: RECEIPT_SIGNER,
  });
  const sign = (payload) =>
    tlv(
      SEQUENCE,
      tlv(OID, OID_SIGNED_DATA),
      tlv(
        CONTEXT_0,
        tlv(
          SEQUENCE,
          tlv(INTEGER, Buffer.from([1])),
          tlv(SET, tlv(SEQUENCE, tlv(OID, OID_SHA256), tlv(NULL))),
          tlv(SEQUENCE, tlv(OID, OID_DATA), tlv(CONTEXT_0, tlv(OCTET_STRING, payload))),
          tlv(CONTEXT_0, leaf.der, intermediate.der),
          tlv(
            SET,
            tlv(
              SEQUENCE,
              tlv(INTEGER, Buffer.from([1])),
              leaf.sid,
              tlv(SEQUENCE, tlv(OID, OID_SHA256), tlv(NULL)),
              tlv(SEQUENCE, tlv(OID, OID_RSA_ENCRYPTION), tlv(NULL)),
              tlv(OCTET_STRING, cryptoSign('sha256', payload, leafKey.privateKey)),
            ),
          ),
        ),
      ),
    );
  return { root: root.der, sign };
}
