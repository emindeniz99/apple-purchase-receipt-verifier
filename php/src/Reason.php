<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * The machine-readable cause of a verification failure.
 *
 * The vocabulary is closed and shared by every port of this library: the
 * backing string is byte-identical to Java's `Reason.name()`, Node's string
 * union, Python's enum value and Swift's `rawValue`, so a log line, a metrics
 * label and a `fixtures/cases.json` vector read the same in every language.
 * Read it with `$e->reason` and switch on the case; `$e->reason->value` is the
 * canonical `SCREAMING_SNAKE` token.
 *
 * Adding a twelfth case is a cross-port change, not a PHP one.
 */
enum Reason: string
{
    /** Not three dot-separated segments, bad base64url/JSON, wrong `alg`, or a malformed `x5c`. */
    case InvalidJwsFormat = 'INVALID_JWS_FORMAT';

    /** An `x5c` entry is not a parseable X.509 certificate. */
    case InvalidCertificate = 'INVALID_CERTIFICATE';

    /** A certificate is well-formed but lacks the Apple marker OID its position requires. */
    case InvalidCertificatePurpose = 'INVALID_CERTIFICATE_PURPOSE';

    /** The chain does not reach a pinned anchor, or is not valid at the signing instant. */
    case InvalidChain = 'INVALID_CHAIN';

    /** The cryptographic signature over the payload does not check out. */
    case InvalidSignature = 'INVALID_SIGNATURE';

    /** The payload's bundle id is not the configured one. */
    case WrongBundleId = 'WRONG_BUNDLE_ID';

    /** The payload's environment is outside the accepted set. */
    case WrongEnvironment = 'WRONG_ENVIRONMENT';

    /** A Production AppTransaction does not name the configured app Apple id. */
    case WrongAppAppleId = 'WRONG_APP_APPLE_ID';

    /** The legacy receipt is not a parseable CMS SignedData / attribute set. */
    case InvalidReceiptFormat = 'INVALID_RECEIPT_FORMAT';

    /** SHA1(guid ‖ opaqueValue ‖ bundleIdBytes) does not equal receipt attribute 5. */
    case DeviceHashMismatch = 'DEVICE_HASH_MISMATCH';

    /** The payload was signed longer ago than the configured max signed age. */
    case StalePayload = 'STALE_PAYLOAD';
}
