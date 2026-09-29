<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * Why a verification failed (docs/design/0.7-api.md, "Result").
 *
 * The vocabulary is closed and shared by every port of this library: the
 * backing string is byte-identical to Java's `Reason.name()`, and a
 * `fixtures/cases.json` vector reads the same in every language. Match
 * on the case, never persist an ordinal: the set may grow between 0.x
 * releases.
 */
enum Reason: string
{
    /** The base64, ASN.1, CMS or JWS structure is broken, or a structural bound (other than a size cap) was exceeded. Decided before any signature is checked. */
    case Malformed = 'MALFORMED';

    /** The input is over a fixed size cap. Decided before anything is decoded. */
    case TooLarge = 'TOO_LARGE';

    /** The signature does not match the signed content. */
    case InvalidSignature = 'INVALID_SIGNATURE';

    /** The chain does not reach a pinned root, or is longer than the maximum. */
    case UntrustedChain = 'UNTRUSTED_CHAIN';

    /** A certificate the check depends on does not decode, or is expired or not yet valid at the checked instant. */
    case InvalidCertificate = 'INVALID_CERTIFICATE';

    /** A certificate that chains to a pinned root but is of the wrong kind: a marker OID is missing. */
    case InvalidCertificatePurpose = 'INVALID_CERTIFICATE_PURPOSE';

    /** The signature and chain verified — the payload bytes are Apple's — but they do not parse. Deterministic: alert, do not retry. */
    case UnreadablePayload = 'UNREADABLE_PAYLOAD';

    /** The library itself failed before it could decide: the module trapped, `aprv` did not answer, or the clock threw. `Failure::$cause` says which when this library produced it. Deterministic: alert, do not retry. */
    case InternalError = 'INTERNAL_ERROR';
}
