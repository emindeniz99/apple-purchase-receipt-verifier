<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * One CMS SignerInfo, structurally decoded but not yet cryptographically
 * checked. `signedAttrs`, when present, has already had its SET-OF-Attribute
 * syntax validated (docs/design/0.7-hardening-parity.md, hardening parity
 * change #4 / J4): every SignerInfo's signedAttrs is checked before any
 * signature, in receipt order, regardless of which signer eventually
 * verifies.
 *
 * @internal
 */
final class CmsSignerInfo
{
    public function __construct(
        public readonly string $issuerRaw,
        public readonly string $serial,
        /** Dotted digestAlgorithm OID, unresolved: an unsupported digest is a signature-time verdict, not a parse-time one. */
        public readonly string $digestAlgorithmOid,
        public readonly ?Asn1Node $signedAttrs,
        /** Dotted signatureAlgorithm OID. */
        public readonly string $signatureAlgorithmOid,
        public readonly string $signature,
    ) {
    }
}
