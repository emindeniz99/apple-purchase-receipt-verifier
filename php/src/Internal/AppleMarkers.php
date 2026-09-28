<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * Apple's two purpose-marker OIDs, shared between the receipt and JWS
 * verification paths (docs/design/0.7-api.md, "Reading certificates and
 * signed attributes"): the same purpose, whichever format carries it.
 *
 * @internal
 */
final class AppleMarkers
{
    /** Leaf certificate used for App Store / receipt signing. */
    public const LEAF_OID = '1.2.840.113635.100.6.11.1';

    /** Worldwide Developer Relations intermediate CA. */
    public const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

    private function __construct()
    {
    }
}
