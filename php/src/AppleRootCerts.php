<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\RootsData;

/**
 * The Apple root certificates bundled with this package — copies of the
 * public roots from <https://www.apple.com/certificateauthority/>, compiled
 * into {@see RootsData} rather than read from disk at call time.
 *
 * Both sets contain all three published Apple roots (PLAN.md D15). Apple
 * deliberately documents the JWS chain as ending in "an Apple root
 * certificate" rather than naming one, and its guidance is to trust every
 * root on the PKI page — so anchoring on a single root would break silently
 * and with no warning if Apple ever re-anchored a path.
 *
 * These are trust anchors, not a trust store: nothing here reads the
 * operating system's certificates, and nothing fetches anything (PLAN.md
 * D12). A caller running its own rotation pipeline passes its own anchors to
 * the verifier constructors instead.
 */
final class AppleRootCerts
{
    /**
     * Trust anchors for StoreKit 2 / App Store Server JWS chains.
     * Production chains currently end at Apple Root CA - G3.
     *
     * @return list<string> DER bytes
     */
    public static function jwsRoots(): array
    {
        return self::all();
    }

    /**
     * Trust anchors for legacy PKCS#7 app-receipt chains.
     * Production chains currently end at the Apple Inc. Root CA.
     *
     * @return list<string> DER bytes
     */
    public static function receiptRoots(): array
    {
        return self::all();
    }

    /** @return list<string> */
    private static function all(): array
    {
        $out = [];
        foreach (RootsData::APPLE_ROOT_DER_BASE64 as $base64) {
            $der = base64_decode($base64, true);
            if ($der === false) {
                throw new \RuntimeException('bundled Apple root is not decodable — the package is corrupt');
            }
            $out[] = $der;
        }

        return $out;
    }
}
