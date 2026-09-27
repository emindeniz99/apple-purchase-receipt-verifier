<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\RootsData;
use RuntimeException;

/**
 * The Apple root certificates bundled with this package — copies of the
 * public roots from <https://www.apple.com/certificateauthority/>, compiled
 * into {@see RootsData} rather than read from disk at call time.
 *
 * All three published Apple roots are pinned (PLAN.md D15). Apple
 * deliberately documents the JWS chain as ending in "an Apple root
 * certificate" rather than naming one, and its guidance is to trust every
 * root on the PKI page — so anchoring on a single root would break silently
 * and with no warning if Apple ever re-anchored a path. 0.7 uses the same
 * set for both verification paths (docs/design/0.7-api.md, "Setup").
 *
 * These are trust anchors, not a trust store: nothing here reads the
 * operating system's certificates, and nothing fetches anything (PLAN.md
 * D12). A caller running its own rotation pipeline passes its own anchors to
 * {@see Config::builder()} instead.
 */
final class AppleRootCerts
{
    /**
     * Apple's published root fingerprints, compile-time constants copied
     * from the certificateauthority page, checked against the bundled
     * resources rather than trusted by virtue of shipping in this package.
     * In `certs/` order: Apple Inc. Root CA, Apple Root CA - G2, Apple Root
     * CA - G3.
     */
    private const PINNED_SHA256 = [
        'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
        'c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050',
        '63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179',
    ];

    /**
     * The three pinned Apple production roots, in a fixed order.
     *
     * @return list<string> DER bytes
     *
     * @throws RuntimeException if a bundled root is missing, does not
     *         decode, or does not match its pinned SHA-256 fingerprint —
     *         which means the resource this package shipped has been
     *         replaced, not that a receipt or JWS is untrustworthy
     */
    public static function pinnedRoots(): array
    {
        $out = [];
        foreach (RootsData::APPLE_ROOT_DER_BASE64 as $index => $base64) {
            $der = base64_decode($base64, true);
            if ($der === false) {
                throw new RuntimeException('bundled Apple root is not decodable — the package is corrupt');
            }
            $expected = self::PINNED_SHA256[$index] ?? null;
            $actual = hash('sha256', $der);
            if ($expected === null || $actual !== $expected) {
                throw new RuntimeException(
                    "bundled Apple root #{$index} has SHA-256 {$actual}, expected " . ($expected ?? '(none pinned)')
                    . ': the pinned Apple roots have been replaced',
                );
            }
            $out[] = $der;
        }

        return $out;
    }
}
