<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * Apple's two App Store environments — the two URLs
 * {@see Verifier::verifyReceiptEndpoint()} imitates.
 *
 * The 0.6 `Xcode` and `LocalTesting` values are gone in 0.7: they only ever
 * named JWS `environment` strings, such payloads are not Apple-signed and
 * fail the chain check regardless, and a caller now reads that string from
 * the JSON directly (docs/design/0.7-api.md, "Helpers").
 *
 * The helpers below state what an Apple value means; whether to accept an
 * environment is the caller's decision — this library takes no policy
 * parameter for it.
 */
enum Environment: string
{
    case Production = 'Production';
    case Sandbox = 'Sandbox';

    /**
     * Maps a receipt's `receipt_type` (attribute 0): `Production` and
     * `ProductionVPP` to {@see Production}, `ProductionSandbox` and
     * `ProductionVPPSandbox` to {@see Sandbox}, anything else — a missing
     * value included — to `null`. {@see Verifier::verifyReceiptEndpoint()}
     * uses the same rule for status 21007 and 21008.
     */
    public static function fromReceiptType(?string $receiptType): ?self
    {
        return match ($receiptType) {
            'Production', 'ProductionVPP' => self::Production,
            'ProductionSandbox', 'ProductionVPPSandbox' => self::Sandbox,
            default => null,
        };
    }

    /**
     * Maps a JWS `environment` claim: `Production` to {@see Production},
     * `Sandbox` to {@see Sandbox}, anything else (`Xcode`, `LocalTesting`, a
     * missing claim) to `null`.
     */
    public static function fromJwsEnvironment(?string $environment): ?self
    {
        return match ($environment) {
            'Production' => self::Production,
            'Sandbox' => self::Sandbox,
            default => null,
        };
    }
}
