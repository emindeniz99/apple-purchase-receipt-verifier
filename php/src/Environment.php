<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * Apple's two App Store environments — the two URLs
 * {@see Verifier::verifyReceiptEndpoint()} imitates, and the environment a
 * verified payload names ({@see ReceiptPayload::$environment},
 * {@see JsonPayload::$environment}), as the module states it.
 *
 * The 0.6 `Xcode` and `LocalTesting` values are gone in 0.7: they only ever
 * named JWS `environment` strings, such payloads are not Apple-signed and
 * fail the chain check regardless, and a caller now reads that string from
 * the JSON directly (docs/design/0.7-api.md, "Helpers").
 *
 * Whether to accept an environment is the caller's decision — this library
 * takes no policy parameter for it.
 */
enum Environment: string
{
    case Production = 'Production';
    case Sandbox = 'Sandbox';
}
