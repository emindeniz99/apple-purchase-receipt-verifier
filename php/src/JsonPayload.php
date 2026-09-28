<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * A verified Apple-signed compact JWS payload — StoreKit 2 transactions,
 * renewal info, app transactions, and App Store Server Notifications V2
 * (docs/design/0.7-api.md §2). One method covers every Apple JWS; the
 * header (`alg`, `x5c`) is not returned, as the receipt side returns no
 * algorithm or certificates.
 *
 * The library ships no typed JWS models and no parse helper: parse
 * {@see $json} with your own JSON library, or Apple's own
 * `app-store-server-library` model classes where one exists for your
 * language (the README shows both).
 */
final readonly class JsonPayload
{
    public function __construct(
        /** The verified payload, unchanged: the exact JSON text the JWS's payload segment decoded to. */
        public string $json,
    ) {
    }
}
