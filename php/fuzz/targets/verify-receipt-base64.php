<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

/**
 * `Verifier::verifyReceipt()` on the transport string a client actually
 * sends — the receipt-base64 rule (docs/design/0.7-api.md: canonical
 * standard base64 and nothing else, as Apple's verifyReceipt accepts it)
 * and then the whole DER path behind it.
 *
 * Seeded from the `receipt-b64` fixtures and the public receipts, so the
 * fuzzer starts from strings that decode and verify rather than from noise it
 * would have to grow into base64 by itself. PHP strings are byte strings, so
 * unlike the Rust and Go targets nothing has to be skipped for not being
 * UTF-8: those bytes reach the entry point exactly as a client could send
 * them.
 *
 * Anchors are Apple's pinned receipt roots alone, matching what a consumer
 * configures. 0.7 checks no bundle id at all — that filtering is the
 * caller's job on the returned payload — so, unlike 0.6, an accepted seed
 * here says nothing about any one claim; it is the CMS/chain/signature path
 * this target explores.
 *
 * Never throws (docs/design/0.7-api.md §1), so nothing is an allowed
 * exception.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$verifier = Verifier::create(Config::builder()->roots(AppleRootCerts::pinnedRoots())->build());

$config->setMaxLen(16384);

$config->setTarget(static function (string $input) use ($verifier): void {
    $verifier->verifyReceipt($input);
});
