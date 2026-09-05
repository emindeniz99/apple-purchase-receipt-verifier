<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

/**
 * `ReceiptVerifier::verify()` on the transport string a client actually sends
 * — the receipt-base64 rule (`fixtures/cases.json`'s "Receipt base64"
 * paragraph: either alphabet, padding present or omitted, CR/LF/space/tab
 * tolerated anywhere) and then the whole DER path behind it.
 *
 * Seeded from the `receipt-b64` fixtures and the public receipts, so the
 * fuzzer starts from strings that decode and verify rather than from noise it
 * would have to grow into base64 by itself. PHP strings are byte strings, so
 * unlike the Rust and Go targets nothing has to be skipped for not being
 * UTF-8: those bytes reach the entry point exactly as a client could send
 * them.
 *
 * Anchors are Apple's pinned receipt roots alone, matching what a consumer
 * configures; the bundle id is the one the G5 public receipt carries, so an
 * accepted seed exercises the claim check rather than stopping at it.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$verifier = new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'dev.bonzer.weeka.app');

$config->setMaxLen(16384);
$config->setAllowedExceptions([VerificationException::class]);

$config->setTarget(static function (string $input) use ($verifier): void {
    $verifier->verify($input);
});
