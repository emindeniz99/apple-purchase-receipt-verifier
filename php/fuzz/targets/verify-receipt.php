<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

/**
 * The whole legacy-receipt path on DER bytes: CMS walk, payload parse, chain
 * build, signature check.
 *
 * The invariants are the three the Go port's `FuzzVerifyReceipt` states:
 * nothing escapes but `VerificationException` (an `InvalidArgumentException`
 * is unreachable with a non-empty anchor set, so it is a bug here, and so is
 * a `TypeError` or a warning from a parser reached with an unexpected node
 * shape); and an accepted receipt is accepted BECAUSE of the anchors, proven
 * by re-running it against an unrelated anchor set and requiring failure.
 * Without that third one a fuzzer can find crashes but never "accepts what it
 * should not".
 *
 * The anchor set is the pinned Apple roots plus the generated fixture receipt
 * root, so both the shared fixture receipts and the two public Apple receipts
 * get past the chain check and the fuzzer can explore what lies beyond it.
 * The unrelated set is the fixture *JWS* root.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$trusted = FuzzFixtures::withReceiptRoot(AppleRootCerts::receiptRoots());
$unrelated = FuzzFixtures::jwsRootOnly();

$config->setMaxLen(16384);
$config->setAllowedExceptions([VerificationException::class]);

$config->setTarget(static function (string $input) use ($trusted, $unrelated): void {
    ReceiptVerifier::verifyReceiptCore($input, $trusted);

    // Reached only when the receipt verified. An Error, not an exception:
    // the fuzzer treats Errors as findings and Exceptions as verdicts.
    try {
        ReceiptVerifier::verifyReceiptCore($input, $unrelated);
    } catch (VerificationException) {
        return;
    }

    throw new \Error(
        'this input verifies against an unrelated anchor set too, '
        . 'so the anchors are not being enforced',
    );
});
