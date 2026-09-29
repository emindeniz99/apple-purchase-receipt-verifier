<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

/**
 * The whole legacy-receipt path on DER bytes: CMS walk, payload parse, chain
 * build, signature check. `Verifier::verifyReceipt()` takes base64 only
 * (0.7 has no raw-DER entry point — `ReceiptVerifier::verifyReceiptCore()`
 * is gone), so the fuzzer's bytes are base64-encoded first; that keeps this
 * target exploring DER-shaped structure the way it always did, rather than
 * spending most of its budget on the base64 alphabet (that is
 * `verify-receipt-base64.php`'s job).
 *
 * `verifyReceipt()` never throws (docs/design/0.7-api.md §1), so nothing is
 * an allowed exception. The anchor invariant is unchanged: an accepted
 * receipt is accepted BECAUSE of the anchors, proven by re-running it
 * against an unrelated anchor set and requiring failure. Without that a
 * fuzzer can find crashes but never "accepts what it should not".
 *
 * The anchor set is the pinned Apple roots plus the generated fixture receipt
 * root, so both the shared fixture receipts and the two public Apple receipts
 * get past the chain check and the fuzzer can explore what lies beyond it.
 * The unrelated set is the fixture *JWS* root.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$trusted = Verifier::create(Config::builder()->roots(FuzzFixtures::withReceiptRoot(AppleRootCerts::pinnedRoots()))->build(), FuzzFixtures::transport());
$unrelated = Verifier::create(Config::builder()->roots(FuzzFixtures::jwsRootOnly())->build(), FuzzFixtures::transport());

$config->setMaxLen(16384);

$config->setTarget(static function (string $input) use ($trusted, $unrelated): void {
    $result = $trusted->verifyReceipt(base64_encode($input));
    if (!$result->verified()) {
        return;
    }

    if ($unrelated->verifyReceipt(base64_encode($input))->verified()) {
        throw new \Error(
            'this input verifies against an unrelated anchor set too, '
            . 'so the anchors are not being enforced',
        );
    }
});
