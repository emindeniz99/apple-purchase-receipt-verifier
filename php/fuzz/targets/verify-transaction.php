<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

/**
 * The StoreKit 2 path: compact-JWS split, strict base64url, JSON header and
 * payload, `x5c` certificates, chain, ES256 signature — `Verifier::verifySignedData()`,
 * the one 0.7 JWS entry point (`verifyTransaction`/`verifyAppTransaction`/
 * `verifyRaw` are gone; claim filtering, including bundle id, is the
 * caller's job on the returned JSON text).
 *
 * `verifySignedData()` never throws (docs/design/0.7-api.md §2), so nothing
 * is an allowed exception any more: anything that escapes is a finding. The
 * anchor-enforcement invariant survives unchanged: a JWS that verifies under
 * the fixture root must be refused under Apple's real roots, or the anchors
 * are not what decided it.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$verifier = Verifier::create(Config::builder()->roots(FuzzFixtures::jwsRootOnly())->build(), FuzzFixtures::transport());
$unrelated = Verifier::create(Config::defaults(), FuzzFixtures::transport());

$config->setMaxLen(8192);

$config->setTarget(static function (string $input) use ($verifier, $unrelated): void {
    $result = $verifier->verifySignedData($input);
    if (!$result->verified()) {
        return;
    }

    if ($unrelated->verifySignedData($input)->verified()) {
        throw new \Error(
            'this input verifies against Apple\'s roots too, '
            . 'so the anchors are not being enforced',
        );
    }
});
