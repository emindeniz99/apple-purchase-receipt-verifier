<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

/**
 * The StoreKit 2 path: compact-JWS split, strict base64url, JSON header and
 * payload, `x5c` certificates, chain, ES256 signature, then the three public
 * entry points' claim checks.
 *
 * Same invariants as the Go port's `FuzzVerifyTransaction`: nothing escapes
 * but `VerificationException`, and a JWS `verifyRaw` accepts under the
 * fixture root must be refused under Apple's roots, or the anchors are not
 * what decided it.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$verifier = new JwsVerifier(
    FuzzFixtures::jwsRootOnly(),
    'com.example.app',
    [Environment::Sandbox],
);
$unrelated = new JwsVerifier(
    AppleRootCerts::jwsRoots(),
    'com.example.app',
    [Environment::Sandbox],
);

$config->setMaxLen(8192);
$config->setAllowedExceptions([VerificationException::class]);

$config->setTarget(static function (string $input) use ($verifier, $unrelated): void {
    // Each entry point is exercised even when an earlier one rejects: a
    // VerificationException is a verdict, and only something else is a
    // finding. Anything that is not a VerificationException propagates out of
    // these blocks and the fuzzer records it as a crash.
    try {
        $verifier->verifyTransaction($input);
    } catch (VerificationException) {
    }
    try {
        $verifier->verifyAppTransaction($input);
    } catch (VerificationException) {
    }

    try {
        $verifier->verifyRaw($input);
    } catch (VerificationException) {
        return;
    }

    try {
        $unrelated->verifyRaw($input);
    } catch (VerificationException) {
        return;
    }

    throw new \Error(
        'this input verifies against Apple\'s roots too, '
        . 'so the anchors are not being enforced',
    );
});
