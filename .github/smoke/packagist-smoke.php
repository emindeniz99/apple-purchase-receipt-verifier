<?php

declare(strict_types=1);

// Smoke-tests the package as Packagist serves it, from a directory that is not
// the repository. Run it after installing the published version and its
// binary:
//
//   composer require "emindeniz99/apple-purchase-receipt-verifier:0.8.0"
//   vendor/bin/aprv-install
//   cp <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
//   php <repo>/.github/smoke/packagist-smoke.php
//
// Everything comes through vendor/autoload.php and the default CLI transport,
// so a package that shipped no bin/aprv-install or binaries.json, an installer
// that cannot fetch the release's binary, or a pin that no longer matches the
// published asset fails here rather than in a user's project.

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

require 'vendor/autoload.php';

$receiptB64 = trim((string) file_get_contents('receipt-sandbox-g5.b64'));
$verifier = Verifier::create(Config::defaults());

// A real Apple-signed receipt against the real pinned root, which lives inside
// aprv.wasm inside the binary the installer fetched.
$result = $verifier->verifyReceipt($receiptB64);
if (!$result->verified()) {
    fwrite(STDERR, "verification failed: {$result->failure->reason->value}: {$result->failure->message}\n");
    exit(1);
}
$receipt = $result->payload;
if ($receipt->receiptType !== 'ProductionSandbox') {
    fwrite(STDERR, "receiptType was " . var_export($receipt->receiptType, true) . ", expected ProductionSandbox\n");
    exit(1);
}
if ($receipt->bundleId !== 'dev.bonzer.weeka.app') {
    fwrite(STDERR, "bundleId was " . var_export($receipt->bundleId, true) . "\n");
    exit(1);
}

// And the negative direction, so a verifier that accepted everything would
// fail here too: the same receipt with one bit flipped in its signature, the
// byte 128 from the end of the DER (BENCHMARKS.md).
$der = (string) base64_decode($receiptB64, true);
$der[strlen($der) - 128] = chr(ord($der[strlen($der) - 128]) ^ 0x01);
$tampered = $verifier->verifyReceipt(base64_encode($der));
if ($tampered->verified() || $tampered->failure->reason !== Reason::InvalidSignature) {
    $what = $tampered->verified() ? 'verified' : $tampered->failure->reason->value;
    fwrite(STDERR, "a tampered signature was not rejected as INVALID_SIGNATURE: {$what}\n");
    exit(1);
}

echo "packagist: published package verified a genuine Apple receipt ({$receipt->bundleId}, "
    . count($receipt->inApp) . " purchases) and rejected a tampered signature\n";
