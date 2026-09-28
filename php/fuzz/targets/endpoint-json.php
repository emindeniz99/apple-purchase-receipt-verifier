<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

/**
 * `Verifier::verifyReceiptEndpoint()`, the one entry point that takes a
 * request body rather than a receipt: JSON parse, `receipt-data`
 * extraction, the receipt-base64 rule, then the DER path.
 *
 * Its contract is stronger than every other target's — it NEVER throws, for
 * any bytes at all, and always answers a JSON object carrying a numeric
 * `status`. So the allowed-exception list is empty: any `Throwable` is a
 * finding. Both halves of the contract are asserted after every call.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$verifier = Verifier::create(Config::builder()->roots(AppleRootCerts::pinnedRoots())->build());

$config->setMaxLen(16384);
$config->setAllowedExceptions([]);

$config->setTarget(static function (string $input) use ($verifier): void {
    $response = $verifier->verifyReceiptEndpoint(Environment::Sandbox, $input);

    $parsed = json_decode($response, true);
    if (!is_array($parsed)) {
        throw new \Error('the endpoint must answer with a JSON object: ' . $response);
    }
    if (!isset($parsed['status']) || !is_int($parsed['status'])) {
        throw new \Error('the endpoint must answer with a numeric status: ' . $response);
    }
});
