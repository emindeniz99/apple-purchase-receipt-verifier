<?php

declare(strict_types=1);

/**
 * What a Composer consumer gets, exercised as a consumer.
 *
 * This file runs OUTSIDE the repository, in a throwaway project that
 * installed the package from an extracted `git archive`. It reaches the
 * library only through vendor/autoload.php, so it proves the three things
 * the root manifest is responsible for and the port's own suite cannot
 * check: that the archive carries the source at all, that the psr-4 root
 * pointing at php/src/ resolves once the package sits under vendor/, and
 * that the bundled Apple roots survive the trip.
 *
 * Two verifications, one per entry point, both against fixtures the shared
 * cases.json pins: a genuine Apple-signed sandbox receipt against the real
 * pinned Apple roots, and the generated StoreKit 2 transaction against its
 * own generated root. Digests are checked the way php/tests/Support/
 * Fixtures.php checks them, because a smoke that verifies fixture bytes
 * nobody pinned proves nothing.
 *
 * Usage: php php-consumer-smoke.php <vendor/autoload.php> <fixtures dir>
 */

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;

if ($argc !== 3) {
    fwrite(STDERR, "usage: php php-consumer-smoke.php <vendor/autoload.php> <fixtures dir>\n");
    exit(2);
}
[$autoload, $fixturesDir] = [$argv[1], $argv[2]];

require $autoload;

$registry = json_decode(
    (string) file_get_contents($fixturesDir . '/cases.json'),
    true,
    64,
    JSON_THROW_ON_ERROR,
)['fixtures'];

/** Decoded, digest-checked bytes of a fixture cases.json registers. */
$fixture = static function (string $id) use ($registry, $fixturesDir): string {
    $entry = $registry[$id];
    $raw = (string) file_get_contents($fixturesDir . '/' . $entry['path']);
    $bytes = match ($entry['codec']) {
        'raw' => $raw,
        'base64' => (string) base64_decode((string) preg_replace('/\s+/', '', $raw), true),
        'utf8' => trim($raw),
        default => throw new RuntimeException("unhandled codec {$entry['codec']} for {$id}"),
    };
    $actual = hash('sha256', $bytes);
    if (!hash_equals($entry['contentSha256'], $actual)) {
        throw new RuntimeException("fixture {$id} has drifted: expected {$entry['contentSha256']}, got {$actual}");
    }

    return $bytes;
};

$check = static function (string $what, mixed $actual, mixed $expected): void {
    if ($actual !== $expected) {
        fwrite(STDERR, sprintf(
            "php-consumer-smoke: %s is %s, expected %s\n",
            $what,
            var_export($actual, true),
            var_export($expected, true),
        ));
        exit(1);
    }
};

// The library was reached through vendor/autoload.php and nothing else.
$reflected = (new ReflectionClass(AppleRootCerts::class))->getFileName();
if (!str_contains((string) $reflected, '/vendor/')) {
    fwrite(STDERR, "php-consumer-smoke: AppleRootCerts loaded from {$reflected}, not from vendor/\n");
    exit(1);
}
$check('bundled Apple roots', count(AppleRootCerts::receiptRoots()), 3);

// receipt/verify-genuine-sandbox-g5-against-apple-roots.
$receipt = (new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'dev.bonzer.weeka.app'))
    ->verify($fixture('public-receipt-sandbox-g5'));
$check('receiptType', $receipt->receiptType, 'ProductionSandbox');
$check('bundleId', $receipt->bundleId, 'dev.bonzer.weeka.app');
$check('inAppPurchases count', count($receipt->inAppPurchases), 2);

// transaction/verify-shared-sandbox.
$transaction = (new JwsVerifier(
    [$fixture('jws-root')],
    'com.example.app',
    [Environment::Sandbox],
))->verifyTransaction($fixture('transaction'));
$check('transaction bundleId', $transaction->bundleId, 'com.example.app');
$check('transaction environment', $transaction->environment, 'Sandbox');
$check('transaction productId', $transaction->productId, 'com.example.app.pro');
$check('transaction transactionId', $transaction->transactionId, '2000000000000001');
$check('transaction signedDate', $transaction->signedDate, 1722945600000);

echo "php-consumer-smoke: OK\n";
echo "  autoloaded from {$reflected}\n";
echo "  receipt  {$receipt->receiptType} {$receipt->bundleId}, "
    . count($receipt->inAppPurchases) . " in-app purchases\n";
echo "  jws      {$transaction->productId} {$transaction->environment} {$transaction->transactionId}\n";
