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
 * Two verifications, one per verify method, both against fixtures the
 * shared cases.json pins: a genuine Apple-signed sandbox receipt against the
 * real pinned Apple roots (Config::defaults()), and the generated StoreKit 2
 * transaction against its own generated root. Digests are checked the way
 * php/tests/Support/Fixtures07.php checks them, because a smoke that
 * verifies fixture bytes nobody pinned proves nothing.
 *
 * The binary under test comes from APRV_BIN: the package ships none.
 *
 * Usage: APRV_BIN=/path/to/aprv php php-consumer-smoke.php <vendor/autoload.php> <fixtures dir>
 */

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

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
        'text' => $raw,
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
$reflected = (new ReflectionClass(Config::class))->getFileName();
if (!str_contains((string) $reflected, '/vendor/')) {
    fwrite(STDERR, "php-consumer-smoke: Config loaded from {$reflected}, not from vendor/\n");
    exit(1);
}
// The package carries no copy of the roots: null means the module's built-in ones.
$check('Config::defaults() roots', Config::defaults()->roots, null);

// The package ships no binary. APRV_BIN names the aprv binary under test (CI
// downloads the release asset, or builds it); `vendor/bin/aprv-install` is
// what a consumer runs against a released version.
$binary = getenv('APRV_BIN');
if (!is_string($binary) || $binary === '') {
    fwrite(STDERR, "php-consumer-smoke: set APRV_BIN to the aprv binary\n");
    exit(2);
}
$transport = static fn (): CliTransport => new CliTransport($binary);

// receipt/verify-genuine-sandbox-g5-against-apple-roots.
$receiptResult = Verifier::create(Config::defaults(), $transport())
    ->verifyReceipt(base64_encode($fixture('public-receipt-sandbox-g5')));
$check('receipt verified', $receiptResult->verified(), true);
$receipt = $receiptResult->payload;
$check('receiptType', $receipt->receiptType, 'ProductionSandbox');
$check('bundleId', $receipt->bundleId, 'dev.bonzer.weeka.app');
$check('inApp count', count($receipt->inApp), 2);

// The shared transaction, under its own generated root.
$jwsResult = Verifier::create(new Config(roots: [$fixture('jws-root')]), $transport())
    ->verifySignedData($fixture('transaction'));
$check('transaction verified', $jwsResult->verified(), true);
$transaction = json_decode($jwsResult->payload->json, true, 64, JSON_THROW_ON_ERROR);
$check('transaction bundleId', $transaction['bundleId'], 'com.example.app');
$check('transaction environment', $transaction['environment'], 'Sandbox');
$check('transaction productId', $transaction['productId'], 'com.example.app.pro');
$check('transaction transactionId', $transaction['transactionId'], '2000000000000001');
$check('transaction signedDate', $transaction['signedDate'], 1722945600000);

echo "php-consumer-smoke: OK\n";
echo "  autoloaded from {$reflected}\n";
echo "  receipt  {$receipt->receiptType} {$receipt->bundleId}, "
    . count($receipt->inApp) . " in-app purchases\n";
echo "  jws      {$transaction['productId']} {$transaction['environment']} {$transaction['transactionId']}\n";
