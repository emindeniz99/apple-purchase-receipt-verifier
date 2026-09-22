<?php

declare(strict_types=1);

/*
 * The cross-port benchmark: the same six operations on the same two genuine
 * sandbox receipts in every port, named after the Java JMH benchmarks in
 * java-bench/ (BENCHMARKS.md at the repository root has the table).
 *
 *     composer install --no-dev --no-scripts
 *     php bench/bench.php > php-bench.json
 *
 * A plain script rather than phpbench, which is not a dev dependency here.
 * Each benchmark warms up for one second, then takes ten samples of at least
 * 100 ms each; the JSON on stdout carries the median, minimum and maximum
 * microseconds per operation over those samples.
 */

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Bench;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use Psr\Clock\ClockInterface;
use RuntimeException;

require __DIR__ . '/../vendor/autoload.php';

const WARMUP_S = 1.0;
const SAMPLES = 10;
const MIN_SAMPLE_S = 0.1;

/**
 * File under fixtures/public-receipts, and the bundle id, in-app count and
 * digest fixtures/cases.json pins for it.
 */
const FIXTURES = [
    ['receipt-sandbox-g5', 'dev.bonzer.weeka.app', 2, 'bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0'],
    ['receipt-sandbox-legacy', 'com.nutcall.alert', 187, 'ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8'],
];

/** @return array<string, mixed> */
function measure(string $benchmark, string $fixture, callable $op): array
{
    $start = hrtime(true);
    $warmupOps = 0;
    while ((hrtime(true) - $start) / 1e9 < WARMUP_S) {
        $op();
        ++$warmupOps;
    }
    $perOp = (hrtime(true) - $start) / 1e9 / $warmupOps;
    $ops = max(1, (int) (MIN_SAMPLE_S / $perOp) + 1);
    $samples = [];
    for ($s = 0; $s < SAMPLES; ++$s) {
        $t = hrtime(true);
        for ($i = 0; $i < $ops; ++$i) {
            $op();
        }
        $samples[] = (hrtime(true) - $t) / 1e3 / $ops;
    }
    sort($samples);
    $median = ($samples[SAMPLES / 2 - 1] + $samples[SAMPLES / 2]) / 2;
    fwrite(STDERR, sprintf("%24s %-24s %12.1f us/op\n", $benchmark, $fixture, $median));

    return [
        'benchmark' => $benchmark,
        'fixture' => $fixture,
        'us_per_op_median' => $median,
        'us_per_op_min' => $samples[0],
        'us_per_op_max' => $samples[SAMPLES - 1],
        'ops_per_sample' => $ops,
    ];
}

/**
 * Flips one bit in the middle of the SignerInfo signature, the byte
 * java-bench's flipSignatureByte flips. In both fixtures the signature is a
 * 256-byte OCTET STRING that ends the DER (openssl asn1parse shows it), so
 * its middle byte is 128 from the end; setup proves the flip landed there by
 * requiring INVALID_SIGNATURE.
 */
function tamper(string $der): string
{
    $at = strlen($der) - 128;
    $der[$at] = chr(ord($der[$at]) ^ 0x01);

    return $der;
}

/** @param list<mixed> $roots */
function reject(string $der, array $roots): mixed
{
    try {
        return ReceiptVerifier::verifyReceiptCore($der, $roots);
    } catch (VerificationException $e) {
        return $e;
    }
}

function check(bool $condition, string $what): void
{
    if (!$condition) {
        throw new RuntimeException("setup check failed: {$what}");
    }
}

$clock = new class () implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        // Any fixed instant: it only feeds the request_date fields.
        return new DateTimeImmutable('2026-01-01T00:00:00Z');
    }
};
$roots = AppleRootCerts::receiptRoots();
$results = [];
foreach (FIXTURES as [$name, $bundleId, $inAppCount, $sha256]) {
    $text = file_get_contents(__DIR__ . "/../../fixtures/public-receipts/{$name}.b64");
    check($text !== false, "{$name} is readable");
    $der = base64_decode((string) $text, false);
    check(hash('sha256', $der) === $sha256, "{$name} matches its digest in cases.json");
    $base64 = base64_encode($der);
    $request = ['receipt-data' => $base64];
    $requestJson = json_encode($request, JSON_THROW_ON_ERROR);
    $tampered = tamper($der);
    $verifier = new ReceiptVerifier($roots, $bundleId);
    $sandbox = new VerifyReceiptEndpoint($roots, Environment::Sandbox, $clock);
    $production = new VerifyReceiptEndpoint($roots, Environment::Production, $clock);

    // Every call once, with the answer the conformance suite expects, so no
    // benchmark can time a fast failure by accident.
    check(Base64::decodeReceipt($base64) === $der, 'decodeBase64');
    foreach ([ReceiptVerifier::verifyReceiptCore($der, $roots), $verifier->verify($base64)] as $receipt) {
        check($receipt->bundleId === $bundleId && count($receipt->inAppPurchases) === $inAppCount, 'receipt');
    }
    $ok = json_decode($sandbox->verifyReceiptJson($requestJson), true, 512, JSON_THROW_ON_ERROR);
    check($ok['status'] === 0 && count($ok['receipt']['in_app']) === $inAppCount, 'endpointJson');
    $retry = json_decode(
        $production->verifyReceiptResult($request)->toJson(Environment::Sandbox),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );
    check($retry['status'] === 0 && $retry['environment'] === 'Sandbox', 'retryViaResult');
    $rejected = reject($tampered, $roots);
    check($rejected instanceof VerificationException && $rejected->reason === Reason::InvalidSignature, 'rejectTamperedSignature');

    $results[] = measure('decodeBase64', $name, static fn () => Base64::decodeReceipt($base64));
    $results[] = measure('core', $name, static fn () => ReceiptVerifier::verifyReceiptCore($der, $roots));
    $results[] = measure('verifierBase64', $name, static fn () => $verifier->verify($base64));
    $results[] = measure('endpointJson', $name, static fn () => $sandbox->verifyReceiptJson($requestJson));
    $results[] = measure(
        'retryViaResult',
        $name,
        static fn () => $production->verifyReceiptResult($request)->toJson(Environment::Sandbox),
    );
    $results[] = measure('rejectTamperedSignature', $name, static fn () => reject($tampered, $roots));
}

echo json_encode([
    'port' => 'php',
    'tool' => 'bench/bench.php (hrtime)',
    'runtime' => 'PHP ' . PHP_VERSION . ', ' . OPENSSL_VERSION_TEXT,
    'settings' => ['warmup_s' => WARMUP_S, 'samples' => SAMPLES, 'min_sample_s' => MIN_SAMPLE_S],
    'results' => $results,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
