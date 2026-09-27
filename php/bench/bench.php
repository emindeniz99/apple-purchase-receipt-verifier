<?php

declare(strict_types=1);

/*
 * The cross-port benchmark: the same four operations on the same two genuine
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
 *
 *     php bench/bench.php --worst-case
 *
 * times, the same way, every shared case in fixtures/cases.json that carries
 * a maxMillis budget: the hostile inputs (oversized untrusted keys,
 * certificate meshes, encoding oddities inside certificates) the shared suite
 * bounds in time. Each call is run once first and must give the answer the
 * case expects. The README's worst-case CPU figure comes from this mode.
 */

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Bench;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
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

function check(bool $condition, string $what): void
{
    if (!$condition) {
        throw new RuntimeException("setup check failed: {$what}");
    }
}

$clock = new class () implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        // Any fixed instant: both receipts carry a creation date, so it
        // only feeds the request_date fields.
        return new DateTimeImmutable('2026-01-01T00:00:00Z');
    }
};
/**
 * A registered fixture's logical bytes, per its codec (the same rules the
 * conformance adapter in tests/ applies).
 *
 * @param array{path: string, codec: string} $entry
 */
function fixtureBytes(array $entry): string
{
    $raw = file_get_contents(__DIR__ . '/../../fixtures/' . $entry['path']);
    check($raw !== false, "{$entry['path']} is readable");

    return match ($entry['codec']) {
        'raw', 'text' => $raw,
        'base64' => base64_decode((string) preg_replace('/\s+/', '', $raw), true),
        'utf8' => trim($raw),
        default => throw new RuntimeException("unknown fixture codec {$entry['codec']}"),
    };
}

/** @return list<array<string, mixed>> */
function worstCase(ClockInterface $clock): array
{
    $file = json_decode((string) file_get_contents(__DIR__ . '/../../fixtures/cases.json'), true, 512, JSON_THROW_ON_ERROR);
    $registry = $file['fixtures'];
    $results = [];
    foreach ($file['cases'] as $case) {
        if (!isset($case['maxMillis'])) {
            continue;
        }
        $id = $case['id'];
        $builder = Config::builder()->clock($clock);
        $trusted = $case['config']['trustedRoots'];
        if ($trusted['source'] === 'fixtures') {
            $builder = $builder->roots(array_map(static fn (string $root) => fixtureBytes($registry[$root]), $trusted['fixtures']));
        }
        $verifier = Verifier::create($builder->build());
        $entry = $registry[$case['input']['fixture']];
        $bytes = fixtureBytes($entry);
        $op = match ($case['operation']) {
            'verifyReceipt' => (static function () use ($verifier, $entry, $bytes) {
                $text = in_array($entry['codec'], ['raw', 'base64'], true) ? base64_encode($bytes) : $bytes;

                return static fn () => $verifier->verifyReceipt($text);
            })(),
            'verifySignedData' => static fn () => $verifier->verifySignedData($bytes),
            default => throw new RuntimeException("{$id}: no adapter for operation {$case['operation']}"),
        };

        // The answer the case expects, before anything is timed.
        $result = $op();
        $outcome = $result->verified() ? 'ok' : $result->failure?->reason->value;
        $expected = $case['expected'];
        if (isset($expected['oneOf'])) {
            check(in_array($outcome, $expected['oneOf'], true), "{$id} answered {$outcome}");
        } else {
            check($outcome === ($expected['status'] === 'ok' ? 'ok' : $expected['reason']), "{$id} answered {$outcome}");
        }
        $results[] = measure($case['operation'], $id, $op);
    }

    return $results;
}

$worst = in_array('--worst-case', array_slice($argv, 1), true);
// The built-in Apple roots; the fixed clock only reaches request_date.
$verifier = Verifier::create(Config::builder()->clock($clock)->build());
$results = $worst ? worstCase($clock) : [];
foreach ($worst ? [] : FIXTURES as [$name, $bundleId, $inAppCount, $sha256]) {
    $text = file_get_contents(__DIR__ . "/../../fixtures/public-receipts/{$name}.b64");
    check($text !== false, "{$name} is readable");
    $der = base64_decode((string) $text, false);
    check(hash('sha256', $der) === $sha256, "{$name} matches its digest in cases.json");
    $base64 = base64_encode($der);
    $requestJson = json_encode(['receipt-data' => $base64], JSON_THROW_ON_ERROR);
    $tamperedBase64 = base64_encode(tamper($der));

    // Every call once, with the answer the conformance suite expects, so no
    // benchmark can time a fast failure by accident.
    check(Base64::decodeCanonical($base64) === $der, 'decodeBase64');
    $verified = $verifier->verifyReceipt($base64);
    check(
        $verified->verified()
            && $verified->payload->bundleId === $bundleId
            && count($verified->payload->inApp) === $inAppCount,
        'verifyReceipt',
    );
    $ok = json_decode($verifier->verifyReceiptEndpoint(Environment::Sandbox, $requestJson), true, 512, JSON_THROW_ON_ERROR);
    check($ok['status'] === 0 && count($ok['receipt']['in_app']) === $inAppCount, 'endpointJson');
    $rejected = $verifier->verifyReceipt($tamperedBase64);
    check($rejected->failure?->reason === Reason::InvalidSignature, 'rejectTamperedSignature');

    $results[] = measure('decodeBase64', $name, static fn () => Base64::decodeCanonical($base64));
    $results[] = measure('verifyReceipt', $name, static fn () => $verifier->verifyReceipt($base64));
    $results[] = measure(
        'endpointJson',
        $name,
        static fn () => $verifier->verifyReceiptEndpoint(Environment::Sandbox, $requestJson),
    );
    $results[] = measure('rejectTamperedSignature', $name, static fn () => $verifier->verifyReceipt($tamperedBase64));
}

echo json_encode([
    'port' => 'php',
    'tool' => 'bench/bench.php ' . ($worst ? 'worst-case' : 'cross-port') . ' (hrtime)',
    'runtime' => 'PHP ' . PHP_VERSION . ', ' . OPENSSL_VERSION_TEXT,
    'settings' => ['warmup_s' => WARMUP_S, 'samples' => SAMPLES, 'min_sample_s' => MIN_SAMPLE_S],
    'results' => $results,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
