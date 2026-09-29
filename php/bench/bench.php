<?php

declare(strict_types=1);

/*
 * The per-call cost of the façade over each transport of `aprv`: the same
 * three operations on the same two genuine sandbox receipts as the other
 * ports' benchmarks (BENCHMARKS.md at the repository root has the table).
 *
 *     composer install --no-dev --no-scripts
 *     php bench/bench.php --aprv /path/to/aprv > php-bench.json
 *
 * `--transport cli|http|both` (default both). The CLI transport starts one
 * `aprv` process per call; the HTTP transport talks to an `aprv serve` this
 * script starts on a free loopback port. A plain script rather than phpbench,
 * which is not a dev dependency here. Each benchmark warms up for one
 * second, then takes ten samples of at least 100 ms each; the JSON on stdout
 * carries the median, minimum and maximum microseconds per operation over
 * those samples.
 *
 * Every call is run once first and must give the answer the fixture expects,
 * read from the module's JSON directly, so no benchmark times a fast
 * failure by accident.
 */

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Bench;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\HttpTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Transport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use Psr\Clock\ClockInterface;
use RuntimeException;

require __DIR__ . '/../vendor/autoload.php';

const WARMUP_S = 1.0;
const SAMPLES = 10;
const MIN_SAMPLE_S = 0.1;

/** File under fixtures/public-receipts, its bundle id and the digest fixtures/cases.json pins for it. */
const FIXTURES = [
    ['receipt-sandbox-g5', 'dev.bonzer.weeka.app', 'bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0'],
    ['receipt-sandbox-legacy', 'com.nutcall.alert', 'ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8'],
];

function check(bool $condition, string $what): void
{
    if (!$condition) {
        throw new RuntimeException("setup check failed: {$what}");
    }
}

/** @return array<string, mixed> */
function measure(string $transport, string $benchmark, string $fixture, callable $op): array
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
    fwrite(STDERR, sprintf("%-5s %-24s %-24s %10.1f us/op\n", $transport, $benchmark, $fixture, $median));

    return [
        'transport' => $transport,
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
 * java-bench's flipSignatureByte flips: in both fixtures the signature is a
 * 256-byte OCTET STRING that ends the DER, so its middle byte is 128 from the
 * end.
 */
function tamper(string $der): string
{
    $at = strlen($der) - 128;
    $der[$at] = chr(ord($der[$at]) ^ 0x01);

    return $der;
}

$options = getopt('', ['aprv:', 'transport:']);
$aprv = $options['aprv'] ?? null;
$which = $options['transport'] ?? 'both';
if (!is_string($aprv) || !in_array($which, ['cli', 'http', 'both'], true)) {
    fwrite(STDERR, "usage: php bench/bench.php --aprv PATH [--transport cli|http|both]\n");
    exit(2);
}

$clock = new class () implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        // Any fixed instant: both receipts carry a creation date, so it
        // only feeds the request_date fields.
        return new DateTimeImmutable('2026-01-01T00:00:00Z');
    }
};

/** @var array<string, Transport> $transports */
$transports = [];
$server = null;
$pipes = [];
if ($which !== 'http') {
    $transports['cli'] = new CliTransport($aprv);
}
if ($which !== 'cli') {
    $server = proc_open([$aprv, 'serve', '--listen', '127.0.0.1:0'], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    check(is_resource($server), 'aprv serve starts');
    $line = fgets($pipes[1]);
    check(is_string($line) && preg_match('/^APRV_LISTEN=(127\.0\.0\.1:\d+)$/', trim($line), $match) === 1, 'aprv serve reports its address');
    $transports['http'] = new HttpTransport('http://' . $match[1]);
}

$results = [];
foreach ($transports as $name => $transport) {
    $verifier = Verifier::create(Config::builder()->clock($clock)->build(), $transport);
    foreach (FIXTURES as [$fixture, $bundleId, $sha256]) {
        $text = file_get_contents(__DIR__ . "/../../fixtures/public-receipts/{$fixture}.b64");
        check($text !== false, "{$fixture} is readable");
        $der = base64_decode((string) $text, false);
        check(is_string($der) && hash('sha256', $der) === $sha256, "{$fixture} matches its digest in cases.json");
        $base64 = base64_encode($der);
        $requestJson = json_encode(['receipt-data' => $base64], JSON_THROW_ON_ERROR);
        $tampered = base64_encode(tamper($der));

        // Every call once, on the module's own JSON, so no benchmark times a fast failure.
        $now = (int) ($clock->now()->format('U')) * 1000;
        $answer = $transport->call(Operation::Receipt, $base64, $now);
        check(str_starts_with($answer, '{"verified":true') || str_contains($answer, '"verified":true'), "{$fixture}: verifyReceipt verifies");
        check(str_contains($answer, $bundleId), "{$fixture}: the payload names {$bundleId}");
        $endpoint = $transport->call(Operation::EndpointSandbox, $requestJson, $now);
        check(str_contains($endpoint, '"status":0'), "{$fixture}: the endpoint answers status 0");
        $refused = $transport->call(Operation::Receipt, $tampered, $now);
        check(str_contains($refused, '"verified":false'), "{$fixture}: a tampered signature is refused");

        $results[] = measure($name, 'verifyReceipt', $fixture, static fn () => $verifier->verifyReceipt($base64));
        $results[] = measure($name, 'endpointJson', $fixture, static fn () => $verifier->verifyReceiptEndpoint(Environment::Sandbox, $requestJson));
        $results[] = measure($name, 'rejectTamperedSignature', $fixture, static fn () => $verifier->verifyReceipt($tampered));
    }
}
if ($server !== null && is_resource($server)) {
    proc_terminate($server);
    proc_close($server);
}

echo json_encode([
    'port' => 'php',
    'tool' => 'bench/bench.php (hrtime)',
    'runtime' => 'PHP ' . PHP_VERSION,
    'settings' => ['warmup_s' => WARMUP_S, 'samples' => SAMPLES, 'min_sample_s' => MIN_SAMPLE_S],
    'results' => $results,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
