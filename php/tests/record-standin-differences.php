<?php

declare(strict_types=1);

// Writes standin-differences.txt: the ids of the fixtures/cases.json cases
// that fail on the component `aprv` runs. Run it only when that component is
// the round-13 stand-in (the 0.6 core in 0.7's ABI), and regenerate when the
// stand-in changes. The list records the component's hash and applies to that
// component only: any other must pass every case.
//
// It uses PHPUnit's assertions, so PHPUnit's autoloader has to be loaded: run
// it as a PHPUnit bootstrap (it exits before PHPUnit looks for tests).
//
//   APRV_BIN=/path/to/aprv vendor/bin/phpunit --bootstrap tests/record-standin-differences.php

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\ConformanceBase;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

require __DIR__ . '/bootstrap.php';

$hash = Aprv::componentSha256();
$factory = static fn (Config $config): Verifier => Verifier::create($config, new CliTransport(Aprv::binary()));
$failing = [];
/** @var list<array<string, mixed>> $cases */
$cases = Fixtures07::cases()['cases'];
foreach ($cases as $case) {
    try {
        ConformanceBase::execute($case, $factory);
    } catch (Throwable) {
        /** @var string $id */
        $id = $case['id'];
        $failing[] = $id;
    }
}
$lines = [
    '# Cases of fixtures/cases.json that fail on the stand-in component: ' . count($failing) . ' of ' . count($cases) . '.',
    '# The stand-in is the round-13 core component on the 0.6 core: it answers 0.6\'s JSON shapes and',
    '# reason names, which the façade does not read as 0.7. The list applies to the component hashed',
    '# below and to no other. Regenerate: see tests/record-standin-differences.php',
    "# component_sha256 {$hash}",
    ...$failing,
];
file_put_contents(__DIR__ . '/standin-differences.txt', implode("\n", $lines) . "\n");
fwrite(STDOUT, count($failing) . ' of ' . count($cases) . " cases fail on component {$hash}\n");
exit(0);
