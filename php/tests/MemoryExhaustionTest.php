<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Subprocess;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The failure mode PHP has and the other ports do not: **out of memory is a
 * fatal error, not a `Throwable`**.
 *
 * `JwsVerifier::verifySignature()`, `ReceiptVerifier::verifyReceiptCore()` and
 * `VerifyReceiptEndpoint` all promise that only a typed verdict escapes. A
 * `memory_limit` exhaustion cannot be caught by any of them: the worker dies
 * with exit 255 and no response at all. So every bound this library declares
 * has to hold *before* the allocation happens, and every one of them is a
 * security control rather than a nicety — an unauthenticated request that kills
 * a worker is a denial of service against every other request it was serving.
 *
 * The three bounds the library declared before these tests existed each
 * constrain a different axis, and hostile input inside all three still killed
 * the process:
 *
 * - `Der::MAX_DEPTH` bounds nesting, not bytes;
 * - `Der::DEFAULT_NODE_BUDGET` bounds node count, and deep-but-large nesting
 *   costs ~33 nodes for megabytes of retained state;
 * - `ReceiptVerifier::DEFAULT_MAX_RECEIPT_BYTES` bounds the receipt path only,
 *   and the JWS and endpoint paths had no byte cap at all.
 *
 * The missing bound is on the **product**: PHP has no zero-copy slice, so
 * `Der` retains roughly `2 x depth x input` bytes, which
 * {@see Der::DEFAULT_BYTE_BUDGET} is what actually caps.
 *
 * These vectors run in a child process at the `php.ini-production` default
 * `memory_limit` of 128M, because a test that triggered the fatal in-process
 * would take PHPUnit down with it. They are deliberately in no PHPUnit group:
 * they are the regression fences for a remotely triggerable worker kill, so
 * there must be no `--exclude-group` that quietly stops running them.
 */
#[CoversNothing]
final class MemoryExhaustionTest extends TestCase
{
    /**
     * Shared prelude: DER length encoding and a "deep but large" blob, which
     * is the shape all three declared bounds wave through.
     */
    private const PRELUDE = <<<'PHP'
        function derLen(int $n): string {
            if ($n < 0x80) { return chr($n); }
            $b = ''; $x = $n;
            while ($x > 0) { $b = chr($x & 0xff) . $b; $x >>= 8; }
            return chr(0x80 | strlen($b)) . $b;
        }
        /** One chain of $depth SEQUENCEs wrapped around $payload bytes. */
        function nested(int $depth, int $payload): string {
            $node = "\x04" . derLen($payload) . str_repeat("\x41", $payload);
            for ($i = 0; $i < $depth; ++$i) { $node = "\x30" . derLen(strlen($node)) . $node; }
            return $node;
        }
        function report(string $verdict): void {
            printf("VERDICT=%s PEAK_MB=%.1f\n", $verdict, memory_get_peak_usage(true) / 1048576);
        }
        PHP;

    /** @return array{int, string} */
    private static function child(string $body, string $memoryLimit = Subprocess::PRODUCTION_MEMORY_LIMIT): array
    {
        return Subprocess::run(self::PRELUDE . "\n" . $body, $memoryLimit);
    }

    private static function assertVerdict(string $expected, string $body, string $memoryLimit): float
    {
        [$status, $output] = self::child($body, $memoryLimit);

        self::assertSame(
            0,
            $status,
            "the worker did not survive the vector at memory_limit={$memoryLimit}; output was:\n" . $output,
        );
        self::assertMatchesRegularExpression('/^VERDICT=' . preg_quote($expected, '/') . ' /m', $output, $output);
        self::assertSame(1, preg_match('/PEAK_MB=([0-9.]+)/', $output, $m), $output);

        return (float) Shape::asString($m[1] ?? null, 'PEAK_MB capture');
    }

    /**
     * A JWS whose `x5c[0]` is a 4 MB payload behind 32 SEQUENCEs. Depth 32 is
     * the declared maximum and the blob is ~33 nodes, so neither the depth
     * ceiling nor the node budget sees anything wrong; the receipt path's byte
     * cap does not apply here at all. Before {@see JwsVerifier::MAX_JWS_BYTES}
     * this died at `Der.php` line 132 with exit 255.
     */
    public function testAJwsCarryingADeeplyNestedCertificateDoesNotKillTheWorker(): void
    {
        self::assertVerdict('INVALID_JWS_FORMAT', <<<'PHP'
            $jws = trim(file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/transaction.jws'));
            $parts = explode('.', $jws);
            $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
            $header['x5c'][0] = base64_encode(nested(32, 4 * 1024 * 1024));
            $evil = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=')
                . '.' . $parts[1] . '.' . $parts[2];
            $verifier = new \EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/jws-root.der')],
                'com.example.app',
                [\EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Sandbox],
            );
            try {
                $verifier->verifyRaw($evil);
                report('ACCEPTED');
            } catch (\EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException $e) {
                report($e->reason->value);
            }
            PHP, Subprocess::PRODUCTION_MEMORY_LIMIT);
    }

    /**
     * The payload segment is base64-decoded and JSON-parsed at step 3, BEFORE
     * the signature is checked at step 5 — so no valid signature is needed to
     * reach the allocation. A flat array of ~700k tiny nodes expands roughly
     * 48x under `json_decode`, and `JSON_MAX_DEPTH` bounds nesting, not
     * breadth. Before the size cap this died at `JwsClaims.php` line 73.
     */
    public function testAJwsCarryingAJsonBombPayloadDoesNotKillTheWorker(): void
    {
        self::assertVerdict('INVALID_JWS_FORMAT', <<<'PHP'
            $jws = trim(file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/transaction.jws'));
            $parts = explode('.', $jws);
            $bomb = '{"a":[' . implode(',', array_fill(0, 700000, '[[]]')) . ']}';
            $evil = $parts[0] . '.' . rtrim(strtr(base64_encode($bomb), '+/', '-_'), '=') . '.' . $parts[2];
            $verifier = new \EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/jws-root.der')],
                'com.example.app',
                [\EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Sandbox],
            );
            try {
                $verifier->verifyRaw($evil);
                report('ACCEPTED');
            } catch (\EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException $e) {
                report($e->reason->value);
            }
            PHP, Subprocess::PRODUCTION_MEMORY_LIMIT);
    }

    /**
     * The bomb sits in a sibling key, so this is the request-body `json_decode`
     * itself and has nothing to do with whether `receipt-data` is valid. The
     * class docblock says neither method ever throws; before the request cap
     * this died at `VerifyReceiptEndpoint.php` line 168 and returned nothing.
     */
    public function testAJsonBombRequestBodyDoesNotKillTheWorker(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $endpoint = new \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/receipt-root.der')],
                \EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production,
            );
            $body = '{"receipt-data":"AA","x":[' . implode(',', array_fill(0, 700000, '[[]]')) . ']}';
            $answer = $endpoint->verifyReceiptJson($body);
            report($answer);
            PHP);

        self::assertSame(0, $status, "the worker did not survive a JSON-bomb request body; output was:\n" . $output);
        self::assertStringContainsString('VERDICT={"status":21002}', $output, $output);
    }

    /**
     * `receipt-data` is base64-decoded by the endpoint before
     * `verifyReceiptCore` gets a chance to apply its own byte cap, so the cap
     * has to be applied to the transport string here too.
     */
    public function testAnOversizedReceiptDataPropertyIsRejectedBeforeItIsDecoded(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $endpoint = new \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/receipt-root.der')],
                \EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production,
            );
            // 96 MB of base64: ~72 MB once decoded, which on its own is most of
            // a 128M budget before a single byte has been parsed.
            $answer = $endpoint->verifyReceipt(['receipt-data' => str_repeat('QUFB', 24 * 1024 * 1024)]);
            report(json_encode($answer));
            PHP);

        self::assertSame(0, $status, "the worker did not survive an oversized receipt-data; output was:\n" . $output);
        self::assertStringContainsString('VERDICT={"status":21002}', $output, $output);
    }

    /**
     * The load-bearing one, and the vector every declared bound waved through:
     * 600 sibling chains, each 31 SEQUENCEs deep around ~3 KB, is 19,201 nodes
     * (under the 20,000 budget), depth 31 (under the 32 ceiling) and 1.9 MB
     * (under the 2 MiB receipt cap) — and cost 92 MB of parser state, because
     * every level of nesting copies the bytes below it again.
     *
     * Run with no memory limit so the cost is *measured* rather than merely
     * survived: the assertion is on the peak, which is the axis the byte budget
     * bounds.
     */
    public function testDeepAndLargeNestingTogetherStaysInsideAMeasuredMemoryCeiling(): void
    {
        $peak = self::assertVerdict('INVALID_RECEIPT_FORMAT', <<<'PHP'
            $blob = '';
            for ($c = 0; $c < 600; ++$c) { $blob .= nested(31, 3100); }
            $blob = "\x30" . derLen(strlen($blob)) . $blob;
            if (strlen($blob) > \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier::DEFAULT_MAX_RECEIPT_BYTES) {
                throw new RuntimeException('harness error: vector is outside the declared byte cap, so it proves nothing');
            }
            $verifier = new \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/receipt-root.der')],
                'com.example.app',
            );
            try {
                $verifier->verify($blob);
                report('ACCEPTED');
            } catch (\EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException $e) {
                report($e->reason->value);
            }
            PHP, '-1');

        self::assertLessThan(
            48.0,
            $peak,
            'parsing a hostile receipt inside every declared bound cost ' . $peak . ' MB of parser state',
        );
    }

    /**
     * The same vector through the endpoint, at the production memory limit and
     * sized so its BASE64 form — which is what the transport cap sees — stays
     * inside the receipt cap, so the parser really does run on it.
     */
    public function testDeepAndLargeNestingThroughTheEndpointDoesNotKillTheWorker(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $blob = '';
            for ($c = 0; $c < 480; ++$c) { $blob .= nested(31, 3100); }
            $blob = "\x30" . derLen(strlen($blob)) . $blob;
            if (strlen(base64_encode($blob)) > \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier::DEFAULT_MAX_RECEIPT_BYTES) {
                throw new RuntimeException('harness error: the base64 form is over the cap, so the parser never runs');
            }
            $endpoint = new \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/receipt-root.der')],
                \EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production,
            );
            report(json_encode($endpoint->verifyReceipt(['receipt-data' => base64_encode($blob)])));
            PHP);

        self::assertSame(0, $status, "the worker did not survive the vector through the endpoint:\n" . $output);
        self::assertStringContainsString('VERDICT={"status":21002}', $output, $output);
    }

    /**
     * The bounds are only defensible if a genuine receipt is nowhere near
     * them. The largest public fixture — 79 KB, 187 in-app purchases — retains
     * under a megabyte, two orders of magnitude inside the byte budget.
     */
    public function testTheLargestGenuineReceiptIsFarInsideTheByteBudget(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $legacy = \EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::bytes('public-receipt-sandbox-legacy');
            $tight = \EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der::DEFAULT_BYTE_BUDGET;
            $node = \EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der::parse($legacy, 20000, intdiv($tight, 16));
            report('parsed-at-one-sixteenth-of-the-budget');
            PHP);

        self::assertSame(0, $status, $output);
        self::assertStringContainsString('VERDICT=parsed-at-one-sixteenth-of-the-budget', $output, $output);
    }

    /**
     * The caps only mean something if an input sized exactly AT one of them is
     * still affordable — a bound that merely moves the cliff is not a bound.
     * Both vectors below are built to sit just inside their cap and to be the
     * most expensive shape that fits: an `x5c` entry nested to
     * `Der::MAX_DEPTH`, and a request body that is nothing but JSON-bomb nodes.
     *
     * Measured at the `php.ini-production` limit: 10 MB and 52 MB peak.
     */
    public function testAnInputSizedExactlyAtEachCapIsStillAffordable(): void
    {
        $peak = self::assertVerdict('INVALID_CERTIFICATE', <<<'PHP'
            $blob = nested(32, 143000);
            $jws = trim(file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/transaction.jws'));
            $parts = explode('.', $jws);
            $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
            $header['x5c'][0] = base64_encode($blob);
            $evil = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=')
                . '.' . $parts[1] . '.' . $parts[2];
            if (strlen($evil) > \EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier::MAX_JWS_BYTES) {
                throw new RuntimeException('harness error: over the cap, so the parser never runs');
            }
            $verifier = new \EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/jws-root.der')],
                'com.example.app',
                [\EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Sandbox],
            );
            try {
                $verifier->verifyRaw($evil);
                report('ACCEPTED');
            } catch (\EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException $e) {
                report($e->reason->value);
            }
            PHP, Subprocess::PRODUCTION_MEMORY_LIMIT);
        self::assertLessThan(32.0, $peak, 'a JWS at the cap cost ' . $peak . ' MB');

        [$status, $output] = self::child(<<<'PHP'
            $cap = \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint::MAX_REQUEST_BYTES;
            $body = '{"receipt-data":"AA","x":[' . str_repeat('[[]],', intdiv($cap - 40, 5));
            $body = rtrim($body, ',') . ']}';
            if (strlen($body) > $cap) {
                throw new RuntimeException('harness error: over the cap, so json_decode never runs');
            }
            $endpoint = new \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint(
                [file_get_contents(\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures::directory() . '/generated/receipt-root.der')],
                \EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production,
            );
            report($endpoint->verifyReceiptJson($body));
            PHP);

        self::assertSame(0, $status, "a request body at the cap did not survive:\n" . $output);
        self::assertStringContainsString('VERDICT={"status":21002}', $output, $output);
    }

    /** The declared bounds sit far above any real input, and are documented. */
    public function testTheDeclaredBoundsLeaveRoomForEveryGenuineInput(): void
    {
        // The largest genuine JWS in the corpus is ~2.5 KB.
        self::assertGreaterThan(100 * 2500, JwsVerifier::MAX_JWS_BYTES);
        // The largest genuine base64 receipt in the corpus is ~106 KB.
        self::assertGreaterThan(8 * 106000, VerifyReceiptEndpoint::MAX_REQUEST_BYTES);
        // The largest genuine receipt retains ~967 KB of parser state.
        self::assertGreaterThan(16 * 967000, Der::DEFAULT_BYTE_BUDGET);
    }
}
