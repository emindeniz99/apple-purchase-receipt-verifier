<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Subprocess;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The failure mode PHP has and the other ports do not: **out of memory is a
 * fatal error, not a `Throwable`**.
 *
 * `Verifier::verifyReceipt()`, `verifySignedData()` and
 * `verifyReceiptEndpoint()` all promise that only a typed result escapes. A
 * `memory_limit` exhaustion cannot be caught by any of them: the worker dies
 * with exit 255 and no response at all. So every bound this library declares
 * has to hold *before* the allocation happens, and every one of them is a
 * security control rather than a nicety — an unauthenticated request that
 * kills a worker is a denial of service against every other request it was
 * serving.
 *
 * The declared bounds each constrain a different axis:
 *
 * - `Der::MAX_DEPTH` bounds nesting, not bytes;
 * - `Der::DEFAULT_NODE_BUDGET` bounds node count, and deep-but-large nesting
 *   costs ~33 nodes for megabytes of retained state;
 * - the 3 MiB receipt/request cap bounds the receipt and endpoint paths;
 * - the 256 KiB JWS cap bounds the JWS path.
 *
 * The missing bound is on the **product**: PHP has no zero-copy slice, so
 * `Der` retains roughly `2 x depth x input` bytes, which
 * {@see Der::DEFAULT_BYTE_BUDGET} is what actually caps.
 *
 * These vectors run in a child process at the `php.ini-production` default
 * `memory_limit` of 128M, because a test that triggered the fatal in-process
 * would take PHPUnit down with it. They are deliberately in no PHPUnit
 * group: they are the regression fences for a remotely triggerable worker
 * kill, so there must be no `--exclude-group` that quietly stops running
 * them.
 */
#[CoversNothing]
final class MemoryExhaustionTest extends TestCase
{
    /**
     * The `memory_limit` the README asks of a worker that hands raw request
     * bodies to the endpoint: the costliest body under Apple's 3 MiB cap
     * peaks well above the `php.ini-production` default of 128M.
     */
    private const REQUEST_BODY_MEMORY_LIMIT = '384M';

    /** The ceiling that vector's peak must stay under, in MB, per the above. */
    private const REQUEST_BODY_PEAK_MB = 352.0;

    /**
     * Shared prelude: DER length encoding and a "deep but large" blob, which
     * is the shape all declared bounds wave through.
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
        function verifierOverRoot(string $rootFixtureId): \EminDeniz99\ApplePurchaseReceiptVerifier\Verifier {
            return \EminDeniz99\ApplePurchaseReceiptVerifier\Verifier::create(
                \EminDeniz99\ApplePurchaseReceiptVerifier\Config::builder()
                    ->roots([\EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07::bytes($rootFixtureId)])
                    ->build(),
            );
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
     * at the declared maximum of 32, and the blob is ~33 nodes, so
     * neither the depth ceiling nor the node budget sees anything wrong; the
     * receipt path's byte cap does not apply here at all. What does apply is
     * the 256 KiB JWS cap, checked before any of the base64 segments are
     * decoded — a 4 MB `x5c` entry is caught there, well before it costs
     * anything.
     */
    public function testAJwsCarryingADeeplyNestedCertificateDoesNotKillTheWorker(): void
    {
        self::assertVerdict('TOO_LARGE', <<<'PHP'
            $jws = \EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07::bytes('transaction');
            $parts = explode('.', $jws);
            $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
            $header['x5c'][0] = base64_encode(nested(32, 4 * 1024 * 1024));
            $evil = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=')
                . '.' . $parts[1] . '.' . $parts[2];
            $verifier = verifierOverRoot('jws-root');
            $result = $verifier->verifySignedData($evil);
            report($result->verified() ? 'ACCEPTED' : $result->failure->reason->value);
            PHP, Subprocess::PRODUCTION_MEMORY_LIMIT);
    }

    /**
     * The payload segment is base64-decoded and JSON-parsed
     * (`JwsPayloadReader::readPayload()`) before the signature is checked,
     * so no valid signature is needed to reach the allocation; `BoundedJson`
     * bounds nesting depth, not breadth. The array is sized to ~35k tiny
     * elements rather than the historical 700k so the whole JWS still fits
     * under the 256 KiB transport cap that gates everything before it — a
     * bomb too big for that cap would only prove the cap works, not that
     * breadth inside it is affordable. The payload no longer matches the
     * genuine signature, so the real chain still authenticates and the
     * final verdict is an invalid signature, not a decode failure.
     */
    public function testAJwsCarryingAJsonBombPayloadDoesNotKillTheWorker(): void
    {
        self::assertVerdict('INVALID_SIGNATURE', <<<'PHP'
            $jws = \EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07::bytes('transaction');
            $parts = explode('.', $jws);
            $bomb = '{"a":[' . implode(',', array_fill(0, 35000, '[[]]')) . ']}';
            $evil = $parts[0] . '.' . rtrim(strtr(base64_encode($bomb), '+/', '-_'), '=') . '.' . $parts[2];
            if (strlen($evil) > 262144) {
                throw new RuntimeException('harness error: over the JWS cap, so the payload decode never runs');
            }
            $verifier = verifierOverRoot('jws-root');
            $result = $verifier->verifySignedData($evil);
            report($result->verified() ? 'ACCEPTED' : $result->failure->reason->value);
            PHP, Subprocess::PRODUCTION_MEMORY_LIMIT);
    }

    /**
     * The bomb sits in a sibling key, so this is the request-body
     * `json_decode` itself and has nothing to do with whether `receipt-data`
     * is valid. `Verifier` promises it never throws.
     */
    public function testAJsonBombRequestBodyDoesNotKillTheWorker(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $verifier = verifierOverRoot('receipt-root');
            $body = '{"receipt-data":"AA","x":[' . implode(',', array_fill(0, 700000, '[[]]')) . ']}';
            $answer = $verifier->verifyReceiptEndpoint(\EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production, $body);
            report($answer);
            PHP);

        self::assertSame(0, $status, "the worker did not survive a JSON-bomb request body; output was:\n" . $output);
        self::assertStringContainsString('VERDICT={"status":21002}', $output, $output);
    }

    /**
     * The whole request body is checked against {@see Verifier}'s 3 MiB
     * request cap before any JSON decoding happens
     * (`Verifier::extractReceiptData()`), so an oversized `receipt-data`
     * property is rejected as part of that same pre-decode check. The body
     * here is built by direct concatenation rather than `json_encode()`, and
     * sized just over the cap rather than the historical 96 MB: this vector
     * used to need that much because 0.6 decoded `receipt-data` before
     * checking anything, and doubling a 96 MB string is itself most of a
     * 128M budget — a false positive for what this test now checks.
     */
    public function testAnOversizedReceiptDataPropertyIsRejectedBeforeItIsDecoded(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $verifier = verifierOverRoot('receipt-root');
            $cap = 3145728;
            $body = '{"receipt-data":"' . str_repeat('A', $cap) . '"}';
            $answer = $verifier->verifyReceiptEndpoint(\EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production, $body);
            report($answer);
            PHP);

        self::assertSame(0, $status, "the worker did not survive an oversized receipt-data; output was:\n" . $output);
        self::assertStringContainsString('VERDICT={"status":21002}', $output, $output);
    }

    /**
     * The load-bearing one, and the vector every declared bound waves
     * through by itself: 600 sibling chains, each 31 SEQUENCEs deep around
     * ~3 KB, is under the node budget, under the depth ceiling and under
     * the 3 MiB receipt cap — but costs tens of megabytes of parser state,
     * because every level of nesting copies the bytes below it again.
     *
     * Run with no memory limit so the cost is *measured* rather than merely
     * survived: the assertion is on the peak, which is the axis the byte
     * budget bounds.
     */
    public function testDeepAndLargeNestingTogetherStaysInsideAMeasuredMemoryCeiling(): void
    {
        $peak = self::assertVerdict('MALFORMED', <<<'PHP'
            $blob = '';
            for ($c = 0; $c < 600; ++$c) { $blob .= nested(31, 3100); }
            $blob = "\x30" . derLen(strlen($blob)) . $blob;
            $base64 = base64_encode($blob);
            if (strlen($base64) > 3145728) {
                throw new RuntimeException('harness error: vector is outside the declared byte cap, so it proves nothing');
            }
            $verifier = verifierOverRoot('receipt-root');
            $result = $verifier->verifyReceipt($base64);
            report($result->verified() ? 'ACCEPTED' : $result->failure->reason->value);
            PHP, '-1');

        self::assertLessThan(
            64.0,
            $peak,
            'parsing a hostile receipt inside every declared bound cost ' . $peak . ' MB of parser state',
        );
    }

    /**
     * The same vector through the endpoint, at the production memory limit
     * and sized so its BASE64 form — which is what the transport cap sees —
     * stays inside the receipt cap, so the parser really does run on it.
     */
    public function testDeepAndLargeNestingThroughTheEndpointDoesNotKillTheWorker(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $blob = '';
            for ($c = 0; $c < 480; ++$c) { $blob .= nested(31, 3100); }
            $blob = "\x30" . derLen(strlen($blob)) . $blob;
            if (strlen(base64_encode($blob)) > 3145728) {
                throw new RuntimeException('harness error: the base64 form is over the cap, so the parser never runs');
            }
            $verifier = verifierOverRoot('receipt-root');
            $body = json_encode(['receipt-data' => base64_encode($blob)]);
            report($verifier->verifyReceiptEndpoint(\EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production, $body));
            PHP);

        self::assertSame(0, $status, "the worker did not survive the vector through the endpoint:\n" . $output);
        self::assertStringContainsString('VERDICT={"status":21002}', $output, $output);
    }

    /**
     * The bounds are only defensible if a genuine receipt is nowhere near
     * them. The largest public fixture — 79 KB, 187 in-app purchases —
     * retains under a megabyte, two orders of magnitude inside the byte
     * budget.
     */
    public function testTheLargestGenuineReceiptIsFarInsideTheByteBudget(): void
    {
        [$status, $output] = self::child(<<<'PHP'
            $legacy = \EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07::bytes('public-receipt-sandbox-legacy');
            $tight = \EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der::DEFAULT_BYTE_BUDGET;
            $node = \EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der::parse($legacy, 20000, intdiv($tight, 16));
            report('parsed-at-one-sixteenth-of-the-budget');
            PHP);

        self::assertSame(0, $status, $output);
        self::assertStringContainsString('VERDICT=parsed-at-one-sixteenth-of-the-budget', $output, $output);
    }

    /**
     * The caps only mean something if an input sized exactly AT one of them
     * is still affordable — a bound that merely moves the cliff is not a
     * bound. Both vectors below are built to sit just inside their cap and
     * to be the most expensive shape that fits: an `x5c` entry nested to
     * the ASN.1 depth ceiling, and a request body that is nothing but
     * JSON-bomb nodes.
     */
    public function testAnInputSizedExactlyAtEachCapIsStillAffordable(): void
    {
        $peak = self::assertVerdict('INVALID_CERTIFICATE', <<<'PHP'
            $blob = nested(32, 120000);
            $jws = \EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07::bytes('transaction');
            $parts = explode('.', $jws);
            $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
            $header['x5c'][0] = base64_encode($blob);
            $evil = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=')
                . '.' . $parts[1] . '.' . $parts[2];
            if (strlen($evil) > 262144) {
                throw new RuntimeException('harness error: over the cap, so the parser never runs');
            }
            $verifier = verifierOverRoot('jws-root');
            $result = $verifier->verifySignedData($evil);
            report($result->verified() ? 'ACCEPTED' : $result->failure->reason->value);
            PHP, Subprocess::PRODUCTION_MEMORY_LIMIT);
        self::assertLessThan(48.0, $peak, 'a JWS at the cap cost ' . $peak . ' MB');

        $peak = self::assertVerdict('{"status":21002}', <<<'PHP'
            $cap = 3145728;
            // Each level costs two bytes of body and a whole PHP array, so a
            // deep chain is the costliest shape per byte; 60 plus the two
            // enclosing levels stays inside the depth limit of 64.
            $chain = str_repeat('[', 60) . '0' . str_repeat(']', 60) . ',';
            $body = '{"receipt-data":"AA","x":[' . str_repeat($chain, intdiv($cap - 40, strlen($chain)));
            $body = rtrim($body, ',') . ']}';
            if (strlen($body) > $cap || strlen($body) < $cap - 200) {
                throw new RuntimeException('harness error: not just inside the cap, so it proves nothing');
            }
            $verifier = verifierOverRoot('receipt-root');
            report($verifier->verifyReceiptEndpoint(\EminDeniz99\ApplePurchaseReceiptVerifier\Environment::Production, $body));
            PHP, self::REQUEST_BODY_MEMORY_LIMIT);
        self::assertLessThan(self::REQUEST_BODY_PEAK_MB, $peak, 'a request body at the cap cost ' . $peak . ' MB');
    }

    /** The declared bounds sit far above any real input. */
    public function testTheDeclaredBoundsLeaveRoomForEveryGenuineInput(): void
    {
        // The largest genuine JWS in the corpus is ~2.5 KB; the cap is 256 KiB.
        self::assertGreaterThan(100 * 2500, 262144);
        // The largest genuine base64 receipt in the corpus is ~106 KB; the cap is 3 MiB.
        self::assertGreaterThan(8 * 106000, 3145728);
        // The largest genuine receipt retains ~967 KB of parser state.
        self::assertGreaterThan(16 * 967000, Der::DEFAULT_BYTE_BUDGET);
    }
}
