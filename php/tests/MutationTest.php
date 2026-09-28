<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * A mutation pass over the genuine, Apple-signed corpus: every truncation and
 * every single-byte flip of a real receipt or JWS, through the public entry
 * points.
 *
 * Two properties are asserted, and deliberately not the reason — a mutation
 * can legitimately land in different fields, and pinning the reason would
 * make this a change-detector instead of a safety net.
 *
 * 1. **Nothing escapes as an unhandled `Throwable`.** Not a `TypeError`, not
 *    an `Error`, not a warning (`phpunit.xml` fails the run on those too).
 * 2. **No mutation ever produces a DIFFERENT accepted result.** A mutated
 *    input is either rejected, or it verifies to exactly what the genuine
 *    input verifies to.
 *
 * The second property is the anti-forgery one, and it is stated that way
 * rather than as "nothing mutated is ever accepted" because the looser claim
 * is false for every implementation of this format, in a way that is not a
 * defect: a genuine receipt embeds certificates the chain walk never reaches
 * (the third one is a root, and anchors come from the caller), and the CMS
 * signature covers the encapsulated content rather than the envelope. A flip
 * there changes nothing an attacker can use — and the assertion below proves
 * that, byte for byte, instead of assuming it.
 */
#[CoversNothing]
#[Group('mutation')]
final class MutationTest extends TestCase
{
    private const TRUNCATION_STRIDE = 64;

    public function testNoReceiptMutationEverProducesADifferentVerifiedReceipt(): void
    {
        $corpora = [
            'g5 sandbox receipt' => ['public-receipt-sandbox-g5', 97],
            'legacy sha-1 receipt' => ['public-receipt-sandbox-legacy', 997],
            'xcode receipt' => ['public-receipt-xcode-with-purchases', 397],
        ];

        $checked = 0;
        $accepted = 0;
        foreach ($corpora as $label => [$fixtureId, $flipStride]) {
            $genuineDer = self::genuineReceiptBytes($fixtureId);
            $verifier = Verifier::create(Config::builder()->roots(AppleRootCerts::pinnedRoots())->build());

            // The genuine verdict, whatever it is: the Xcode receipt is not
            // Apple-signed and is rejected outright, and a mutation of it
            // must stay rejected.
            $genuineResult = $verifier->verifyReceipt(base64_encode($genuineDer));
            $expected = $genuineResult->verified() ? $genuineResult->payload : null;

            foreach (self::mutations($genuineDer, $flipStride) as $what => $mutated) {
                ++$checked;
                try {
                    $result = $verifier->verifyReceipt(base64_encode($mutated));
                } catch (Throwable $e) {
                    self::fail("{$label}: {$what} escaped as " . $e::class . ': ' . $e->getMessage());
                }
                if ($result->verified()) {
                    ++$accepted;
                    self::assertNotNull($expected, "{$label}: {$what} was accepted, but the genuine input is not");
                    self::assertEquals(
                        $expected,
                        $result->payload,
                        "{$label}: {$what} verified to a DIFFERENT receipt — that is a forgery",
                    );
                }

                // The endpoint promises never to throw, and 21009 would mean
                // it hit something it did not expect.
                $requestJson = json_encode(
                    ['receipt-data' => base64_encode($mutated)],
                    JSON_THROW_ON_ERROR,
                );
                try {
                    $response = $verifier->verifyReceiptEndpoint(Environment::Sandbox, $requestJson);
                } catch (Throwable $e) {
                    self::fail("{$label}: {$what} escaped the endpoint as " . $e::class . ': ' . $e->getMessage());
                }
                /** @var array{status: int} $decoded */
                $decoded = json_decode($response, true, 8, JSON_THROW_ON_ERROR);
                self::assertNotSame(21009, $decoded['status'], "{$label}: {$what} reached the endpoint's internal error");
            }
        }

        self::assertGreaterThan(1400, $checked, 'the mutation corpus collapsed');
        self::assertLessThan(
            (int) ($checked / 4),
            $accepted,
            'most mutations should be rejected outright; this many acceptances '
            . 'means the corpus is not landing on signed bytes',
        );
    }

    public function testNoJwsMutationEverProducesDifferentVerifiedClaims(): void
    {
        $corpora = [
            'shared transaction' => ['transaction', 'jws-root'],
            'shared app transaction' => ['app-transaction', 'jws-root'],
            'apple official transaction info' => ['apple-transaction-info', 'apple-test-ca'],
            'apple official renewal info' => ['apple-renewal-info', 'apple-test-ca'],
        ];

        $checked = 0;
        foreach ($corpora as $label => [$fixtureId, $rootFixtureId]) {
            $genuine = Fixtures07::bytes($fixtureId);
            $root = self::rootBytes($rootFixtureId);
            $verifier = Verifier::create(Config::builder()->roots([$root])->build());

            $genuineResult = $verifier->verifySignedData($genuine);
            $expected = $genuineResult->verified() ? $genuineResult->payload->json : null;

            foreach (self::mutations($genuine, 37) as $what => $mutated) {
                ++$checked;
                try {
                    $result = $verifier->verifySignedData($mutated);
                } catch (Throwable $e) {
                    self::fail("{$label}: {$what} escaped as " . $e::class . ': ' . $e->getMessage());
                }
                if ($result->verified()) {
                    self::assertNotNull($expected, "{$label}: {$what} was accepted, but the genuine input is not");
                    self::assertSame(
                        $expected,
                        $result->payload->json,
                        "{$label}: {$what} verified to DIFFERENT claims — that is a forgery",
                    );
                }
            }
        }

        self::assertGreaterThan(300, $checked, 'the mutation corpus collapsed');
    }

    private static function genuineReceiptBytes(string $fixtureId): string
    {
        $entry = Fixtures07::registry()[$fixtureId] ?? null;
        self::assertNotNull($entry, "harness error: fixture {$fixtureId} is not registered in cases.json");

        return Fixtures07::bytes($fixtureId);
    }

    private static function rootBytes(string $fixtureId): string
    {
        return Fixtures07::bytes($fixtureId);
    }

    /**
     * @return iterable<string, string>
     */
    private static function mutations(string $genuine, int $flipStride): iterable
    {
        $length = strlen($genuine);
        for ($cut = 1; $cut < $length; $cut += self::TRUNCATION_STRIDE) {
            yield "truncated to {$cut} bytes" => substr($genuine, 0, $cut);
        }
        for ($at = 0; $at < $length; $at += $flipStride) {
            $flipped = $genuine;
            $flipped[$at] = chr(ord($genuine[$at]) ^ 0xff);
            yield "byte {$at} flipped" => $flipped;
        }
        yield 'one trailing byte' => $genuine . "\x00";
        yield 'one leading byte' => "\x00" . $genuine;
        yield 'doubled' => $genuine . $genuine;
    }
}
