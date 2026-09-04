<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * A mutation pass over the genuine, Apple-signed corpus: every truncation and
 * every single-byte flip of a real receipt or JWS, through every public entry
 * point.
 *
 * Two properties are asserted, and deliberately not the reasons — a mutation
 * can legitimately land in different fields, and pinning the reason would make
 * this a change-detector instead of a safety net.
 *
 * 1. **Nothing but `VerificationException` escapes.** Not a `TypeError`, not
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
 * that, byte for byte, instead of assuming it. Measured on this corpus:
 * of 1,506 receipt mutations, 13 are accepted and all 13 return the identical
 * receipt.
 *
 * The strides were chosen against measured cost: the 79 KB legacy receipt
 * costs an RSA check per attempt, so it gets a coarser one than the 5.6 KB
 * G5 receipt.
 */
#[CoversNothing]
#[Group('mutation')]
final class MutationTest extends TestCase
{
    private const TRUNCATION_STRIDE = 64;

    public function testNoReceiptMutationEverProducesADifferentVerifiedReceipt(): void
    {
        $corpora = [
            'g5 sandbox receipt' => [Fixtures::bytes('public-receipt-sandbox-g5'), 'dev.bonzer.weeka.app', 97],
            'legacy sha-1 receipt' => [Fixtures::bytes('public-receipt-sandbox-legacy'), 'com.nutcall.alert', 997],
            'xcode receipt' => [Fixtures::bytes('public-receipt-xcode-with-purchases'), 'com.example.app', 397],
        ];

        $checked = 0;
        $accepted = 0;
        foreach ($corpora as $label => [$genuine, $bundleId, $flipStride]) {
            $verifier = new ReceiptVerifier(AppleRootCerts::receiptRoots(), $bundleId);
            $endpoint = new VerifyReceiptEndpoint(AppleRootCerts::receiptRoots(), Environment::Sandbox);

            // The genuine verdict, whatever it is: the Xcode receipt is not
            // Apple-signed and is rejected outright, and a mutation of it must
            // stay rejected.
            $expected = null;
            try {
                $expected = $verifier->verify($genuine);
            } catch (VerificationException) {
                $expected = null;
            }

            foreach (self::mutations($genuine, $flipStride) as $what => $mutated) {
                ++$checked;
                try {
                    $result = $verifier->verify($mutated);
                    ++$accepted;
                    self::assertNotNull($expected, "{$label}: {$what} was accepted, but the genuine input is not");
                    self::assertEquals(
                        $expected,
                        $result,
                        "{$label}: {$what} verified to a DIFFERENT receipt — that is a forgery",
                    );
                } catch (VerificationException) {
                    // rejected: the common and expected outcome
                } catch (Throwable $e) {
                    self::fail("{$label}: {$what} escaped as " . $e::class . ': ' . $e->getMessage());
                }

                // The endpoint promises never to throw, and 21009 would mean
                // it hit something it did not expect.
                $status = $endpoint->verifyReceipt(['receipt-data' => base64_encode($mutated)])['status'];
                self::assertNotSame(21009, $status, "{$label}: {$what} reached the endpoint's internal error");
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
            'shared transaction' => ['transaction', 'jws-root', 'com.example.app'],
            'shared app transaction' => ['app-transaction', 'jws-root', 'com.example.app'],
            'apple official transaction info' => ['apple-transaction-info', 'apple-test-ca', 'com.example'],
            'apple official renewal info' => ['apple-renewal-info', 'apple-test-ca', 'com.example'],
        ];

        $checked = 0;
        foreach ($corpora as $label => [$fixture, $rootFixture, $bundleId]) {
            $genuine = Fixtures::bytes($fixture);
            $verifier = new JwsVerifier(
                [Fixtures::bytes($rootFixture)],
                $bundleId,
                [Environment::Sandbox, Environment::Production],
                123456789,
            );

            foreach (['verifyTransaction', 'verifyAppTransaction', 'verifyRaw'] as $operation) {
                $expected = null;
                try {
                    $expected = $verifier->{$operation}($genuine);
                } catch (VerificationException) {
                    $expected = null;
                }

                foreach (self::mutations($genuine, 37) as $what => $mutated) {
                    ++$checked;
                    try {
                        $result = $verifier->{$operation}($mutated);
                        self::assertNotNull(
                            $expected,
                            "{$label}/{$operation}: {$what} was accepted, but the genuine input is not",
                        );
                        self::assertEquals(
                            $expected,
                            $result,
                            "{$label}/{$operation}: {$what} verified to DIFFERENT claims — that is a forgery",
                        );
                    } catch (VerificationException) {
                        // rejected: the common and expected outcome
                    } catch (Throwable $e) {
                        self::fail(
                            "{$label}/{$operation}: {$what} escaped as " . $e::class . ': ' . $e->getMessage(),
                        );
                    }
                }
            }
        }

        self::assertGreaterThan(900, $checked, 'the mutation corpus collapsed');
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
