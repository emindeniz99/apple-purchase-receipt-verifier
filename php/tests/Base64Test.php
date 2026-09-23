<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The two base64 rules, pinned where they differ from what PHP's own decoder
 * would do alone: compact-JWS segments ({@see Base64::decodeStrict()}) and
 * receipt-data and x5c entries ({@see Base64::decodeCanonical()}).
 *
 * The receipt-data and x5c spellings themselves are the decodeBase64 groups
 * of fixtures/cases.json, which ConformanceCasesTest runs against
 * decodeCanonical(); what stays here is why the check in front of
 * base64_decode() exists.
 */
#[CoversClass(Base64::class)]
final class Base64Test extends TestCase
{
    /**
     * The three compact-JWS segments (RFC 7515 §2) reject a trailing
     * out-of-alphabet byte rather than skipping it. None of the three is
     * malleable any more: garbage appended to the signature segment used to
     * decode-and-ignore its way to an accepted claim; now every one of the
     * three segments fails closed with `INVALID_JWS_FORMAT`, matching
     * `fixtures/cases.json`'s `transaction/reject-signature-segment-*`
     * vectors.
     */
    public function testCompactJwsSegmentsRejectWhatDecodeWouldHaveTolerated(): void
    {
        $pki = MintedPki::get();
        $jws = $pki->jws(MintedPki::transactionClaims());
        $verifier = new JwsVerifier([$pki->rootDer], 'com.example.app', [Environment::Sandbox]);
        [$header, $payload, $signature] = explode('.', $jws);

        // Sanity check: the genuine JWS still verifies untouched.
        self::assertSame(
            '2000000000000001',
            $verifier->verifyTransaction($header . '.' . $payload . '.' . $signature)->transactionId,
        );

        foreach ([
            'header' => $header . "\x00" . '.' . $payload . '.' . $signature,
            'payload' => $header . '.' . $payload . "\x00" . '.' . $signature,
            'signature' => $header . '.' . $payload . '.' . $signature . "\x00",
        ] as $what => $tampered) {
            try {
                $verifier->verifyTransaction($tampered);
                self::fail("a byte outside the base64url alphabet in the {$what} segment was ACCEPTED");
            } catch (VerificationException $e) {
                self::assertSame(Reason::InvalidJwsFormat, $e->reason, "{$what} segment");
            }
        }
    }

    /** @return iterable<string, array{string}> */
    public static function invalidCompactJwsSegmentProvider(): iterable
    {
        yield 'trailing junk' => ['QUJD' . "\x00"];
        yield 'padded' => ['QUJD=='];
        yield 'a lone equals' => ['='];
        yield 'impossible length (len % 4 == 1)' => ['QUJDR'];
        yield 'standard-alphabet + is not base64url' => ['+++++++='];
        // 'TR' decodes the same top byte as 'TQ' but its low 2 bits are '01'
        // rather than the canonical '00' — the noncanonical spelling this
        // pins is exactly what `fixtures/cases.json`'s
        // `transaction/reject-signature-segment-noncanonical` exercises.
        yield 'noncanonical final character' => ['TR'];
    }

    #[DataProvider('invalidCompactJwsSegmentProvider')]
    public function testDecodeStrictRejectsInvalidSegments(string $segment): void
    {
        self::assertNull(Base64::decodeStrict($segment));
    }

    /** @return iterable<string, array{string, string}> */
    public static function validCompactJwsSegmentProvider(): iterable
    {
        yield 'unpadded, as a JWS segment carries it' => ['QUJDRA', 'ABCD'];
        yield 'empty' => ['', ''];
        yield 'canonical final character' => ['TQ', "\x4d"];
    }

    #[DataProvider('validCompactJwsSegmentProvider')]
    public function testDecodeStrictAcceptsCanonicalSegments(string $segment, string $expected): void
    {
        self::assertSame($expected, Base64::decodeStrict($segment));
    }

    /**
     * Why the check in front exists: PHP's strict mode skips whitespace,
     * accepts omitted padding and decodes the empty string.
     */
    public function testBase64DecodeStrictModeAloneIsNotTheRule(): void
    {
        self::assertSame('ABC', base64_decode("QU JD\n", true));
        self::assertSame('A', base64_decode('QQ', true));
        self::assertSame('', base64_decode('', true));
    }
}
