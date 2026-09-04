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
 * The decoder's leniency, pinned — including the part the shipped ports do not
 * agree about.
 *
 * This reader skips any byte outside both base64 alphabets, exactly as
 * `node/src/bytes.ts` and `Buffer.from(s, 'base64url')` do. Python's
 * `urlsafe_b64decode(seg + '=' * (-len(seg) % 4))` computes its padding from
 * the RAW length, so a single non-alphabet byte on a segment of length ≡ 2 mod
 * 4 makes the padding wrong and raises; Java's `Base64.getUrlDecoder()`
 * rejects out-of-alphabet bytes outright, and rejects a lone `=` there too.
 * There is no answer that matches all four ports, so this one follows the
 * reader it was ported from — and these tests exist so that stays a decision
 * rather than an accident.
 *
 * `decode()`'s leniency now applies only to `x5c` entries and legacy receipt
 * base64 — the compact-JWS header, payload and signature segments go through
 * {@see Base64::decodeStrict()} instead, pinned by
 * {@see testCompactJwsSegmentsRejectWhatDecodeWouldHaveTolerated} below.
 */
#[CoversClass(Base64::class)]
final class Base64Test extends TestCase
{
    /** @return iterable<string, array{string, string}> */
    public static function alphabetProvider(): iterable
    {
        yield 'standard alphabet' => ['+/++//', "\xfb\xff\xbe\xff"];
        yield 'url-safe alphabet' => ['-_--__', "\xfb\xff\xbe\xff"];
        yield 'padded' => ['QUJD', 'ABC'];
        yield 'unpadded, as a JWS segment carries it' => ['QUJDRA', 'ABCD'];
        yield 'PEM-style line breaks' => ["QUJD\nRA==", 'ABCD'];
    }

    #[DataProvider('alphabetProvider')]
    public function testBothAlphabetsAndTheFormsAJwsAndAPemActuallyCarry(string $text, string $expected): void
    {
        self::assertSame($expected, Base64::decode($text));
    }

    /**
     * A trailing byte outside the alphabet is skipped, so it changes nothing
     * about the decoded value. Deliberate, and divergent from Python and Java.
     *
     * @return iterable<string, array{string}>
     */
    public static function ignoredByteProvider(): iterable
    {
        yield 'NUL' => ["\x00"];
        yield 'space' => [' '];
        yield 'padding' => ['='];
        yield 'double padding' => ['=='];
        yield 'punctuation' => ['!'];
        yield 'a run of punctuation' => [str_repeat('!', 100)];
    }

    #[DataProvider('ignoredByteProvider')]
    public function testBytesOutsideBothAlphabetsAreSkippedWhereverTheyAppear(string $garbage): void
    {
        self::assertSame('ABCD', Base64::decode('QUJDRA' . $garbage));
        self::assertSame('ABCD', Base64::decode('QUJ' . $garbage . 'DRA'));
    }

    /** A byte INSIDE the alphabet is data, so it does change the value. */
    public function testAnInAlphabetByteIsDataAndNotGarbage(): void
    {
        self::assertNotSame('ABCD', Base64::decode('QUJDRAA'));
        self::assertSame(5, strlen(Base64::decode('QUJDRAA')), 'six more bits is a fifth byte');
    }

    /**
     * The three compact-JWS segments (RFC 7515 §2) reject exactly what
     * `decode()` above would have tolerated — a trailing out-of-alphabet
     * byte skipped rather than rejected. None of the three is malleable any
     * more: garbage appended to the signature segment used to decode-and-
     * ignore its way to an accepted claim (the divergence
     * `testBytesOutsideBothAlphabetsAreSkippedWhereverTheyAppear` above still
     * pins for the shared, unrelated `decode()` callers); now every one of
     * the three segments fails closed with `INVALID_JWS_FORMAT`, matching
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
     * {@see Base64::decodeReceipt()} is a third rule, distinct from both
     * `decode()`'s skip-and-ignore leniency above and `decodeStrict()`'s
     * canonical-unpadded rule: Apple's own contract for what
     * `base64EncodedString(options:)` can emit, pinned in
     * `fixtures/cases.json`'s "Receipt base64" paragraph and exercised
     * end-to-end by the `receipt-base64/*` and `endpoint/receipt-data-*`
     * conformance cases. These tests pin the decoder function directly.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function validReceiptBase64Provider(): iterable
    {
        yield 'standard alphabet, padded' => ['QUJD', 'ABC'];
        yield 'standard alphabet, unpadded' => ['QUJDRA', 'ABCD'];
        yield 'base64url alphabet, padded' => ['LV5f', "\x2d\x5e\x5f"];
        yield 'base64url alphabet, unpadded' => ['LV5fXQ', "\x2d\x5e\x5f\x5d"];
        yield 'CR, LF, space and tab anywhere' => ["QU\tJ\r\nD RA==", 'ABCD'];
        yield 'leading and trailing whitespace' => ["  QUJDRA==\n", 'ABCD'];
    }

    #[DataProvider('validReceiptBase64Provider')]
    public function testDecodeReceiptAcceptsApplesContract(string $text, string $expected): void
    {
        self::assertSame($expected, Base64::decodeReceipt($text));
    }

    /** @return iterable<string, array{string}> */
    public static function invalidReceiptBase64Provider(): iterable
    {
        yield 'empty' => [''];
        yield 'whitespace only' => [" \t\r\n"];
        yield 'a character outside both alphabets' => ['QUJD!'];
        yield 'text after the padding' => ['QUJDRA==XY'];
        yield 'both alphabets in one string' => ['ab+c-d'];
        yield 'impossible length (len % 4 == 1)' => ['QUJDR'];
    }

    #[DataProvider('invalidReceiptBase64Provider')]
    public function testDecodeReceiptRejectsWhatApplesContractRejects(string $text): void
    {
        self::assertNull(Base64::decodeReceipt($text));
    }
}
