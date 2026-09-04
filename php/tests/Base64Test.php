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
 * The security argument for why the divergence is not exploitable is in
 * {@see testTrailingGarbageCannotChangeAVerifiedClaim}.
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
     * Why the leniency is not forgeable, which is the part that matters.
     *
     * An ES256 JWS signature covers the literal `header.payload` segment TEXT.
     * Garbage tolerated inside those two segments therefore changes the
     * signing input and breaks the signature; only the signature segment is
     * malleable, and rewriting it cannot change a claim. So the divergence
     * costs a byte-for-byte disagreement about which encodings are accepted,
     * never a disagreement about what a verified payload says.
     */
    public function testTrailingGarbageCannotChangeAVerifiedClaim(): void
    {
        $pki = MintedPki::get();
        $jws = $pki->jws(MintedPki::transactionClaims());
        $verifier = new JwsVerifier([$pki->rootDer], 'com.example.app', [Environment::Sandbox]);
        [$header, $payload, $signature] = explode('.', $jws);

        // Malleable: the signature segment tolerates it, and the claims are
        // the claims Apple signed, unchanged.
        self::assertSame(
            '2000000000000001',
            $verifier->verifyTransaction($header . '.' . $payload . '.' . $signature . "\x00")->transactionId,
        );

        // Not malleable: the same byte in a signed segment is skipped by the
        // decoder but still changes the signing input, so the check fails.
        foreach ([$header . "\x00" . '.' . $payload, $header . '.' . $payload . "\x00"] as $tampered) {
            try {
                $verifier->verifyTransaction($tampered . '.' . $signature);
                self::fail('a tampered signed segment was ACCEPTED');
            } catch (VerificationException $e) {
                self::assertSame(Reason::InvalidSignature, $e->reason);
            }
        }
    }
}
