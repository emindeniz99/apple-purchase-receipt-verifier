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
        yield 'overpadded (receipt-base64/reject-overpadded: canonical "==" plus two extra "=")' => ['QUJDQQ===='];
        yield 'underpadded (receipt-base64/reject-underpadded: one of two required "=" removed)' => ['QUJDQQ='];
        yield 'impossible data length hidden by padding (receipt-base64/reject-impossible-length-padded: 5 data chars + "===" is 8 in total)' => ['QUJDQ==='];
        yield 'padding only' => ['===='];
    }

    #[DataProvider('invalidReceiptBase64Provider')]
    public function testDecodeReceiptRejectsWhatApplesContractRejects(string $text): void
    {
        self::assertNull(Base64::decodeReceipt($text));
    }

    /**
     * decodeReceipt() answers from `base64_decode($s, true)` when that
     * accepts, and from the tolerant path otherwise. That is only a speed-up
     * if the strict decoder accepts a SUBSET of what the tolerant path
     * accepts, with the same bytes: otherwise a client's receipt would start
     * verifying (or stop) because of an optimisation. PHP's "strict" mode is
     * not strict about everything: it skips whitespace and returns '' for a
     * blank string. So this compares the two paths directly, on seeded
     * random inputs built to sit on the edges (whitespace in and around the
     * padding, base64url, junk bytes, every padding count, lengths across
     * the 32- and 64-character SIMD blocks), and asserts every branch was
     * reached so the corpus cannot quietly go blind.
     */
    public function testTheStrictFastPathAgreesWithTheTolerantPathOnEveryInput(): void
    {
        $inputs = self::edgeCaseInputs();
        mt_srand(20260922);
        while (count($inputs) < 20000 + 60) {
            $inputs[] = self::randomReceiptText();
        }

        $fastAccepted = 0;
        $tolerantOnly = 0;
        $rejected = 0;
        $lenientDisagrees = 0;
        foreach ($inputs as $text) {
            $expected = Base64::decodeReceiptTolerant($text);
            $label = bin2hex($text);
            self::assertSame($expected, Base64::decodeReceipt($text), $label);

            $strict = base64_decode($text, true);
            if ($strict !== false && $strict !== '') {
                self::assertSame($expected, $strict, "strict accepted what the tolerant path does not: {$label}");
                ++$fastAccepted;
            } elseif ($expected !== null) {
                ++$tolerantOnly;
            } else {
                ++$rejected;
            }
            // The corpus has teeth: a permissive decoder in the fast path
            // would disagree with the tolerant path on some of it.
            if (base64_decode($text) !== ($expected ?? false)) {
                ++$lenientDisagrees;
            }
        }

        self::assertGreaterThan(1000, $fastAccepted, 'the fast path was barely exercised');
        self::assertGreaterThan(1000, $tolerantOnly, 'the tolerant-only branch was barely exercised');
        self::assertGreaterThan(1000, $rejected, 'the rejection branch was barely exercised');
        self::assertGreaterThan(1000, $lenientDisagrees, 'the corpus cannot tell a lenient decoder apart');
    }

    /** @return list<string> */
    private static function edgeCaseInputs(): array
    {
        $block = str_repeat('QUJD', 16); // 64 characters, one AVX-512 block
        return [
            '', ' ', " \t\r\n", "\v", "\f", '=', '==', '===', '====',
            'A', 'AA', 'AAA', 'AAAA', 'AA=', 'AA==', 'AAA=', 'AAA==', 'AAAA=', 'AAAA==', 'A=', 'A==', 'A===',
            'AA==AA', 'AA=A', "AA=\n=", 'AA= =', "AA=\t=", "AA=\v=", "AA==\n", "\nAA==", "AA==\0",
            "\vQUJD", "QUJD\f", "QU\x00JD", "QUJD\x80", 'QUJD.', 'QUJD====', 'QUJDRA===',
            '-_-_', '+/+/', '+/-_', 'LV5f', 'LV5fXQ', 'LV5fXQ==', 'LV5fXQ=',
            $block, $block . '=', $block . 'QQ', $block . 'QQ==', $block . 'QQ=', $block . 'Q',
            substr($block, 0, 63) . ' ' . substr($block, 63), substr($block, 0, 32) . "\n" . substr($block, 32),
            substr($block, 0, 31) . '-' . substr($block, 32), $block . $block . "\r\n",
            substr($block, 0, 40) . '=' . substr($block, 40),
            str_repeat("QUJD\n", 40), str_repeat('QUJD', 40) . '=', chunk_split(str_repeat('QUJD', 50), 76, "\r\n"),
        ];
    }

    /**
     * A mix of valid encodings (standard or base64url, padded or not, with
     * or without whitespace) and single mutations of them, plus short random
     * strings over an alphabet dense in the characters that matter.
     */
    private static function randomReceiptText(): string
    {
        $bytes = '';
        for ($i = 0, $n = mt_rand(0, 200); $i < $n; ++$i) {
            $bytes .= chr(mt_rand(0, 255));
        }
        $text = base64_encode($bytes);
        if (mt_rand(0, 3) === 0) {
            $text = rtrim($text, '=');
        }
        if (mt_rand(0, 4) === 0) {
            $text = strtr($text, '+/', '-_');
        }
        $pool = ['A', 'Q', 'z', '0', '+', '/', '-', '_', '=', '=', ' ', "\t", "\r", "\n", "\v", "\f", "\0", '!', '.', "\x80", "\xff"];
        switch (mt_rand(0, 7)) {
            case 0: // insert whitespace, possibly several times
                for ($k = mt_rand(1, 4); $k > 0; --$k) {
                    $at = mt_rand(0, strlen($text));
                    $text = substr($text, 0, $at) . [' ', "\t", "\r", "\n", "\r\n"][mt_rand(0, 4)] . substr($text, $at);
                }
                break;
            case 1: // replace one character
                if ($text !== '') {
                    $at = mt_rand(0, strlen($text) - 1);
                    $text[$at] = $pool[mt_rand(0, count($pool) - 1)];
                }
                break;
            case 2: // insert one character
                $at = mt_rand(0, strlen($text));
                $text = substr($text, 0, $at) . $pool[mt_rand(0, count($pool) - 1)] . substr($text, $at);
                break;
            case 3: // delete one character
                if ($text !== '') {
                    $at = mt_rand(0, strlen($text) - 1);
                    $text = substr($text, 0, $at) . substr($text, $at + 1);
                }
                break;
            case 4: // change the padding
                $text = rtrim($text, '=') . str_repeat('=', mt_rand(0, 4));
                break;
            case 5: // short random string
                $text = '';
                for ($k = mt_rand(0, 10); $k > 0; --$k) {
                    $text .= $pool[mt_rand(0, count($pool) - 1)];
                }
                break;
            default: // leave it valid
                break;
        }

        return $text;
    }
}
