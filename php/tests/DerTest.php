<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The DER/BER reader in isolation.
 *
 * Every input here is a shape an attacker controls, and every assertion is
 * about the reader refusing rather than coping. The bounds it enforces —
 * depth, node count, length encoding — are the only thing between hostile
 * bytes and a crashed FPM worker on PHP 8.1, which has no
 * `zend.max_allowed_stack_size` to catch a runaway recursion.
 */
#[CoversClass(Der::class)]
final class DerTest extends TestCase
{
    public function testParsesASimpleSequence(): void
    {
        $node = Der::parse(DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::int(1), DerWriter::int(2)));
        self::assertSame(Der::TAG_SEQUENCE, $node->tag);
        self::assertTrue($node->constructed);
        self::assertSame(2, $node->childCount());
        self::assertSame("\x01", $node->child(0)?->contents);
    }

    /**
     * Trailing bytes are an error rather than something to ignore: a CMS blob
     * with garbage appended is a different blob, and a reader that stops at
     * the first complete value would let an attacker append content that one
     * port reads and another does not.
     */
    public function testRejectsTrailingBytesAfterTheTopLevelValue(): void
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('/trailing bytes/');
        Der::parse(DerWriter::tlv(DerWriter::SEQUENCE) . "\x00");
    }

    /** @return iterable<string, array{string, string}> */
    public static function malformedProvider(): iterable
    {
        yield 'empty' => ['', 'truncated'];
        yield 'one byte' => ["\x30", 'truncated'];
        yield 'bare indefinite length' => ["\x30\x80", 'unterminated'];
        yield 'indefinite length on a primitive' => ["\x04\x80\x00\x00", 'indefinite length on a primitive'];
        yield 'multi-byte tag' => ["\x1f\x81\x00\x00", 'multi-byte'];
        yield 'length of five bytes' => ["\x30\x85\x00\x00\x00\x00\x01", 'unsupported ASN.1 length'];
        yield 'length beyond the buffer' => ["\x30\x0a\x00", 'length exceeds input'];
        yield 'long-form length beyond the buffer' => ["\x30\x82\xff\xff\x00", 'length exceeds input'];
        yield 'unterminated indefinite value' => ["\x30\x80\x02\x01\x01", 'unterminated'];
    }

    #[DataProvider('malformedProvider')]
    public function testRejectsMalformedInput(string $bytes, string $expected): void
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expected, '/') . '/');
        Der::parse($bytes);
    }

    public function testAcceptsIndefiniteLengthWhichGenuineXcodeReceiptsUse(): void
    {
        $node = Der::parse(DerWriter::indefinite(DerWriter::SEQUENCE, DerWriter::int(7)));
        self::assertSame(1, $node->childCount());
        self::assertSame("\x07", $node->child(0)?->contents);
    }

    public function testAcceptsNestingUpToTheDepthLimitAndRejectsOnePastIt(): void
    {
        self::assertSame(Der::TAG_SEQUENCE, Der::parse(self::nested(Der::MAX_DEPTH))->tag);

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('/nesting depth/');
        Der::parse(self::nested(Der::MAX_DEPTH + 2));
    }

    /**
     * The node budget is the PHP-specific bound. PHP has no zero-copy slice,
     * so a megabyte of minimal two-byte nodes costs tens of megabytes of
     * parser state against a default 128M limit. This asserts the budget
     * fires, and that the largest genuine receipt stays comfortably inside it.
     */
    public function testRejectsATreeLargerThanTheNodeBudget(): void
    {
        $many = DerWriter::tlv(DerWriter::SEQUENCE, str_repeat("\x05\x00", 200));

        self::assertSame(200, Der::parse($many, 500)->childCount());

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('/node budget/');
        Der::parse($many, 100);
    }

    public function testTheBudgetCountsTheWholeTreeNotJustTheTopLevel(): void
    {
        $inner = DerWriter::tlv(DerWriter::SEQUENCE, str_repeat("\x05\x00", 50));
        $outer = DerWriter::tlv(DerWriter::SEQUENCE, $inner, $inner);

        $this->expectException(ParseException::class);
        Der::parse($outer, 60);
    }

    public function testOctetsConcatenatesBerConstructedChunks(): void
    {
        $chunked = DerWriter::tlv(
            Der::TAG_OCTET_STRING_CONSTRUCTED,
            DerWriter::tlv(DerWriter::OCTET_STRING, 'abc'),
            DerWriter::tlv(DerWriter::OCTET_STRING, 'def'),
        );
        self::assertSame('abcdef', Der::octets(Der::parse($chunked)));
        self::assertTrue(Der::isOctetString(Der::parse($chunked)));
        self::assertTrue(Der::isOctetString(Der::parse(DerWriter::tlv(DerWriter::OCTET_STRING, 'x'))));
    }

    /** @return iterable<string, array{string, string}> */
    public static function oidProvider(): iterable
    {
        yield 'apple leaf marker' => ['1.2.840.113635.100.6.11.1', '2a864886f76364060b01'];
        yield 'apple wwdr marker' => ['1.2.840.113635.100.6.2.1', '2a864886f76364060201'];
        yield 'sha-1' => ['1.3.14.3.2.26', '2b0e03021a'];
        yield 'sha-256' => ['2.16.840.1.101.3.4.2.1', '608648016503040201'];
        yield 'signed data' => ['1.2.840.113549.1.7.2', '2a864886f70d010702'];
        yield 'basic constraints' => ['2.5.29.19', '551d13'];
    }

    /**
     * Marker-OID checks compare these bytes rather than a name a crypto
     * library chose, so the encoding has to be exactly right — and has to
     * round-trip, since the same OIDs are read back out of certificates.
     */
    #[DataProvider('oidProvider')]
    public function testOidEncodingRoundTrips(string $dotted, string $hex): void
    {
        self::assertSame($hex, bin2hex(Der::encodeOidContents($dotted)));
        self::assertSame($dotted, Der::decodeOid((string) hex2bin($hex)));
    }

    public function testRejectsATruncatedOid(): void
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('/truncated OBJECT IDENTIFIER/');
        Der::decodeOid("\x2a\x86");
    }

    public function testRejectsAnEmptyOid(): void
    {
        $this->expectException(ParseException::class);
        Der::decodeOid('');
    }

    private static function nested(int $depth): string
    {
        $node = DerWriter::int(1);
        for ($i = 0; $i < $depth; ++$i) {
            $node = DerWriter::tlv(DerWriter::SEQUENCE, $node);
        }

        return $node;
    }
}
