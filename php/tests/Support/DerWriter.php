<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

/**
 * A minimal DER writer for the tests — definite lengths only, which is what a
 * forgery an attacker would actually build uses.
 *
 * Deliberately independent of `Internal\Der`: a bug that makes the reader
 * accept something it should not would otherwise be mirrored by a writer that
 * emits the same wrong shape, and the tests would agree with themselves.
 */
final class DerWriter
{
    public const BOOLEAN = 0x01;
    public const INTEGER = 0x02;
    public const BIT_STRING = 0x03;
    public const OCTET_STRING = 0x04;
    public const NULL_TAG = 0x05;
    public const OID = 0x06;
    public const UTF8_STRING = 0x0c;
    public const IA5_STRING = 0x16;
    public const UTC_TIME = 0x17;
    public const GENERALIZED_TIME = 0x18;
    public const SEQUENCE = 0x30;
    public const SET = 0x31;
    public const CONTEXT_0 = 0xa0;
    public const CONTEXT_3 = 0xa3;

    public static function tlv(int $tag, string ...$parts): string
    {
        $contents = implode('', $parts);
        $n = strlen($contents);
        if ($n < 0x80) {
            $length = chr($n);
        } elseif ($n < 0x100) {
            $length = "\x81" . chr($n);
        } elseif ($n < 0x10000) {
            $length = "\x82" . chr($n >> 8) . chr($n & 0xff);
        } else {
            $length = "\x83" . chr(($n >> 16) & 0xff) . chr(($n >> 8) & 0xff) . chr($n & 0xff);
        }

        return chr($tag) . $length . $contents;
    }

    /** An indefinite-length constructed value, which genuine Xcode receipts use. */
    public static function indefinite(int $tag, string ...$parts): string
    {
        return chr($tag) . "\x80" . implode('', $parts) . "\x00\x00";
    }

    public static function oid(string $hex): string
    {
        return self::tlv(self::OID, (string) hex2bin($hex));
    }

    public static function int(int ...$bytes): string
    {
        return self::tlv(self::INTEGER, implode('', array_map(chr(...), $bytes)));
    }
}
