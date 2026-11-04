<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use ReflectionMethod;

/** The shared cases through the default transport: one `aprv` process per call. */
final class ConformanceCasesTest extends ConformanceBase
{
    protected static function verifierFor(Config $config): Verifier
    {
        return Verifier::create($config, new CliTransport(Aprv::binary()));
    }

    /**
     * The case pinning download_id at 2^63-1 is there to catch a value
     * rounded through a double, so the field comparison must round nothing
     * itself: a near miss is a mismatch, another spelling of the value is not.
     */
    public function testFieldNumbersCompareWithoutRounding(): void
    {
        $fieldsEqual = new ReflectionMethod(ConformanceBase::class, 'fieldsEqual');
        $pairs = [
            ['9223372036854775807', '9223372036854775807', true],
            ['9223372036854775806', '9223372036854775807', false],
            ['9223372036854775808', '9223372036854775807', false],
            ['9007199254740993.0', '9007199254740993', false],
            ['9007199254740992', '9007199254740993', false],
            ['1722945600000.0', '1722945600000', true],
            ['1722945600000.5', '1722945600000.5', true],
            ['"1"', '1', false],
        ];
        foreach ($pairs as [$got, $want, $equal]) {
            self::assertSame(
                $equal,
                $fieldsEqual->invoke(
                    null,
                    json_decode($got, true, 4, JSON_THROW_ON_ERROR),
                    json_decode($want, true, 4, JSON_THROW_ON_ERROR),
                ),
                "{$got} against {$want}",
            );
        }
    }
}
