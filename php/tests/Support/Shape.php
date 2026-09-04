<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use PHPUnit\Framework\Assert;

/**
 * Narrows one `mixed` out of a decoded structure to the type a test is about
 * to use it as, failing the test when it is anything else.
 *
 * Every public shape this library produces — the endpoint's response body,
 * the fixture registry's JSON — is honestly typed `array<string, mixed>`,
 * because that is what a decoded JSON document is. A test that reaches into
 * one is asserting a shape whether it says so or not, and the assertion it
 * makes silently is the weak kind: an unexpected `null` two levels down
 * surfaces as "Cannot access offset on null" from PHP rather than as a named
 * failure. Going through here makes the shape assertion explicit and gives
 * the failure a message that says which value was wrong and what it was.
 */
final class Shape
{
    /**
     * @return array<array-key, mixed>
     */
    public static function asArray(mixed $value, string $what = 'value'): array
    {
        if (!is_array($value)) {
            Assert::fail("expected {$what} to be an array, got " . get_debug_type($value));
        }

        return $value;
    }

    public static function asString(mixed $value, string $what = 'value'): string
    {
        if (!is_string($value)) {
            Assert::fail("expected {$what} to be a string, got " . get_debug_type($value));
        }

        return $value;
    }

    public static function asInt(mixed $value, string $what = 'value'): int
    {
        if (!is_int($value)) {
            Assert::fail("expected {$what} to be an int, got " . get_debug_type($value));
        }

        return $value;
    }
}
