<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\BoundedJson;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The nesting bound, pinned on {@see BoundedJson} itself rather than only
 * through the conformance cases that reach it indirectly.
 *
 * Why the bound exists: the header, the payload and the endpoint request
 * body are all parsed before anything has vouched for them. Unbounded
 * nesting in that text is a stack and CPU attack: a few kilobytes of `[`
 * cost a recursive decoder one frame per byte. The shared bound
 * (docs/design/0.7-api.md, "Bounds") is 64 levels, outermost included, and
 * every caller turns a refusal here into MALFORMED.
 */
#[CoversClass(BoundedJson::class)]
final class BoundedJsonTest extends TestCase
{
    /**
     * The callers' `json_decode()` depth. PHP counts the innermost value as
     * one more level, so 64 levels of nesting need 65.
     */
    private const CALLER_DECODE_DEPTH = 65;

    /** @return iterable<string, array{\Closure(int): string}> */
    public static function nestings(): iterable
    {
        yield 'arrays' => [static fn (int $depth): string => str_repeat('[', $depth) . '0' . str_repeat(']', $depth)];
        yield 'objects' => [static fn (int $depth): string => str_repeat('{"a":', $depth) . '0' . str_repeat('}', $depth)];
        yield 'alternating' => [static fn (int $depth): string => str_repeat('{"a":[', intdiv($depth, 2))
            . ($depth % 2 === 1 ? '[0]' : '0')
            . str_repeat(']}', intdiv($depth, 2))];
    }

    /**
     * Exactly 64 levels is inside the bound, and the callers' decoder must
     * accept the same document: the class documents that the scanner and
     * `json_decode()` never disagree about valid JSON. If they did, a
     * document at the bound would pass here and still fail in the decoder,
     * or the reverse.
     *
     * @param \Closure(int): string $nest
     */
    #[DataProvider('nestings')]
    public function testSixtyFourLevelsAreAccepted(\Closure $nest): void
    {
        $json = $nest(BoundedJson::MAX_NESTING_DEPTH);

        self::assertSame(64, BoundedJson::MAX_NESTING_DEPTH);
        self::assertFalse(BoundedJson::exceedsBounds($json));
        self::assertNotNull(json_decode($json, false, self::CALLER_DECODE_DEPTH));
    }

    /**
     * One level more is refused by the scanner, before any decoder recurses
     * into it.
     *
     * @param \Closure(int): string $nest
     */
    #[DataProvider('nestings')]
    public function testSixtyFiveLevelsAreRefused(\Closure $nest): void
    {
        self::assertTrue(BoundedJson::exceedsBounds($nest(BoundedJson::MAX_NESTING_DEPTH + 1)));
    }

    /**
     * Depth is how deep the brackets are open at once, not how many there
     * are: 65 sibling structures of depth 1 stay within the bound, so the
     * refusal cannot be a byte count in disguise.
     */
    public function testDepthIsNestingNotBracketCount(): void
    {
        self::assertFalse(BoundedJson::exceedsBounds('[' . implode(',', array_fill(0, 65, '[0]')) . ']'));
    }
}
