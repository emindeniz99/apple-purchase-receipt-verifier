<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The package is a façade over `aprv`: it holds no verification logic
 * (docs/rust-core/ARCHITECTURE.md §9). The crypto functions it must not call
 * are banned for every wrapper in one place, tools/check-one-implementation.mjs;
 * this test holds what that line scan does not: the manifests require no
 * crypto extension, and no file under src/Internal could hold a parser.
 */
#[CoversNothing]
final class NoVerificationLogicTest extends TestCase
{
    /**
     * What `src/Internal` may hold: data and mapping (PayloadJson writes the
     * payload's JSON values, Info reads what `aprv` states about itself),
     * never a parser.
     */
    private const INTERNAL_FILES = ['Info.php', 'PayloadJson.php', 'Text.php', 'Wire.php'];

    public function testTheOpensslExtensionIsNotRequired(): void
    {
        foreach (['/../../composer.json', '/../composer.json'] as $manifest) {
            /** @var array{require: array<string, string>} $composer */
            $composer = json_decode((string) file_get_contents(__DIR__ . $manifest), true, 16, JSON_THROW_ON_ERROR);
            self::assertArrayNotHasKey('ext-openssl', $composer['require'], $manifest);
            self::assertSame(['php', 'ext-json', 'psr/clock'], array_keys($composer['require']), $manifest);
        }
    }

    public function testInternalHoldsNoParserOrChainCode(): void
    {
        $files = array_map('basename', glob(__DIR__ . '/../src/Internal/*.php') ?: []);
        sort($files);
        self::assertSame(self::INTERNAL_FILES, $files, 'a new file under src/Internal needs a reason: no parser lives here');
    }
}
