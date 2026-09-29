<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The package is a façade over `aprv`: it holds no verification logic. This
 * is the PHP half of the one-implementation rule (docs/rust-core/
 * ARCHITECTURE.md §9): no crypto call, no ASN.1, X.509, CMS or JWS code, and
 * no file that could hold any.
 */
#[CoversNothing]
final class NoVerificationLogicTest extends TestCase
{
    /**
     * Functions a verifier would reach for. `hash()` and `base64_*` are not
     * here: the façade fingerprints roots and moves bytes, and decides
     * nothing with either.
     */
    private const BANNED_PREFIXES = ['openssl_', 'sodium_crypto', 'gmp_', 'bcpowmod', 'hash_hmac', 'mcrypt_'];

    /** What `src/Internal` may hold: data and mapping, never a parser. */
    private const INTERNAL_FILES = ['Info.php', 'Text.php', 'Wire.php'];

    public function testNoCryptoFunctionIsCalledAnywhereInTheSourceTree(): void
    {
        $offences = [];
        foreach (self::sourceFiles() as $file) {
            $tokens = token_get_all((string) file_get_contents($file), TOKEN_PARSE);
            foreach ($tokens as $index => $token) {
                if (!is_array($token) || $token[0] !== T_STRING) {
                    continue;
                }
                $next = self::nextMeaningful($tokens, $index);
                if ($next !== '(') {
                    continue;
                }
                $name = strtolower($token[1]);
                foreach (self::BANNED_PREFIXES as $prefix) {
                    if (str_starts_with($name, $prefix) && !self::isMethodCall($tokens, $index)) {
                        $offences[] = basename($file) . ': ' . $token[1] . '()';
                    }
                }
            }
        }

        self::assertSame([], $offences, 'the façade must not verify anything itself');
    }

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

    /** @return list<string> */
    private static function sourceFiles(): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../src'));
        foreach ($iterator as $file) {
            if ($file instanceof SplFileInfo && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        sort($files);
        self::assertNotEmpty($files);

        return $files;
    }

    /** @param array<int, array{int, string, int}|string> $tokens */
    private static function nextMeaningful(array $tokens, int $index): ?string
    {
        for ($i = $index + 1; $i < count($tokens); ++$i) {
            $token = $tokens[$i];
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return is_array($token) ? $token[1] : $token;
        }

        return null;
    }

    /** @param array<int, array{int, string, int}|string> $tokens */
    private static function isMethodCall(array $tokens, int $index): bool
    {
        for ($i = $index - 1; $i >= 0; --$i) {
            $token = $tokens[$i];
            if (is_array($token) && $token[0] === T_WHITESPACE) {
                continue;
            }

            return is_array($token) && in_array($token[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true);
        }

        return false;
    }
}
