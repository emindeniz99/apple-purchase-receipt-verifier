<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use RuntimeException;

/**
 * Shared setup for every target under `targets/`: the library's autoloader,
 * and a loader for the two generated fixture roots the anchor-set invariants
 * need.
 *
 * The fixture directory is located by walking up from this file, the same way
 * `tests/Support/Fixtures.php` does, so nothing under `fixtures/` is copied
 * into `php/`.
 */
require __DIR__ . '/../vendor/autoload.php';

final class FuzzFixtures
{
    public static function directory(): string
    {
        $dir = __DIR__;
        for ($i = 0; $i < 12; ++$i) {
            if (is_file($dir . '/fixtures/cases.json')) {
                return $dir . '/fixtures';
            }
            $parent = dirname($dir);
            if ($parent === $dir) {
                break;
            }
            $dir = $parent;
        }

        throw new RuntimeException('harness error: could not locate fixtures/cases.json by walking up from ' . __DIR__);
    }

    /** Raw bytes of a file under `fixtures/`, addressed by its relative path. */
    public static function bytes(string $relativePath): string
    {
        $path = self::directory() . '/' . $relativePath;
        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new RuntimeException('harness error: fixture "' . $path . '" is unreadable');
        }

        return $raw;
    }

    /**
     * The pinned Apple receipt anchors plus the generated fixture receipt
     * root, so the shared fixture receipts and the two public Apple receipts
     * all get past the chain check and the fuzzer can explore what lies
     * beyond it.
     *
     * @param list<string> $appleRoots
     *
     * @return list<string>
     */
    public static function withReceiptRoot(array $appleRoots): array
    {
        $appleRoots[] = self::bytes('generated/receipt-root.der');

        return $appleRoots;
    }

    /**
     * The unrelated anchor set: the generated fixture JWS root, which signs
     * nothing in the receipt corpus.
     *
     * @return list<string>
     */
    public static function jwsRootOnly(): array
    {
        return [self::bytes('generated/jws-root.der')];
    }
}
