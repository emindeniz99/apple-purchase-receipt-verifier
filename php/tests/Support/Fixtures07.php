<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use RuntimeException;

/**
 * Locates the repository's shared `fixtures/` directory and decodes the
 * fixtures `cases-0.7.json` registers, checking each one against the
 * SHA-256 the registry records for its DECODED logical bytes.
 *
 * A sibling of {@see Fixtures}, kept separate because the 0.7 cases file
 * has its own schema (schemaVersion 2) and lives beside the 0.6 one while
 * ports migrate one by one (docs/design/0.7-api.md, "Release").
 */
final class Fixtures07
{
    /** @var array<string, string> */
    private static array $cache = [];

    /** @var array<string, mixed>|null */
    private static ?array $document = null;

    public static function directory(): string
    {
        $dir = __DIR__;
        for ($i = 0; $i < 12; ++$i) {
            if (is_file($dir . '/fixtures/cases-0.7.json')) {
                return $dir . '/fixtures';
            }
            $parent = dirname($dir);
            if ($parent === $dir) {
                break;
            }
            $dir = $parent;
        }

        throw new RuntimeException('harness error: could not locate fixtures/cases-0.7.json by walking up from ' . __DIR__);
    }

    /** @return array<string, mixed> */
    public static function cases(): array
    {
        if (self::$document === null) {
            $json = file_get_contents(self::directory() . '/cases-0.7.json');
            if ($json === false) {
                throw new RuntimeException('harness error: cases-0.7.json is unreadable');
            }
            /** @var array<string, mixed> $parsed */
            $parsed = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
            self::$document = $parsed;
        }

        return self::$document;
    }

    /** @return array<string, array{path: string, role: string, codec: string, contentSha256: string}> */
    public static function registry(): array
    {
        /** @var array<string, array{path: string, role: string, codec: string, contentSha256: string}> */
        return self::cases()['fixtures'];
    }

    /** The decoded logical bytes of a registered fixture, digest-checked. */
    public static function bytes(string $id): string
    {
        if (isset(self::$cache[$id])) {
            return self::$cache[$id];
        }
        $registry = self::registry();
        if (!isset($registry[$id])) {
            throw new RuntimeException("harness error: cases-0.7.json registers no fixture \"{$id}\"");
        }
        $entry = $registry[$id];
        $raw = file_get_contents(self::directory() . '/' . $entry['path']);
        if ($raw === false) {
            throw new RuntimeException("harness error: fixture \"{$id}\" ({$entry['path']}) is unreadable");
        }
        $bytes = match ($entry['codec']) {
            'raw' => $raw,
            'base64' => self::strictBase64($id, $raw),
            'utf8' => trim($raw),
            // Verbatim, untrimmed: pins how a port decodes what a client
            // sent, whitespace included.
            'text' => $raw,
            default => throw new RuntimeException(
                "harness error: unknown fixture codec \"{$entry['codec']}\" for \"{$id}\"",
            ),
        };
        $actual = hash('sha256', $bytes);
        if (!hash_equals($entry['contentSha256'], $actual)) {
            throw new RuntimeException(
                "fixture \"{$id}\" ({$entry['path']}, codec {$entry['codec']}) has drifted: "
                . "cases-0.7.json records contentSha256 {$entry['contentSha256']}, "
                . "the decoded bytes hash to {$actual}",
            );
        }

        return self::$cache[$id] = $bytes;
    }

    private static function strictBase64(string $id, string $text): string
    {
        $stripped = preg_replace('/\s+/', '', $text) ?? '';
        $decoded = base64_decode($stripped, true);
        if ($decoded === false) {
            throw new RuntimeException("harness error: fixture \"{$id}\" is not valid base64");
        }

        return $decoded;
    }
}
