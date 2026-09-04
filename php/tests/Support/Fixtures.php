<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use RuntimeException;

/**
 * Locates the repository's shared `fixtures/` directory and decodes the
 * fixtures `cases.json` registers, checking each one against the SHA-256 the
 * registry records for its DECODED logical bytes.
 *
 * That digest check is not decoration. It is the only mechanical defence
 * against the whole conformance suite going green against fixture bytes that
 * were regenerated, re-encoded or quietly edited: the pinned expectations
 * would then describe bytes no other port ever saw.
 */
final class Fixtures
{
    /** @var array<string, string> */
    private static array $cache = [];

    /** @var array<string, mixed>|null */
    private static ?array $document = null;

    /**
     * The directory is found by walking up from this file, not by a
     * `../../..` literal, so moving the port one level deeper is a rename
     * rather than a silent breakage.
     */
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

    /** @return array<string, mixed> */
    public static function cases(): array
    {
        if (self::$document === null) {
            $json = file_get_contents(self::directory() . '/cases.json');
            if ($json === false) {
                throw new RuntimeException('harness error: cases.json is unreadable');
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
            throw new RuntimeException("harness error: cases.json registers no fixture \"{$id}\"");
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
            default => throw new RuntimeException(
                "harness error: unknown fixture codec \"{$entry['codec']}\" for \"{$id}\"",
            ),
        };
        $actual = hash('sha256', $bytes);
        if (!hash_equals($entry['contentSha256'], $actual)) {
            throw new RuntimeException(
                "fixture \"{$id}\" ({$entry['path']}, codec {$entry['codec']}) has drifted: "
                . "cases.json records contentSha256 {$entry['contentSha256']}, "
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
