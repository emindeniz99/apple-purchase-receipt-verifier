<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use RuntimeException;
use stdClass;

/**
 * Resolves the `fields`/`lengths` pointers `fixtures/cases-0.7.schema.json`
 * defines: RFC 6901 JSON Pointer, with one extension — a reference token
 * `[key=value]` selects the single element of an array whose member `key`
 * equals the JSON string `value`.
 */
final class JsonPointer
{
    /** Distinct from JSON `null`: "this path did not resolve" versus "the value there is null". */
    private static ?stdClass $missing = null;

    public static function missing(): stdClass
    {
        return self::$missing ??= new stdClass();
    }

    public static function isMissing(mixed $value): bool
    {
        return $value === self::missing();
    }

    /** @return list<array{bool, string}> [isBracketExtension, token] */
    private static function steps(string $path): array
    {
        if ($path === '') {
            return [];
        }
        $steps = [];
        $consumed = 0;
        if (preg_match_all('#/\[([^\]]+)\]|/([^/\[\]]*)#', $path, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE) === false) {
            throw new RuntimeException("harness error: unparseable field path \"{$path}\"");
        }
        foreach ($matches as $m) {
            if ($m[0][1] !== $consumed) {
                throw new RuntimeException("harness error: unparseable field path \"{$path}\"");
            }
            $consumed += strlen($m[0][0]);
            $bracket = $m[1][0] !== '' || $m[1][1] !== -1;
            $steps[] = [$bracket, $bracket ? $m[1][0] : self::unescape($m[2][0])];
        }
        if ($consumed !== strlen($path)) {
            throw new RuntimeException("harness error: unparseable field path \"{$path}\"");
        }

        return $steps;
    }

    private static function unescape(string $token): string
    {
        return str_replace(['~1', '~0'], ['/', '~'], $token);
    }

    public static function resolve(mixed $root, string $path): mixed
    {
        $current = $root;
        foreach (self::steps($path) as [$isBracket, $step]) {
            if ($current === null || self::isMissing($current)) {
                return self::missing();
            }
            if ($isBracket) {
                $eq = strpos($step, '=');
                if ($eq === false) {
                    throw new RuntimeException("harness error: bracket step \"[{$step}]\" has no \"=\"");
                }
                $key = substr($step, 0, $eq);
                $wanted = substr($step, $eq + 1);
                if (!is_array($current) || !array_is_list($current)) {
                    throw new RuntimeException("{$path}: [{$step}] does not select from a list");
                }
                $matches = array_values(array_filter(
                    $current,
                    static fn (mixed $e): bool => is_array($e) && array_key_exists($key, $e) && $e[$key] === $wanted,
                ));
                if (count($matches) !== 1) {
                    throw new RuntimeException(
                        "{$path}: [{$step}] must select exactly one element, selected " . count($matches),
                    );
                }
                $current = $matches[0];
                continue;
            }
            if (is_array($current) && array_is_list($current)) {
                if (!ctype_digit($step)) {
                    return self::missing();
                }
                $index = (int) $step;
                $current = $index < count($current) ? $current[$index] : self::missing();
            } elseif (is_array($current)) {
                $current = array_key_exists($step, $current) ? $current[$step] : self::missing();
            } else {
                return self::missing();
            }
        }

        return $current;
    }

    public static function resolveLength(mixed $root, string $path): mixed
    {
        $value = self::resolve($root, $path);

        return is_array($value) ? count($value) : self::missing();
    }
}
