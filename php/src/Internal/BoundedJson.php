<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * JSON structural bounds, checked before `json_decode()` runs: nesting
 * depth, member-name length and number length. `json_decode()`'s `$depth`
 * argument bounds nesting only, so member-name and number length are
 * measured here first, on text nobody has vouched for yet. The three bounds
 * are the shared ones (docs/design/0.7-api.md, "Bounds"): 64 levels of
 * nesting, 50,000-character member names, 1,000-character numbers.
 *
 * This is a bounds scanner, not a validator: malformed JSON this scanner
 * cannot make sense of is left for `json_decode()` to reject on its own
 * terms. The two must never disagree about what counts as "too deep" for a
 * document that IS valid JSON, which is the only case this scanner's verdict
 * is acted on for.
 *
 * @internal
 */
final class BoundedJson
{
    /** How deep an object/array structure may nest, outermost included. */
    public const MAX_NESTING_DEPTH = 64;

    /** The longest object member name, in characters (source form, between the quotes). */
    public const MAX_NAME_LENGTH = 50000;

    /** The longest number token, in characters. */
    public const MAX_NUMBER_LENGTH = 1000;

    /**
     * A manual byte scan, not `preg_match_all()`: that built one match-array
     * entry per token via `PREG_SET_ORDER`, and a body that is mostly tiny
     * bracket tokens (well inside {@see MAX_NESTING_DEPTH} and the caller's
     * byte cap — a deep, narrow chain repeated many times, not one deep
     * document) turns into millions of those entries, costing far more
     * memory than the input itself (measured: a 3 MiB body of repeated
     * `[0]` chains exhausted a 384M limit inside `preg_match_all` before
     * `json_decode` ever ran). A single pass with scalar state has no such
     * amplification: cost stays linear in the input regardless of how the
     * tokens are shaped.
     *
     * Byte-oriented throughout, like the regex it replaces: a JSON string's
     * content is scanned as raw bytes between the quotes, escapes included,
     * so {@see MAX_NAME_LENGTH} counts source characters between the quotes,
     * not decoded ones. This does not itself validate JSON — a malformed
     * document is left for `json_decode()` to reject on its own terms — so
     * grammar it recognizes only loosely (a "number" is any run of
     * `[-+.eE0-9]`) is exactly what a well-formed JSON number occupies; nothing
     * valid tokenizes differently here than the RFC 8259 grammar would.
     */
    public static function exceedsBounds(string $text): bool
    {
        $depth = 0;
        $pendingStringLength = null;
        $length = strlen($text);
        $i = 0;
        while ($i < $length) {
            $ch = $text[$i];
            if ($ch === ' ' || $ch === "\t" || $ch === "\r" || $ch === "\n") {
                // ws: a string/number pending before whitespace stays pending.
                ++$i;
                continue;
            }
            if ($ch === '"') {
                $j = $i + 1;
                while ($j < $length) {
                    if ($text[$j] === '\\') {
                        $j += 2;
                        continue;
                    }
                    if ($text[$j] === '"') {
                        break;
                    }
                    ++$j;
                }
                $pendingStringLength = $j - ($i + 1);
                $i = $j < $length ? $j + 1 : $length;
                continue;
            }
            if ($ch === '-' || ($ch >= '0' && $ch <= '9')) {
                $start = $i;
                while ($i < $length && (
                    ($text[$i] >= '0' && $text[$i] <= '9')
                    || $text[$i] === '.' || $text[$i] === 'e' || $text[$i] === 'E'
                    || $text[$i] === '+' || $text[$i] === '-'
                )) {
                    ++$i;
                }
                if ($i - $start > self::MAX_NUMBER_LENGTH) {
                    return true;
                }
                $pendingStringLength = null;
                continue;
            }
            if ($ch === '{' || $ch === '[') {
                ++$depth;
                // False positive: PHPStan 2.2 stops widening $depth after a
                // few passes of this many-branched loop and infers
                // int<-2, 4>, but 65 consecutive '[' bytes reach 65.
                // @phpstan-ignore greater.alwaysFalse
                if ($depth > self::MAX_NESTING_DEPTH) {
                    return true;
                }
                $pendingStringLength = null;
                ++$i;
                continue;
            }
            if ($ch === '}' || $ch === ']') {
                --$depth;
                $pendingStringLength = null;
                ++$i;
                continue;
            }
            if ($ch === ':') {
                if ($pendingStringLength !== null && $pendingStringLength > self::MAX_NAME_LENGTH) {
                    return true;
                }
                $pendingStringLength = null;
                ++$i;
                continue;
            }
            // ',', a literal (true/false/null), or any other single byte:
            // neither a string nor a number is pending after it.
            $pendingStringLength = null;
            ++$i;
        }

        return false;
    }
}
