<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * Renders attacker-controlled input for a {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Failure}
 * message.
 *
 * Every message that quotes something out of the input goes through here
 * first. Truncation keeps a huge claim from making every message huge;
 * replacing control characters keeps a newline in a claim from forging the
 * next log line, and a bidirectional override from reordering the line it
 * sits in. Ported from the Java port's `SafeText` and the Python port's
 * `_safe_text` (docs/design/0.7-api.md: "message never embeds raw input").
 *
 * @internal
 */
final class SafeText
{
    /** Longer input is cut here: long enough to identify a claim, short enough to be free. */
    private const MAX_LENGTH = 64;

    /** The cut for {@see detail()}: a library message quoting two distinguished names still fits. */
    private const MAX_DETAIL_LENGTH = 256;

    /** Stands in for a character that must not reach a log line as itself. */
    private const PLACEHOLDER = "\u{FFFD}";

    /**
     * The input, at most {@see MAX_LENGTH} characters long and carrying no
     * control character. A truncated value states its own original length,
     * so "this was cut" is never confused with "this was the whole value".
     * `null` renders as `"null"`.
     */
    public static function quote(?string $value): string
    {
        return self::render($value, self::MAX_LENGTH);
    }

    /**
     * A third-party exception message rendered as {@see quote()} renders a
     * claim, with a longer cut: such a message can quote the input, a
     * distinguished name out of a certificate say, so it is
     * attacker-controlled too.
     */
    public static function detail(?string $value): string
    {
        return self::render($value, self::MAX_DETAIL_LENGTH);
    }

    private static function render(?string $value, int $maxLength): string
    {
        if ($value === null) {
            return 'null';
        }
        // Decode as UTF-8 code points where possible; invalid UTF-8 is
        // walked byte by byte instead so a malformed claim still renders
        // (every byte outside 0x00-0x7F is then itself unsafe and becomes
        // the placeholder, which is a safe, if blunt, answer).
        $chars = preg_match('//u', $value) === 1
            ? preg_split('//u', $value, -1, PREG_SPLIT_NO_EMPTY) ?: []
            : str_split($value);
        $total = count($chars);
        $cut = min($total, $maxLength);
        $out = '';
        for ($i = 0; $i < $cut; ++$i) {
            $out .= self::unsafeInALogLine($chars[$i]) ? self::PLACEHOLDER : $chars[$i];
        }
        if ($total > $maxLength) {
            $out .= '... (' . $total . ' characters)';
        }

        return $out;
    }

    /**
     * C0 and C1 controls, DEL, and the Unicode line and paragraph
     * separators: everything a log viewer or a line-splitter may treat as a
     * break. And the bidirectional formatting characters (U+061C, U+200E,
     * U+200F, U+202A-U+202E, U+2066-U+2069), which can make a log line
     * display in an order other than the one it was written in.
     */
    private static function unsafeInALogLine(string $char): bool
    {
        $code = self::codepoint($char);
        if ($code === null) {
            // A lone byte from invalid UTF-8: anything outside printable
            // ASCII is unsafe by default.
            $code = ord($char);

            return $code < 0x20 || $code >= 0x7F;
        }

        return $code < 0x20
            || ($code >= 0x7F && $code <= 0x9F)
            || $code === 0x2028 || $code === 0x2029
            || $code === 0x061C || $code === 0x200E || $code === 0x200F
            || ($code >= 0x202A && $code <= 0x202E)
            || ($code >= 0x2066 && $code <= 0x2069);
    }

    /**
     * The Unicode code point of one UTF-8-encoded character (as
     * {@see render()} splits it with `preg_split('//u', ...)`), or `null`
     * when `$char` is not one well-formed UTF-8 sequence. No `ext-mbstring`
     * dependency: this reads no more than the four bytes a single code point
     * ever takes.
     */
    private static function codepoint(string $char): ?int
    {
        $bytes = array_map(ord(...), str_split($char));
        $len = count($bytes);
        if ($len === 1) {
            return $bytes[0] < 0x80 ? $bytes[0] : null;
        }
        if ($len === 2) {
            return (($bytes[0] & 0x1F) << 6) | ($bytes[1] & 0x3F);
        }
        if ($len === 3) {
            return (($bytes[0] & 0x0F) << 12) | (($bytes[1] & 0x3F) << 6) | ($bytes[2] & 0x3F);
        }
        if ($len === 4) {
            return (($bytes[0] & 0x07) << 18) | (($bytes[1] & 0x3F) << 12)
                | (($bytes[2] & 0x3F) << 6) | ($bytes[3] & 0x3F);
        }

        return null;
    }
}
