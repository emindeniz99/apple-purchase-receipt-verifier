package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * Renders attacker-controlled input for an exception message.
 *
 * <p>Every {@link VerificationException} detail that quotes something out of
 * the input goes through here first. Truncation keeps a huge claim from
 * making every message and log line huge; replacing control characters keeps
 * a newline in a claim from forging the next log line, and a bidirectional
 * override from reordering the line it sits in.
 */
final class SafeText {

    /** Longer input is cut here. Long enough to identify a claim, short enough to be free. */
    private static final int MAX_LENGTH = 64;

    /**
     * The cut for {@link #detail}: a validator's message quoting two
     * distinguished names still fits, a flood does not.
     */
    private static final int MAX_DETAIL_LENGTH = 256;

    /** Stands in for a character that must not reach a log line as itself. */
    private static final char PLACEHOLDER = '\uFFFD';

    private SafeText() {}

    /**
     * The input, at most {@link #MAX_LENGTH} characters long and carrying no
     * control character. A truncated value states its own original length, so
     * "this was cut" is never confused with "this was the whole value".
     *
     * @param value the attacker-controlled text; {@code null} renders as
     *              {@code "null"}, the same as string concatenation would
     */
    static String quote(@Nullable String value) {
        return render(value, MAX_LENGTH);
    }

    /**
     * A third-party exception message (BouncyCastle, Jackson) rendered as
     * {@link #quote} renders a claim, with a longer cut. Such a message can
     * quote the input, a distinguished name out of a certificate, say, so it
     * is attacker-controlled too.
     *
     * @param message the message; {@code null} renders as {@code "null"}
     */
    static String detail(@Nullable String message) {
        return render(message, MAX_DETAIL_LENGTH);
    }

    private static String render(@Nullable String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        int cut = Math.min(value.length(), maxLength);
        // Never between the two halves of a surrogate pair, which would
        // leave a lone surrogate at the end of the message.
        if (cut < value.length()
                && Character.isHighSurrogate(value.charAt(cut - 1))
                && Character.isLowSurrogate(value.charAt(cut))) {
            cut -= 1;
        }
        StringBuilder out = new StringBuilder(cut + 32);
        for (int i = 0; i < cut; i++) {
            char c = value.charAt(i);
            out.append(unsafeInALogLine(c) ? PLACEHOLDER : c);
        }
        if (value.length() > maxLength) {
            out.append("... (").append(value.length()).append(" characters)");
        }
        return out.toString();
    }

    /**
     * C0 and C1 controls, DEL, and the Unicode line and paragraph separators:
     * everything a log viewer or {@code String.lines()} may treat as a break.
     * And the bidirectional formatting characters (U+061C, U+200E, U+200F,
     * U+202A to U+202E, U+2066 to U+2069), which can make a log line display
     * in an order other than the one it was written in.
     */
    private static boolean unsafeInALogLine(char c) {
        return c < 0x20
                || (c >= 0x7F && c <= 0x9F)
                || c == '\u2028'
                || c == '\u2029'
                || c == '\u061C'
                || c == '\u200E'
                || c == '\u200F'
                || (c >= '\u202A' && c <= '\u202E')
                || (c >= '\u2066' && c <= '\u2069');
    }
}
