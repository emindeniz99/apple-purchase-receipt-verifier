package io.github.emindeniz99.applepurchasereceiptverifier.internal;

import org.jspecify.annotations.Nullable;

/**
 * Renders attacker-controlled input for an exception message.
 *
 * <p>Every {@code VerificationException} detail that quotes something out of
 * the input goes through here first. Truncation keeps a huge claim from
 * making every message and log line huge; replacing control characters keeps
 * a newline in a claim from forging the next log line.
 *
 * <p>This package is an implementation detail of the library. It is public
 * only because Java packages are not nested, and the classes that need it sit
 * in two different packages; nothing in it is API and it may change in any
 * release.
 */
public final class SafeText {

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
    public static String quote(@Nullable String value) {
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
    public static String detail(@Nullable String message) {
        return render(message, MAX_DETAIL_LENGTH);
    }

    private static String render(@Nullable String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        String head = value.length() <= maxLength ? value : value.substring(0, maxLength);
        StringBuilder out = new StringBuilder(head.length() + 32);
        for (int i = 0; i < head.length(); i++) {
            char c = head.charAt(i);
            out.append(c < 0x20 || c == 0x7F ? PLACEHOLDER : c);
        }
        if (value.length() > maxLength) {
            out.append("... (").append(value.length()).append(" characters)");
        }
        return out.toString();
    }
}
