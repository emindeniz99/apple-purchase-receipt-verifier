package io.github.emindeniz99.applepurchasereceiptverifier.internal;

/**
 * Renders attacker-controlled input for an exception message.
 *
 * <p>Every {@code VerificationException} detail that quotes something out of
 * the input goes through here first. Two things go wrong when it does not. A
 * multi-megabyte {@code alg} claim produced a multi-megabyte message, so an
 * input the library correctly refused still cost the caller the memory it was
 * refusing to spend, once per log line and once per exception kept. And a
 * newline inside a claim ended the log record and started a new one, so an
 * attacker chose what the next line of the log said.
 *
 * <p>This package is an implementation detail of the library. It is public
 * only because Java packages are not nested, and the classes that need it sit
 * in two different packages; nothing in it is API and it may change in any
 * release.
 */
public final class SafeText {

    /** Longer input is cut here. Long enough to identify a claim, short enough to be free. */
    private static final int MAX_LENGTH = 64;

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
    public static String quote(String value) {
        if (value == null) {
            return "null";
        }
        String head = value.length() <= MAX_LENGTH ? value : value.substring(0, MAX_LENGTH);
        StringBuilder out = new StringBuilder(head.length() + 32);
        for (int i = 0; i < head.length(); i++) {
            char c = head.charAt(i);
            out.append(c < 0x20 || c == 0x7F ? PLACEHOLDER : c);
        }
        if (value.length() > MAX_LENGTH) {
            out.append("... (").append(value.length()).append(" characters)");
        }
        return out.toString();
    }

    /** {@link #quote(String)} for a single character, so one control byte cannot forge a log line. */
    public static String quote(char value) {
        return quote(String.valueOf(value));
    }
}
