package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

/**
 * Measures a {@link String} in UTF-8 bytes without encoding it. The input
 * limits are Apple's, and Apple counts the bytes on the wire: a Java
 * {@code String} holds UTF-16 code units, so {@code length()} under-counts
 * any character above U+007F, and {@code getBytes(UTF_8)} would copy up to
 * three bytes per character of an input whose whole point is being too large.
 *
 * <p>Two shortcuts decide almost every call without looking at a character.
 * Every UTF-16 unit costs at least one byte, so more units than the limit is
 * over it. Every unit costs at most three bytes (a surrogate pair is two
 * units and four bytes), so three times the units within the limit is within
 * it. Only a string between those two bounds is walked, and the walk stops as
 * soon as the count passes the limit.</p>
 *
 * <p>A lone surrogate, which no well-formed UTF-8 can carry, counts as three
 * bytes: what it takes in CESU-8 and WTF-8, and never less than any encoder
 * emits for it ({@code getBytes(UTF_8)} substitutes the one byte {@code '?'}).
 * It cannot arrive from the wire, where a decoder turns invalid bytes into
 * U+FFFD, itself three bytes.</p>
 */
final class Utf8Length {

    private Utf8Length() {}

    /** Whether {@code text} takes more than {@code limit} bytes as UTF-8. */
    static boolean exceeds(String text, int limit) {
        int units = text.length();
        if (units > limit) {
            return true;
        }
        if (units * 3L <= limit) {
            return false;
        }
        long bytes = 0;
        for (int i = 0; i < units; i++) {
            char c = text.charAt(i);
            if (c < 0x80) {
                bytes += 1;
            } else if (c < 0x800) {
                bytes += 2;
            } else if (Character.isHighSurrogate(c) && i + 1 < units && Character.isLowSurrogate(text.charAt(i + 1))) {
                bytes += 4;
                i++;
            } else {
                bytes += 3;
            }
            if (bytes > limit) {
                return true;
            }
        }
        return false;
    }
}
