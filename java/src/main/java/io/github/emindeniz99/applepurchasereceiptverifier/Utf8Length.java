package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * A {@link String}'s length in UTF-8 bytes, as Apple counts its limits,
 * without encoding it; see docs/design/java-notes.md.
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
