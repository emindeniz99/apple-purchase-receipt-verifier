package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;

/**
 * A {@link String}'s length in UTF-8 bytes, as Apple counts its limits. A
 * lone surrogate counts the one {@code ?} that {@code getBytes} writes for it.
 */
final class Utf8Length {

    private Utf8Length() {}

    /** Whether {@code text} takes more than {@code limit} bytes as UTF-8. */
    static boolean exceeds(String text, int limit) {
        // Every UTF-16 unit is at least one byte, so the first test also
        // bounds what the second one copies.
        return text.length() > limit || text.getBytes(StandardCharsets.UTF_8).length > limit;
    }
}
