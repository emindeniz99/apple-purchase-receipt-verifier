package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptVerifier#parseDate} reads {@code yyyy-MM-ddTHH:mm:ssZ}
 * itself instead of calling {@link java.time.Instant#parse}. A date it read
 * differently would move a purchase or expiry instant, and the receipt
 * creation date is the instant the certificate chain is validated at, so a
 * wrong one could change which certificates count as valid. A date it
 * accepted that Instant.parse refuses would let a malformed receipt through.
 * So it is compared with Instant.parse on generated dates that sit on and
 * around every boundary the shortcut checks: leap days, month ends, hour 24,
 * second 60, year 0000 and 9999, lower case, fractions, offsets and widths.
 */
class ReceiptDateFastPathTest {

    private static final long SEED = 0xDA7E_5EEDL;
    private static final int CASES = 100_000;

    @Test
    void readsEveryDateAsInstantParseDoes() {
        Random random = new Random(SEED);
        int shortcut = 0;
        int parsedFully = 0;
        int rejected = 0;
        for (int i = 0; i < CASES; i++) {
            String text = generate(random);
            String expected = outcome(text, false);
            assertEquals(expected, outcome(text, true), "parseDate differs for \"" + text + "\"");
            if (ReceiptVerifier.simpleUtcInstant(text) != null) {
                shortcut++;
            } else if (expected.startsWith("value")) {
                parsedFully++;
            } else {
                rejected++;
            }
        }
        assertTrue(shortcut > 5_000, "shortcut read only " + shortcut);
        assertTrue(parsedFully > 5_000, "full parse accepted only " + parsedFully);
        assertTrue(rejected > 20_000, "rejected only " + rejected);
    }

    @Test
    void leavesEveryShapeItDoesNotOwnToInstantParse() {
        for (String text : new String[] {
            "2024-02-30T00:00:00Z", // not a date: Instant.parse's own error
            "2023-02-29T00:00:00Z",
            "2024-01-01T24:00:00Z", // accepted by Instant.parse as the next midnight
            "2024-06-30T23:59:60Z", // accepted by Instant.parse as a leap second
            "2024-01-01t00:00:00z",
            "2024-01-01T00:00:00.5Z",
            "2024-01-01T00:00Z",
            "+2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00+00:00",
            "\uFF12\uFF10\uFF12\uFF14-01-01T00:00:00Z"
        }) {
            assertNull(ReceiptVerifier.simpleUtcInstant(text), text);
        }
    }

    private static String outcome(String text, boolean withShortcut) {
        try {
            return "value " + (withShortcut ? ReceiptVerifier.parseDate(text) : ReceiptVerifier.parseDateFully(text));
        } catch (VerificationException e) {
            return "rejected " + e.reason() + ": " + e.getMessage() + " cause "
                    + (e.getCause() == null ? null : e.getCause().getMessage());
        }
    }

    private static String generate(Random random) {
        int year = pick(random, new int[] {0, 1, 4, 100, 400, 1582, 1900, 1970, 2000, 2024, 2100, 9999})
                + (random.nextInt(4) == 0 ? random.nextInt(3) - 1 : 0);
        int month = random.nextInt(14);
        int day = pick(random, new int[] {0, 1, 28, 29, 30, 31, 32}) + (random.nextInt(8) == 0 ? random.nextInt(9) : 0);
        int hour = pick(random, new int[] {0, 12, 23, 24, 25});
        int minute = pick(random, new int[] {0, 30, 59, 60});
        int second = pick(random, new int[] {0, 30, 59, 60, 61});
        String text =
                String.format("%04d-%02d-%02dT%02d:%02d:%02dZ", Math.max(year, 0), month, day, hour, minute, second);
        switch (random.nextInt(12)) {
            case 0:
                return text.toLowerCase(java.util.Locale.ROOT);
            case 1:
                return text.replace("Z", ".123Z");
            case 2:
                return text.replace("Z", "+00:00");
            case 3:
                // One character replaced: a digit, a separator or junk.
                char[] chars = text.toCharArray();
                String replacements = "0/9: T-Za+" + (char) 0x0660;
                chars[random.nextInt(chars.length)] = replacements.charAt(random.nextInt(replacements.length()));
                return new String(chars);
            case 4:
                return text.substring(0, random.nextInt(text.length()));
            case 5:
                return (random.nextBoolean() ? "+" : "-") + "0" + text;
            default:
                return text;
        }
    }

    private static int pick(Random random, int[] values) {
        return values[random.nextInt(values.length)];
    }
}
