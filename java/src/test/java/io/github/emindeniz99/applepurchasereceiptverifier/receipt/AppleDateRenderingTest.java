package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Every date in a verifyReceipt response is rendered by
 * {@link VerifyReceiptResult#format}, which writes the common years itself
 * instead of going through {@code DateTimeFormatter}. The rendered strings are
 * the response Apple's clients parse, and the other ports render the same
 * text, so a single character of difference is a compatibility break. So the
 * shortcut is compared with the formatter on instants around everything it
 * decides: Pacific daylight-saving transitions (where the offset changes
 * under the same wall-clock text), the year 1 and year 9999 boundaries it
 * hands back to the formatter, negative years, sub-second instants, and the
 * ends of the Instant range, where both must fail the same way.
 */
class AppleDateRenderingTest {

    private static final long SEED = 0xDA7E_F0E7L;
    private static final int CASES = 200_000;
    private static final long YEAR = 31_556_952L;

    @Test
    void rendersEveryInstantAsTheFormatterDoes() {
        Random random = new Random(SEED);
        long[] anchors = {
            Instant.parse("2024-03-10T10:00:00Z").getEpochSecond(), // PST to PDT
            Instant.parse("2024-11-03T09:00:00Z").getEpochSecond(), // PDT to PST
            Instant.parse("1883-11-18T20:00:00Z").getEpochSecond(), // LMT to PST
            Instant.parse("0001-01-01T00:00:00Z").getEpochSecond(),
            Instant.parse("9999-12-31T23:59:59Z").getEpochSecond(),
            0L
        };
        int common = 0;
        for (int i = 0; i < CASES; i++) {
            long seconds;
            switch (random.nextInt(3)) {
                case 0:
                    seconds = anchors[random.nextInt(anchors.length)] + random.nextInt(2 * 86_400) - 86_400;
                    break;
                case 1:
                    seconds = (long) (random.nextDouble() * 12_000 * YEAR) - 2_000 * YEAR;
                    break;
                default:
                    seconds = (long) (random.nextDouble() * 60 * YEAR);
                    break;
            }
            Instant instant = Instant.ofEpochSecond(seconds, random.nextBoolean() ? 0 : random.nextInt(1_000_000_000));
            for (ZoneId zone : new ZoneId[] {VerifyReceiptResult.GMT, VerifyReceiptResult.PACIFIC}) {
                String expected = VerifyReceiptResult.FORMAT.format(instant.atZone(zone));
                assertEquals(expected, VerifyReceiptResult.format(instant, zone), instant + " in " + zone);
                if (!expected.startsWith("+") && expected.length() == 19) {
                    common++;
                }
            }
        }
        assertTrue(common > 200_000, "only " + common + " renderings in years 1 to 9999");
    }

    @Test
    void failsAtTheEndsOfTheInstantRangeAsTheFormatterDoes() {
        for (Instant instant : new Instant[] {Instant.MIN, Instant.MAX}) {
            for (ZoneId zone : new ZoneId[] {VerifyReceiptResult.GMT, VerifyReceiptResult.PACIFIC}) {
                assertEquals(
                        outcome(() -> VerifyReceiptResult.FORMAT.format(instant.atZone(zone))),
                        outcome(() -> VerifyReceiptResult.format(instant, zone)),
                        instant + " in " + zone);
            }
        }
    }

    private interface Render {
        String run();
    }

    private static String outcome(Render render) {
        try {
            return "value " + render.run();
        } catch (RuntimeException e) {
            return e.getClass().getName() + ": " + e.getMessage();
        }
    }
}
