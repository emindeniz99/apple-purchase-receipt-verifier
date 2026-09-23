package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Apple's verifyReceipt answers a 3,145,728-byte body and refuses a
 * 3,145,729-byte one, counting UTF-8 bytes rather than characters. A Java
 * {@code String} counts UTF-16 units, so {@link Utf8Length} is what makes the
 * Java limit Apple's limit. Each test here pins one way a units-based or
 * approximate count would move the boundary: two-byte characters,
 * three-byte characters, surrogate pairs (two units, four bytes), and both
 * shortcuts that skip the walk.
 */
class Utf8LengthTest {

    private static final int CAP = VerifyReceiptEndpoint.MAX_REQUEST_BYTES;
    private static final String E_ACUTE = "é"; // 2 bytes, 1 unit
    private static final String EURO = "€"; // 3 bytes, 1 unit
    private static final String EMOJI = "😀"; // 4 bytes, 2 units

    @Test
    void theCapIsApplesMeasuredRequestLimit() {
        assertEquals(3145728, CAP);
        assertEquals(3145728, ReceiptVerifier.MAX_RECEIPT_BYTES);
    }

    @Test
    void asciiIsOneBytePerCharacterRightAtTheCap() {
        assertFalse(Utf8Length.exceeds(repeat("a", CAP), CAP));
        assertTrue(Utf8Length.exceeds(repeat("a", CAP + 1), CAP));
    }

    /** Apple's own measurement: 3,145,729 bytes of U+00E9 is only 1,572,874 characters, and it is over. */
    @Test
    void twoByteCharactersAreCountedInBytesNotCharacters() {
        String atCap = repeat(E_ACUTE, CAP / 2);
        assertFalse(Utf8Length.exceeds(atCap, CAP));
        String overCap = "a" + atCap;
        assertEquals(CAP + 1, overCap.getBytes(StandardCharsets.UTF_8).length);
        assertTrue(overCap.length() < CAP, "a character count would call this one under the cap");
        assertTrue(Utf8Length.exceeds(overCap, CAP));
        assertFalse(Utf8Length.exceeds(repeat(E_ACUTE, (CAP - 1) / 2), CAP));
    }

    @Test
    void threeByteCharactersAtTheBoundary() {
        String atCap = repeat(EURO, CAP / 3); // 1,048,576 characters, 3,145,728 bytes
        assertFalse(Utf8Length.exceeds(atCap, CAP));
        assertTrue(Utf8Length.exceeds(atCap + "a", CAP));
    }

    /**
     * A surrogate pair is two UTF-16 units and four UTF-8 bytes: counting it
     * as two (units) or six (three per unit) both move the boundary.
     */
    @Test
    void aSurrogatePairIsFourBytes() {
        String atCap = repeat(EMOJI, CAP / 4);
        assertEquals(CAP, atCap.getBytes(StandardCharsets.UTF_8).length);
        assertFalse(Utf8Length.exceeds(atCap, CAP));
        assertTrue(Utf8Length.exceeds(atCap + "a", CAP));
        assertFalse(Utf8Length.exceeds(EMOJI, 4));
        assertTrue(Utf8Length.exceeds(EMOJI, 3));
    }

    /** The documented choice: a lone surrogate counts three bytes, never the one '?' getBytes writes. */
    @Test
    void aLoneSurrogateCountsThreeBytes() {
        assertFalse(Utf8Length.exceeds("\ud83d", 3));
        assertTrue(Utf8Length.exceeds("\ud83d", 2));
        assertFalse(Utf8Length.exceeds("\ude00", 3));
        assertTrue(Utf8Length.exceeds("\ude00", 2));
        assertTrue(Utf8Length.exceeds("\ud83da", 3), "high surrogate then ASCII is 3 + 1");
        assertTrue(Utf8Length.exceeds("\ude00\ud83d", 5), "reversed pair is two lone surrogates");
    }

    /** Both shortcuts, at their edges: units over the limit, and three times the units within it. */
    @Test
    void theShortcutsAgreeWithTheWalkAtTheirEdges() {
        assertTrue(Utf8Length.exceeds(repeat("a", 11), 10));
        assertFalse(Utf8Length.exceeds(repeat(EURO, 3), 9));
        assertTrue(Utf8Length.exceeds(repeat(EURO, 4), 11));
        assertFalse(Utf8Length.exceeds("", 0));
        assertTrue(Utf8Length.exceeds("a", 0));
    }

    /** For well-formed text the answer is exactly what encoding and measuring would give. */
    @Test
    void agreesWithEncodingOnGeneratedWellFormedText() {
        String[] alphabet = {"a", "~", E_ACUTE, "߿", "ࠀ", EURO, "￿", EMOJI, "􏿿"};
        Random random = new Random(0x0C0FFEE);
        for (int i = 0; i < 5000; i++) {
            StringBuilder text = new StringBuilder();
            int length = random.nextInt(40);
            for (int j = 0; j < length; j++) {
                text.append(alphabet[random.nextInt(alphabet.length)]);
            }
            String s = text.toString();
            int bytes = s.getBytes(StandardCharsets.UTF_8).length;
            for (int limit = Math.max(0, bytes - 4); limit <= bytes + 4; limit++) {
                assertEquals(bytes > limit, Utf8Length.exceeds(s, limit), s + " at limit " + limit);
            }
        }
    }

    /** Java 8 has no {@code String.repeat}, and the artifact's floor is 8. */
    private static String repeat(String unit, int count) {
        char[] units = unit.toCharArray();
        char[] out = new char[units.length * count];
        for (int i = 0; i < count; i++) {
            System.arraycopy(units, 0, out, i * units.length, units.length);
        }
        return new String(out);
    }
}
