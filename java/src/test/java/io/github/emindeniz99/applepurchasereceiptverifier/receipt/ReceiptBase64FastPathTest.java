package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import java.util.Base64;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptBase64#decode} tries the JDK's strict decoder before its own
 * tolerant parser. That shortcut is only safe if it never changes an answer:
 * every string the JDK decoder accepts must be one the tolerant parser accepts
 * too, with the same bytes, and every string it refuses must reach the
 * tolerant parser unchanged. If the fast path ever accepted something the
 * documented {@code receipt-data} contract rejects (a character after the
 * padding, a wrong padding count), a malformed receipt would start verifying
 * in Java alone, and the nine ports would disagree.
 *
 * <p>The generator is seeded, so a failure reproduces. It mixes the shapes
 * the contract names: clean standard base64, missing and extra padding, both
 * alphabets, whitespace anywhere, illegal characters (including ones outside
 * Latin-1), characters after the padding, and lengths congruent to 1 mod 4.
 */
class ReceiptBase64FastPathTest {

    private static final long SEED = 0x5EED_B64L;
    private static final int CASES = 20_000;
    private static final String ILLEGAL = "!#$%&*.,:;?@[]{}|~\"'\\\u0000\u007féÿĀ  \u000b";
    private static final String WHITESPACE = "\r\n \t";

    @Test
    void decodeAgreesWithTheTolerantPathOnGeneratedInputs() {
        Random random = new Random(SEED);
        int fastAccepted = 0;
        int tolerantOnlyAccepted = 0;
        int rejected = 0;
        for (int i = 0; i < CASES; i++) {
            String input = generate(random);
            if (compare(input)) {
                if (jdkAccepts(input)) {
                    fastAccepted++;
                } else {
                    tolerantOnlyAccepted++;
                }
            } else {
                rejected++;
            }
        }
        // The comparison proves nothing unless every branch was exercised
        // many times: the fast path taken, the fallback accepting, and both
        // rejecting.
        assertTrue(fastAccepted > 1_000, "fast path accepted only " + fastAccepted);
        assertTrue(tolerantOnlyAccepted > 1_000, "fallback accepted only " + tolerantOnlyAccepted);
        assertTrue(rejected > 1_000, "rejected only " + rejected);
    }

    @Test
    void decodeAgreesWithTheTolerantPathOnHandPickedEdges() {
        String[] edges = {
            "",
            " ",
            "\r\n\t ",
            "=",
            "==",
            "===",
            "====",
            "A",
            "A=",
            "A==",
            "A===",
            "AA",
            "AA=",
            "AA==",
            "AA===",
            "AAA",
            "AAA=",
            "AAA==",
            "AAAA",
            "AAAA=",
            "AAAA==",
            "AA==A",
            "AA==\n",
            "AA==AA==",
            "AAAAA",
            "-_",
            "+/",
            "+_",
            "-/",
            "AB-_",
            "AB+/",
            "ABé=",
            "ABĀ",
            "QUJD",
            "QUJ",
            "QUI",
            "QQ",
            "QR",
            "QUK=",
            "QUJD\r\n",
        };
        for (String edge : edges) {
            compare(edge);
        }
    }

    /**
     * Asserts that {@code decode} and {@code decodeTolerant} give the same
     * answer for {@code input}: equal bytes, or the same reason and message.
     * Returns whether the input was accepted.
     */
    private static boolean compare(String input) {
        byte[] expected = null;
        VerificationException expectedError = null;
        try {
            expected = ReceiptBase64.decodeTolerant(input);
        } catch (VerificationException e) {
            expectedError = e;
        }
        byte[] actual = null;
        VerificationException actualError = null;
        try {
            actual = ReceiptBase64.decode(input);
        } catch (VerificationException e) {
            actualError = e;
        }
        String shown = describe(input);
        if (expectedError != null) {
            if (actualError == null) {
                fail("decode accepted what the tolerant path rejects: " + shown);
            }
            assertEquals(expectedError.reason(), actualError.reason(), shown);
            assertEquals(expectedError.getMessage(), actualError.getMessage(), shown);
            return false;
        }
        if (actualError != null) {
            fail("decode rejected what the tolerant path accepts: " + shown + ": " + actualError.getMessage());
        }
        assertArrayEquals(expected, actual, shown);
        return true;
    }

    private static boolean jdkAccepts(String input) {
        try {
            Base64.getDecoder().decode(input);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String generate(Random random) {
        byte[] bytes = new byte[random.nextInt(40)];
        random.nextBytes(bytes);
        StringBuilder s = new StringBuilder(Base64.getEncoder().encodeToString(bytes));
        // About half the inputs stay canonical standard base64 so the fast
        // path is taken often; the rest get one or more defects.
        if (random.nextBoolean()) {
            return s.toString();
        }
        int mutations = 1 + random.nextInt(3);
        for (int m = 0; m < mutations; m++) {
            switch (random.nextInt(9)) {
                case 0: // drop the padding
                    while (s.length() > 0 && s.charAt(s.length() - 1) == '=') {
                        s.setLength(s.length() - 1);
                    }
                    break;
                case 1: // extra padding
                    s.append(random.nextBoolean() ? "=" : "==");
                    break;
                case 2: // base64url alphabet, whole string
                    replaceAll(s, '+', '-');
                    replaceAll(s, '/', '_');
                    break;
                case 3: // one character of the other alphabet
                    insert(s, random, "+/-_".charAt(random.nextInt(4)));
                    break;
                case 4: // whitespace somewhere, including before and after the padding
                    insert(s, random, WHITESPACE.charAt(random.nextInt(WHITESPACE.length())));
                    break;
                case 5: // an illegal character
                    insert(s, random, ILLEGAL.charAt(random.nextInt(ILLEGAL.length())));
                    break;
                case 6: // something after the padding
                    s.append('=').append((char) ('A' + random.nextInt(26)));
                    break;
                case 7: // length congruent to 1 mod 4 (after stripping padding)
                    while (s.length() > 0 && s.charAt(s.length() - 1) == '=') {
                        s.setLength(s.length() - 1);
                    }
                    while (s.length() % 4 != 1) {
                        s.append('A');
                    }
                    break;
                default: // whitespace-only or empty
                    if (random.nextInt(8) == 0) {
                        s.setLength(0);
                        for (int k = random.nextInt(3); k > 0; k--) {
                            s.append(WHITESPACE.charAt(random.nextInt(WHITESPACE.length())));
                        }
                    } else {
                        s.append(WHITESPACE.charAt(random.nextInt(WHITESPACE.length())));
                    }
                    break;
            }
        }
        return s.toString();
    }

    private static void replaceAll(StringBuilder s, char from, char to) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == from) {
                s.setCharAt(i, to);
            }
        }
    }

    private static void insert(StringBuilder s, Random random, char c) {
        s.insert(random.nextInt(s.length() + 1), c);
    }

    private static String describe(String input) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 0x20 && c < 0x7f) {
                out.append(c);
            } else {
                out.append(String.format("\\u%04x", (int) c));
            }
        }
        return out.append('"').toString();
    }
}
