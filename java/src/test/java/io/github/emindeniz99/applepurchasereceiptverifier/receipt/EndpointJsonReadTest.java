package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * {@link VerifyReceiptEndpoint#readJson} hands Jackson the request body as a
 * char array instead of a String, because Jackson reads a String longer than
 * 32,768 characters through a Reader and its receipt-data value one
 * character at a time. The endpoint answers 21002 for exactly the bodies
 * Jackson refuses, so the change is safe only if Jackson accepts, refuses and
 * reads every body the same way both ways. That is checked on short and long
 * bodies (long enough to cross the Reader's chunks), with escapes, broken
 * surrogates, trailing garbage, truncation, and nesting on both sides of the
 * endpoint's depth limit.
 */
class EndpointJsonReadTest {

    private static final long SEED = 0x7501_5EEDL;
    private static final int CASES = 3_000;

    @Test
    void readsEveryBodyAsReadValueOnAStringDoes() {
        Random random = new Random(SEED);
        List<String> bodies = new ArrayList<String>();
        for (int i = 0; i < CASES; i++) {
            bodies.add(generate(random));
        }
        int read = 0;
        int refused = 0;
        int longBodies = 0;
        for (String body : bodies) {
            String expected = outcome(body, false);
            assertEquals(expected, outcome(body, true), "outcome differs for a body of " + body.length() + " chars");
            if (expected.startsWith("value")) {
                read++;
            } else {
                refused++;
            }
            if (body.length() > 0x8000) {
                longBodies++;
            }
        }
        assertTrue(read > 500, "read only " + read);
        assertTrue(refused > 500, "refused only " + refused);
        assertTrue(longBodies > 500, "only " + longBodies + " bodies were long enough for the Reader path");
    }

    private static String outcome(String body, boolean charArray) {
        try {
            Object value = charArray
                    ? VerifyReceiptEndpoint.readJson(body)
                    : VerifyReceiptEndpoint.MAPPER.readValue(body, Object.class);
            return "value " + value;
        } catch (Exception e) {
            // The location in Jackson's message names its input, which is
            // the one thing that legitimately differs; the endpoint never
            // shows the message, only that the body was refused.
            return "refused " + e.getClass().getName();
        }
    }

    private static String generate(Random random) {
        int length = random.nextBoolean() ? random.nextInt(200) : 0x8000 + random.nextInt(0x10000);
        StringBuilder value = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int kind = random.nextInt(400);
            if (kind == 0) {
                value.append("\\n");
            } else if (kind == 1) {
                value.append("\\u00e9");
            } else if (kind == 2) {
                value.append("\\ud800"); // a lone surrogate escape
            } else if (kind == 3) {
                value.append((char) 0xE9);
            } else if (kind == 4 && random.nextInt(20) == 0) {
                value.append('"'); // ends the string early
            } else {
                value.append(
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(random.nextInt(64)));
            }
        }
        String body;
        switch (random.nextInt(10)) {
            case 0:
                body = "{\"receipt-data\":\"" + value + "\",\"password\":\"x\",\"n\":[1,2.5,true,null]}";
                break;
            case 1:
                int depth = random.nextBoolean() ? 63 : 65; // the endpoint allows 64
                body = nested(depth) + "\"" + value + "\"" + closing(depth);
                break;
            case 2:
                body = "[\"" + value + "\"]";
                break;
            case 3:
                body = "{\"receipt-data\":\"" + value + "\"} trailing";
                break;
            default:
                body = "{\"receipt-data\":\"" + value + "\"}";
                break;
        }
        if (random.nextInt(8) == 0) {
            body = body.substring(0, random.nextInt(body.length()));
        }
        return body;
    }

    private static String nested(int depth) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            out.append("{\"a\":");
        }
        return out.toString();
    }

    private static String closing(int depth) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            out.append('}');
        }
        return out.toString();
    }
}
