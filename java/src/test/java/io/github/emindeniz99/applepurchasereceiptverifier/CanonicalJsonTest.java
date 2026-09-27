package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@code toJson()} is compared byte for byte across ports, and against
 * {@code JSON.stringify}; equality has to agree with it.
 */
class CanonicalJsonTest {

    private static String quote(String value) {
        StringBuilder out = new StringBuilder();
        CanonicalJson.quote(out, value);
        return out.toString();
    }

    @Test
    void aLoneSurrogateIsEscapedAsJsonStringifyEscapesIt() {
        // A pair is one character and is written raw; either half alone is
        // no character UTF-8 can carry, and JSON.stringify escapes it.
        assertEquals("\"\uD83D\uDE00\"", quote("\uD83D\uDE00"));
        assertEquals("\"a\\ud83d\"", quote("a\uD83D"));
        assertEquals("\"\\ude00b\"", quote("\uDE00b"));
        assertEquals("\"\\ude00\\ud83d\"", quote("\uDE00\uD83D"));
    }

    @Test
    void unknownAttributesAreEqualExactlyWhenTheirJsonIs() {
        // toJson() writes the types sorted, so the order they were collected
        // in is not part of the value; each type's own list order is.
        Map<Integer, List<byte[]>> ascending = new LinkedHashMap<Integer, List<byte[]>>();
        ascending.put(9, Collections.singletonList(new byte[] {1}));
        ascending.put(13, Arrays.asList(new byte[] {2}, new byte[] {3}));
        Map<Integer, List<byte[]>> descending = new LinkedHashMap<Integer, List<byte[]>>();
        descending.put(13, Arrays.asList(new byte[] {2}, new byte[] {3}));
        descending.put(9, Collections.singletonList(new byte[] {1}));
        Map<Integer, List<byte[]>> reordered = new LinkedHashMap<Integer, List<byte[]>>();
        reordered.put(9, Collections.singletonList(new byte[] {1}));
        reordered.put(13, Arrays.asList(new byte[] {3}, new byte[] {2}));

        assertEquals(json(ascending), json(descending));
        assertEquals(purchase(ascending), purchase(descending));
        assertEquals(purchase(ascending).hashCode(), purchase(descending).hashCode());
        assertFalse(json(ascending).equals(json(reordered)));
        assertFalse(purchase(ascending).equals(purchase(reordered)));
    }

    private static InAppPurchase purchase(Map<Integer, List<byte[]>> unknown) {
        return new InAppPurchase(null, null, null, null, null, null, null, null, null, null, null, unknown);
    }

    private static String json(Map<Integer, List<byte[]>> attributes) {
        StringBuilder out = new StringBuilder();
        CanonicalJson.object(out).attributes("unknown", attributes).end();
        return out.toString();
    }
}
