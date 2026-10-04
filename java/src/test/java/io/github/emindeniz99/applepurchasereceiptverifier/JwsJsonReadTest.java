package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * {@link JwsCore} reads the JWS header and payload with jackson-core's
 * streaming parser. 0.6 read both into a databind tree and asked the tree,
 * so dropping databind is safe only if the streaming read reaches the same
 * answer for every segment: whether the header is a JSON object, its last
 * {@code alg} and {@code x5c}, whether the payload is a JSON object, and its
 * top-level {@code signedDate} under the tree's number conversions (a
 * fraction truncated, a number no long holds refused). Checked here against
 * databind itself, still on the test classpath, over the same bounded
 * factory.
 */
class JwsJsonReadTest {

    private static final long SEED = 0x0715_EEDL;
    private static final int CASES = 20_000;

    /**
     * The 0.6 read: databind over the same bounded factory, with the one
     * rule 0.7 added: nothing but whitespace after the object. Without it
     * {@code {"alg":"ES256"} x} is a header, and a payload with text after
     * its object returns verified with that text in it.
     */
    private static final ObjectMapper MAPPER = new ObjectMapper(BoundedJson.factory(JwsCore.MAX_JWS_BYTES))
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    @Test
    void readsEveryHeaderAsTheDatabindTreeDid() {
        Random random = new Random(SEED);
        int objects = 0;
        int es256 = 0;
        int threeCertificates = 0;
        for (int i = 0; i < CASES; i++) {
            byte[] header = generate(random, "alg", "x5c").getBytes(StandardCharsets.UTF_8);
            String expected = treeHeader(header);
            assertEquals(expected, streamingHeader(header), new String(header, StandardCharsets.UTF_8));
            objects += expected.startsWith("object") ? 1 : 0;
            es256 += expected.contains("alg=ES256") ? 1 : 0;
            threeCertificates += expected.contains("x5c=[a, b, c]") ? 1 : 0;
        }
        assertTrue(objects > CASES / 4, "only " + objects + " headers were objects");
        assertTrue(es256 > 500, "only " + es256 + " headers said ES256");
        assertTrue(threeCertificates > 500, "only " + threeCertificates + " headers carried three certificates");
    }

    @Test
    void readsEveryPayloadAsTheDatabindTreeDid() throws Exception {
        Random random = new Random(SEED + 1);
        int dated = 0;
        int outOfRange = 0;
        for (int i = 0; i < CASES; i++) {
            byte[] payload =
                    generate(random, "signedDate", "receiptCreationDate").getBytes(StandardCharsets.UTF_8);
            if (payload.length > 0 && random.nextInt(50) == 0) {
                // A byte that starts a two-byte UTF-8 sequence, dropped
                // anywhere: invalid UTF-8 in a string or a stray byte outside.
                payload[random.nextInt(payload.length)] = (byte) 0xC3;
            }
            String expected = treePayload(payload);
            assertEquals(expected, streamingPayload(payload), new String(payload, StandardCharsets.UTF_8));
            dated += expected.startsWith("object signedDate=") && !expected.endsWith("null") ? 1 : 0;
            outOfRange += outOfRangeDate(payload) ? 1 : 0;
        }
        assertTrue(dated > 500, "only " + dated + " payloads carried a usable signedDate");
        assertTrue(outOfRange > 50, "only " + outOfRange + " payloads carried an out-of-range signedDate");
    }

    /**
     * The header is read as strict UTF-8 before any JSON: Jackson on bytes
     * would detect UTF-16 and UTF-32 and skip a byte order mark, giving one
     * header several accepted encodings. RFC 7515 and RFC 8259 allow one.
     */
    @Test
    void aHeaderIsStrictUtf8WithNoByteOrderMarkAndNothingAfterIt() throws Exception {
        String header = "{\"alg\":\"ES256\"}";
        assertEquals("ES256", JwsCore.Header.read(utf8(header + " \r\n\t")).alg);
        byte[][] refused = {
            header.getBytes(StandardCharsets.UTF_16LE),
            header.getBytes(StandardCharsets.UTF_16BE),
            concat(new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF}, utf8(header)),
            concat(utf8(header), new byte[] {' ', (byte) 0xFF}),
            utf8(header + " x"),
            utf8(header + "{}"),
        };
        for (byte[] bytes : refused) {
            VerificationException thrown = assertThrows(VerificationException.class, () -> JwsCore.Header.read(bytes));
            assertEquals(Reason.MALFORMED, thrown.reason());
        }
    }

    /** A payload with anything after its object is not the object: carried to the signature as unreadable. */
    @Test
    void aPayloadWithTextAfterItsObjectOrAByteOrderMarkIsUnreadable() throws Exception {
        assertEquals(Long.valueOf(1), JwsCore.readPayload(utf8("{\"signedDate\":1} \n")).signedDate);
        for (byte[] bytes : new byte[][] {
            utf8("{\"signedDate\":1} x"), utf8("{\"signedDate\":1}{}"), utf8("\uFEFF{\"signedDate\":1}"),
        }) {
            VerificationException thrown = assertThrows(VerificationException.class, () -> JwsCore.readPayload(bytes));
            assertEquals(Reason.UNREADABLE_PAYLOAD, thrown.reason(), new String(bytes, StandardCharsets.UTF_8));
        }
    }

    /**
     * The three places Apple documents for a payload's environment, the first
     * present one deciding: the same table as the core's
     * (rust/src/jws.rs, DECISIONS.md R42), so the two read it alike.
     */
    @Test
    void theEnvironmentIsReadFromTheFirstOfThreePlaces() throws Exception {
        Environment production = Environment.PRODUCTION;
        Environment sandbox = Environment.SANDBOX;
        Object[][] table = {
            {"{\"environment\":\"Production\"}", production},
            {"{\"environment\":\"Sandbox\",\"signedDate\":1}", sandbox},
            {"{\"data\":{\"environment\":\"Sandbox\"}}", sandbox},
            {"{\"summary\":{\"environment\":\"Production\"}}", production},
            // The first present one decides, whatever it says.
            {"{\"environment\":\"Xcode\",\"data\":{\"environment\":\"Sandbox\"}}", null},
            {"{\"environment\":null,\"data\":{\"environment\":\"Sandbox\"}}", null},
            {"{\"data\":{\"environment\":1},\"summary\":{\"environment\":\"Sandbox\"}}", null},
            {"{\"summary\":{\"environment\":\"Sandbox\"},\"data\":{\"environment\":\"Production\"}}", production},
            // Absent from a container that is there: the next one decides.
            {"{\"data\":{},\"summary\":{\"environment\":\"Sandbox\"}}", sandbox},
            {"{\"data\":\"Sandbox\",\"summary\":{\"environment\":\"Sandbox\"}}", sandbox},
            // Anything but the two spellings is no environment.
            {"{\"environment\":\"LocalTesting\"}", null},
            {"{\"environment\":\"sandbox\"}", null},
            {"{\"environment\":\"ProductionSandbox\"}", null},
            {"{\"data\":{\"data\":{\"environment\":\"Sandbox\"}}}", null},
            {"{\"transaction\":{\"environment\":\"Sandbox\"}}", null},
            {"{}", null},
            // A repeated name keeps its last value, a container included.
            {"{\"environment\":\"Sandbox\",\"environment\":\"Production\"}", production},
            {"{\"data\":{\"environment\":\"Production\"},\"data\":{}}", null},
            // Nested values inside a container are skipped whole.
            {"{\"data\":{\"renewalInfo\":{\"environment\":\"Production\"},\"environment\":\"Sandbox\"}}", sandbox},
        };
        for (Object[] row : table) {
            String json = (String) row[0];
            assertEquals(row[1], JwsCore.readPayload(utf8(json)).environment(), json);
        }
        VerificationException unreadable =
                assertThrows(VerificationException.class, () -> JwsCore.readPayload(utf8("not json")));
        assertEquals(Reason.UNREADABLE_PAYLOAD, unreadable.reason());
    }

    /** The reader bounds are stated, not inherited from whichever Jackson the host resolved. */
    @Test
    void memberNamesAndNumbersAreBounded() throws Exception {
        String longestName = repeat('n', BoundedJson.MAX_NAME_LENGTH);
        String longestNumber = repeat('1', BoundedJson.MAX_NUMBER_LENGTH);
        assertNull(JwsCore.Header.read(utf8("{\"" + longestName + "\":1}")).alg);
        assertNull(JwsCore.Header.read(utf8("{\"n\":" + longestNumber + "}")).alg);
        for (String header : new String[] {"{\"" + longestName + "n\":1}", "{\"n\":" + longestNumber + "1}"}) {
            VerificationException thrown =
                    assertThrows(VerificationException.class, () -> JwsCore.Header.read(utf8(header)));
            assertTrue(thrown.getCause() instanceof StreamConstraintsException, String.valueOf(thrown.getCause()));
        }
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        java.util.Arrays.fill(chars, c);
        return new String(chars);
    }

    /** Whether the payload's signedDate is a number no long holds, which both reads treat as absent. */
    private static boolean outOfRangeDate(byte[] bytes) {
        try {
            JsonNode claim = MAPPER.readTree(bytes).path("signedDate");
            return claim.isNumber() && !claim.canConvertToLong();
        } catch (Exception e) {
            return false;
        }
    }

    private static String treeHeader(byte[] bytes) {
        JsonNode tree;
        try {
            tree = MAPPER.readTree(bytes);
        } catch (Exception e) {
            return "malformed";
        }
        if (tree == null || !tree.isObject()) {
            return "malformed";
        }
        JsonNode alg = tree.path("alg");
        JsonNode x5c = tree.path("x5c");
        List<String> entries = null;
        if (x5c.isArray()) {
            entries = new ArrayList<String>();
            for (JsonNode entry : x5c) {
                if (!entry.isTextual()) {
                    entries = null;
                    break;
                }
                entries.add(entry.asText());
            }
        }
        return "object alg=" + (alg.isTextual() ? alg.asText() : null) + " x5c=" + entries;
    }

    private static String streamingHeader(byte[] bytes) {
        try {
            JwsCore.Header header = JwsCore.Header.read(bytes);
            return "object alg=" + header.alg + " x5c=" + header.x5c;
        } catch (VerificationException e) {
            assertEquals(Reason.MALFORMED, e.reason());
            return "malformed";
        }
    }

    /**
     * 0.6's instantClaim, on signedDate alone: 0.7 dropped the
     * receiptCreationDate fallback. One deliberate difference first: 0.7
     * returns the payload as text, so bytes that are not UTF-8 are
     * unreadable even where 0.6's tree never reached them (after the
     * object's closing brace).
     */
    private static String treePayload(byte[] bytes) {
        try {
            StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes));
        } catch (java.nio.charset.CharacterCodingException e) {
            return "unreadable";
        }
        JsonNode tree;
        try {
            tree = MAPPER.readTree(bytes);
        } catch (Exception e) {
            return "unreadable";
        }
        if (tree == null || !tree.isObject()) {
            return "unreadable";
        }
        JsonNode claim = tree.path("signedDate");
        // A number no long holds (1e300) counts as not stated, like a string.
        if (claim.canConvertToLong()) {
            return "object signedDate=" + claim.asLong();
        }
        return "object signedDate=null";
    }

    private static String streamingPayload(byte[] bytes) throws Exception {
        JwsCore.Payload read;
        try {
            read = JwsCore.readPayload(bytes);
        } catch (VerificationException e) {
            return "unreadable";
        }
        return "object signedDate=" + read.signedDate;
    }

    /**
     * A JSON text that is mostly an object carrying the two named members,
     * repeated, nested, of every type, with numbers of every spelling, and
     * sometimes broken: truncated, trailing garbage, not an object at all,
     * nested past the depth limit.
     */
    private static String generate(Random random, String first, String second) {
        StringBuilder out = new StringBuilder();
        switch (random.nextInt(12)) {
            case 0:
                out.append(value(random, 0));
                break;
            case 1:
                out.append(nested(random.nextBoolean() ? 63 : 65));
                break;
            default:
                out.append('{');
                int members = random.nextInt(5);
                for (int m = 0; m < members; m++) {
                    if (m > 0) {
                        out.append(',');
                    }
                    int pick = random.nextInt(5);
                    String name = pick == 0 ? first : pick == 1 ? second : pick == 2 ? "other" : first;
                    out.append('"').append(name).append("\":");
                    out.append(pick == 2 ? value(random, 0) : member(random, name));
                }
                out.append('}');
                break;
        }
        String text = out.toString();
        int damage = random.nextInt(20);
        if (damage == 0 && !text.isEmpty()) {
            text = text.substring(0, random.nextInt(text.length()));
        } else if (damage == 1) {
            text = text + (random.nextBoolean() ? " trailing" : "}");
        } else if (damage == 2) {
            text = " \n" + text + " ";
        }
        return text;
    }

    /** A value for {@code alg}, {@code x5c} or {@code signedDate}, shaped to hit their cases. */
    private static String member(Random random, String name) {
        if (name.equals("alg")) {
            switch (random.nextInt(4)) {
                case 0:
                    return "\"ES256\"";
                case 1:
                    return "\"RS256\"";
                default:
                    return value(random, 0);
            }
        }
        if (name.equals("x5c")) {
            switch (random.nextInt(4)) {
                case 0:
                    return "[\"a\",\"b\",\"c\"]";
                case 1:
                    return "[\"a\",1,\"c\"]";
                case 2:
                    return "[\"a\",[\"b\"],\"c\"]";
                default:
                    return value(random, 0);
            }
        }
        return number(random);
    }

    private static String number(Random random) {
        String[] spellings = {
            "1722945600000",
            "-1722945600000",
            "0",
            "-0",
            "1722945600000.0",
            "1722945600000.9",
            "1.7229456E12",
            "1.7229456e+12",
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775808",
            "-9223372036854775809",
            "92233720368547758070",
            "9.3e18",
            "9.2e18",
            "1e300",
            "-1e300",
            "1e400",
            "\"1722945600000\"",
            "null",
            "true",
            "{\"signedDate\":1}",
            "[1722945600000]",
        };
        return spellings[random.nextInt(spellings.length)];
    }

    private static String value(Random random, int depth) {
        switch (random.nextInt(depth > 3 ? 4 : 6)) {
            case 0:
                return number(random);
            case 1:
                return "\"s\\u00e9\\n\"";
            case 2:
                return "null";
            case 3:
                return "é";
            case 4:
                return "[" + value(random, depth + 1) + "," + value(random, depth + 1) + "]";
            default:
                return "{\"k\":" + value(random, depth + 1) + "}";
        }
    }

    private static String nested(int depth) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            out.append("{\"a\":");
        }
        out.append('1');
        for (int i = 0; i < depth; i++) {
            out.append('}');
        }
        return out.toString();
    }
}
