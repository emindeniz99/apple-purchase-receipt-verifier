package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    /** The 0.6 read: databind over the same bounded factory. */
    private static final ObjectMapper MAPPER = new ObjectMapper(BoundedJson.factory(JwsCore.MAX_JWS_BYTES));

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
            outOfRange += expected.equals("out of range") ? 1 : 0;
        }
        assertTrue(dated > 500, "only " + dated + " payloads carried a usable signedDate");
        assertTrue(outOfRange > 50, "only " + outOfRange + " payloads carried an out-of-range signedDate");
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
        if (claim.canConvertToLong()) {
            return "object signedDate=" + claim.asLong();
        }
        if (claim.isNumber()) {
            return "out of range";
        }
        return "object signedDate=null";
    }

    private static String streamingPayload(byte[] bytes) throws Exception {
        try {
            JwsCore.Payload payload = JwsCore.Payload.read(bytes);
            if (payload.json == null) {
                return "unreadable";
            }
            assertEquals(new String(bytes, StandardCharsets.UTF_8), payload.json);
            return "object signedDate=" + payload.signedDate;
        } catch (VerificationException e) {
            assertEquals(Reason.UNTRUSTED_CHAIN, e.reason());
            return "out of range";
        }
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
