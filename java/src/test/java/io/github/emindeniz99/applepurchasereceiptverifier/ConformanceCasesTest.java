package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Runs every vector in {@code fixtures/cases-0.7.json}, the normative
 * cross-language conformance set for the 0.7 API, through the three public
 * {@link Verifier} methods and the two base64 decoders.
 *
 * <p>This adapter carries no knowledge of any individual case. It resolves a
 * fixture id to bytes, builds a {@link Config} from the case's trusted roots
 * and clock, dispatches on {@code operation}, and evaluates the expectation
 * on the JSON the library returns: {@link ReceiptPayload#toJson()},
 * {@link JsonPayload#json()} or the endpoint's response body. A case is added
 * by editing cases-0.7.json, never this file. The file's top-level
 * {@code comment} defines the semantics implemented here.</p>
 *
 * <p>Each case is its own {@link DynamicTest}, named by its case id, so a
 * failure names the vector that broke (java-distroless greps for one by
 * name).</p>
 *
 * <p>Every fixture the adapter loads is checked against the
 * {@code contentSha256} the registry records for it, over the decoded bytes,
 * so fixture bytes and the registry cannot drift apart unnoticed.</p>
 */
class ConformanceCasesTest {

    private static final Path FIXTURES = TestFixtures.root();
    private static final String CASES = "cases-0.7.json";

    // Big decimals for fractions and exact integers, so a pinned value
    // compares without rounding (the endpoint's download_id is 2^63-1).
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);

    private static JsonNode document() throws Exception {
        JsonNode document = MAPPER.readTree(FIXTURES.resolve(CASES).toFile());
        assertEquals(2, document.get("schemaVersion").asInt(), CASES + " schemaVersion");
        return document;
    }

    @TestFactory
    List<DynamicTest> conformanceCases() throws Exception {
        JsonNode document = document();
        final JsonNode fixtures = document.get("fixtures");
        List<DynamicTest> tests = new ArrayList<DynamicTest>();
        final List<String> ids = new ArrayList<String>();
        final Set<String> ran = Collections.synchronizedSet(new HashSet<String>());
        int pinned = 0;
        for (JsonNode node : document.get("cases")) {
            final JsonNode kase = node;
            if (kase.has("clock")) {
                pinned++;
            }
            final String id = kase.get("id").asText();
            ids.add(id);
            tests.add(DynamicTest.dynamicTest(id, () -> {
                ran.add(id);
                runCase(fixtures, kase);
            }));
        }
        System.out.println("conformance: " + tests.size() + " cases in fixtures/" + CASES + ", " + pinned
                + " with a pinned clock, 0 skipped");
        // Coverage self-check, last in the list and so run after every case:
        // each case id in the parsed file ran, compared against the file and
        // never against a literal count, so a case this factory stopped
        // reaching fails here. A run that selects individual dynamic tests
        // does not select this one, so a filtered run needs no stand-down.
        tests.add(DynamicTest.dynamicTest(CASES + " every case ran", () -> {
            List<String> missing = new ArrayList<String>();
            for (String id : ids) {
                if (!ran.contains(id)) {
                    missing.add(id);
                }
            }
            assertTrue(
                    missing.isEmpty(),
                    missing.size() + " of " + ids.size() + " cases did not run: " + String.join(", ", missing));
        }));
        return tests;
    }

    // Surefire reports a dynamic test by its index, not its display name, so
    // every message repeats the case id; otherwise a CI log names no vector.
    private static void runCase(JsonNode fixtures, JsonNode kase) throws Exception {
        String id = kase.get("id").asText();
        String operation = kase.get("operation").asText();
        JsonNode expected = kase.get("expected");
        if ("decodeBase64".equals(operation)) {
            List<String> failures = decodeBase64Failures(kase);
            assertTrue(failures.isEmpty(), String.join("\n", failures));
            return;
        }
        Verifier verifier = Verifier.create(config(fixtures, kase));
        JsonNode input = kase.get("input");
        if ("verifyReceiptEndpoint".equals(operation)) {
            Environment environment =
                    Environment.valueOf(kase.get("config").get("environment").asText());
            String body = input.has("requestBody")
                    ? text(fixtureBytes(fixtures, input.get("requestBody").asText()))
                    : MAPPER.writeValueAsString(
                            Collections.singletonMap("receipt-data", receiptString(fixtures, input)));
            String response = verifier.verifyReceiptEndpoint(environment, body);
            assertTrue(expected.get("fields").has("/status"), id + ": harness error: /status not pinned");
            check(id, expected, parse(id, response));
            return;
        }
        final String argument;
        final boolean receipt;
        if ("verifyReceipt".equals(operation)) {
            argument = receiptString(fixtures, input);
            receipt = true;
        } else if ("verifySignedData".equals(operation)) {
            argument = text(fixtureBytes(fixtures, input.get("fixture").asText()));
            receipt = false;
        } else {
            throw new IllegalStateException(id + ": harness error: unknown operation " + operation);
        }
        // A maxMillis budget (the DoS cases): one warm-up call of the same
        // case, then the timed call. An honest verify never parses the
        // untrusted key and finishes in a few milliseconds; an implementation
        // that decodes or verifies with the oversized key first spends seconds.
        if (kase.has("maxMillis")) {
            call(verifier, receipt, argument);
            long start = System.nanoTime();
            call(verifier, receipt, argument);
            long millis = (System.nanoTime() - start) / 1_000_000;
            long budget = kase.get("maxMillis").asLong();
            assertTrue(millis <= budget, id + ": verify took " + millis + " ms, budget " + budget + " ms");
        }
        // A tolerant case: any verdict but INTERNAL_ERROR, and nothing thrown.
        if (expected.has("anyOutcome")) {
            VerificationResult<?> result;
            try {
                result = call(verifier, receipt, argument);
            } catch (RuntimeException | Error e) {
                throw new AssertionError(id + ": the operation threw instead of answering", e);
            }
            Failure failure = result.failure();
            if (failure != null) {
                assertTrue(
                        failure.reason() != Reason.INTERNAL_ERROR,
                        id + ": answered INTERNAL_ERROR: " + failure.message());
            }
            return;
        }
        VerificationResult<?> result = call(verifier, receipt, argument);
        String status = expected.get("status").asText();
        if ("error".equals(status)) {
            Failure failure = result.failure();
            if (failure == null) {
                fail(id + ": expected " + expected.get("reason").asText() + " but the operation verified");
            }
            assertEquals(expected.get("reason").asText(), failure.reason().name(), id + ": " + failure.message());
            if (expected.has("messageMustNotContain")) {
                String message = failure.message();
                for (JsonNode codePoint : expected.get("messageMustNotContain")) {
                    int cp = codePoint.asInt();
                    assertTrue(
                            message.indexOf(cp) < 0,
                            id + ": the failure message contains U+" + String.format("%04X", cp) + ": "
                                    + message.replaceAll("\\p{Cntrl}", "?"));
                }
            }
            return;
        }
        assertEquals("ok", status, id + ": harness error: unknown status");
        Object payload = result.payload();
        if (payload == null) {
            Failure failure = result.failure();
            fail(id + ": expected ok but failed with " + failure.reason() + ": " + failure.message());
        }
        String json;
        if (payload instanceof ReceiptPayload) {
            json = ((ReceiptPayload) payload).toJson();
            if (expected.has("toJson")) {
                // Same value, not same bytes: whitespace, key order and
                // escaping are free (docs/design/0.7-api.md "Our JSON").
                assertEquals(parse(id, expected.get("toJson").asText()), parse(id, json), id + ": toJson value");
            }
        } else {
            json = ((JsonPayload) payload).json();
        }
        check(id, expected, parse(id, json));
    }

    private static VerificationResult<?> call(Verifier verifier, boolean receipt, String argument) {
        return receipt ? verifier.verifyReceipt(argument) : verifier.verifySignedData(argument);
    }

    // ------------------------------------------------------------ inputs

    /**
     * The config the case names: its trusted roots, and a clock fixed at
     * {@code clock.now} when it pins one, else the default clock.
     */
    private static Config config(JsonNode fixtures, JsonNode kase) throws Exception {
        JsonNode roots = kase.get("config").get("trustedRoots");
        Config.Builder builder = Config.builder();
        String source = roots.get("source").asText();
        if ("fixtures".equals(source)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificates = new ArrayList<X509Certificate>();
            for (JsonNode id : roots.get("fixtures")) {
                certificates.add((X509Certificate)
                        factory.generateCertificate(new ByteArrayInputStream(fixtureBytes(fixtures, id.asText()))));
            }
            builder.roots(certificates);
        } else if (!"defaults".equals(source)) {
            throw new IllegalStateException("harness error: unknown trustedRoots source " + source);
        }
        if (kase.has("clock")) {
            builder.clock(Clock.fixed(Instant.parse(kase.get("clock").get("now").asText()), ZoneOffset.UTC));
        }
        return builder.build();
    }

    /**
     * The string verifyReceipt gets, and the endpoint's receipt-data: a text
     * fixture verbatim, exactly as a client sent it; any other fixture holds
     * DER, encoded as canonical base64.
     */
    private static String receiptString(JsonNode fixtures, JsonNode input) throws Exception {
        String id = input.get("fixture").asText();
        byte[] bytes = fixtureBytes(fixtures, id);
        String codec = fixtures.get(id).get("codec").asText();
        return "text".equals(codec) ? text(bytes) : Base64.getEncoder().encodeToString(bytes);
    }

    // ------------------------------------------------------------ decodeBase64

    /**
     * Every text of a decodeBase64 group that got the wrong answer from a
     * decoder the group names, by case id, decoder, index and escaped text,
     * rather than stopping at the first. receipt-data refuses with
     * MALFORMED and x5c with INVALID_CERTIFICATE; an error group states
     * MALFORMED and is mapped here for x5c.
     */
    private static List<String> decodeBase64Failures(JsonNode kase) {
        String id = kase.get("id").asText();
        JsonNode expected = kase.get("expected");
        boolean ok = "ok".equals(expected.get("status").asText());
        if (!ok) {
            assertEquals("MALFORMED", expected.get("reason").asText(), id + ": harness error");
        }
        String want = ok ? expected.get("bytesHex").asText() : "";
        JsonNode texts = kase.get("input").get("texts");
        assertTrue(texts.size() > 0 && kase.get("decoders").size() > 0, id + ": harness error: no texts");
        List<String> failures = new ArrayList<String>();
        for (JsonNode decoderName : kase.get("decoders")) {
            String name = decoderName.asText();
            Reason refusal;
            if ("receipt-data".equals(name)) {
                refusal = Reason.MALFORMED;
            } else if ("x5c".equals(name)) {
                refusal = Reason.INVALID_CERTIFICATE;
            } else {
                throw new IllegalStateException(id + ": harness error: no decoder " + name);
            }
            for (int index = 0; index < texts.size(); index++) {
                String text = texts.get(index).asText();
                String where = id + ": " + name + " texts[" + index + "] " + escape(text);
                String decoded;
                try {
                    decoded = hex("x5c".equals(name) ? JwsCore.decodeX5cEntry(text) : ReceiptBase64.decode(text));
                } catch (VerificationException e) {
                    if (ok) {
                        failures.add(where + " was refused (" + e.reason() + "), want " + want);
                    } else if (e.reason() != refusal) {
                        failures.add(where + ": reason " + e.reason() + ", want " + refusal);
                    }
                    continue;
                } catch (RuntimeException e) {
                    failures.add(where + ": harness error: threw " + e);
                    continue;
                }
                if (!ok) {
                    failures.add(where + " was accepted (decoded to " + decoded + ")");
                } else if (!decoded.equals(want)) {
                    failures.add(where + " decoded to " + decoded + ", want " + want);
                }
            }
        }
        return failures;
    }

    /** A text as a quoted literal with every non-printable-ASCII character escaped. */
    private static String escape(String text) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c > 0x7e) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.append('"').toString();
    }

    // ---------------------------------------------------------------- fixtures

    /**
     * Every fixture in the registry hashes to the {@code contentSha256} it
     * declares. {@link #fixtureBytes} checks the ones the cases load; this
     * walks the whole registry, so a fixture that drifted while no case
     * reaches it is still caught.
     */
    @Test
    void everyFixtureMatchesItsRecordedContentDigest() throws Exception {
        JsonNode fixtures = document().get("fixtures");
        int checked = 0;
        Iterator<String> ids = fixtures.fieldNames();
        while (ids.hasNext()) {
            fixtureBytes(fixtures, ids.next());
            checked++;
        }
        assertTrue(checked > 0, CASES + " declares no fixtures");
        System.out.println("conformance: " + checked + " fixture content digests verified against " + CASES);
    }

    /**
     * A fixture id to its logical bytes, per the registry's {@code codec},
     * and only after those bytes hash to the {@code contentSha256} the
     * registry records: raw and text are the file verbatim, utf8 the UTF-8 of
     * the trimmed text, base64 the decoded text with whitespace stripped.
     */
    private static byte[] fixtureBytes(JsonNode fixtures, String id) throws Exception {
        JsonNode fixture = fixtures.get(id);
        if (fixture == null) {
            throw new IllegalStateException(CASES + " declares no fixture " + id);
        }
        byte[] stored = Files.readAllBytes(FIXTURES.resolve(fixture.get("path").asText()));
        String codec = fixture.get("codec").asText();
        byte[] decoded;
        if ("raw".equals(codec) || "text".equals(codec)) {
            // text is untrimmed, unlike utf8: a registered fixture may be
            // 0 bytes or carry CRLF, and both must survive as stored.
            decoded = stored;
        } else {
            String text = new String(stored, StandardCharsets.UTF_8).trim();
            if ("utf8".equals(codec)) {
                decoded = text.getBytes(StandardCharsets.UTF_8);
            } else if ("base64".equals(codec)) {
                decoded = Base64.getMimeDecoder().decode(text);
            } else {
                throw new IllegalStateException("unknown codec " + codec + " on fixture " + id);
            }
        }
        String expected = fixture.get("contentSha256").asText();
        String actual = hex(MessageDigest.getInstance("SHA-256").digest(decoded));
        if (!expected.equals(actual)) {
            throw new AssertionError(
                    "fixture " + id + " (" + fixture.get("path").asText() + ", codec " + codec + ") hashes to " + actual
                            + " but " + CASES + " records " + expected);
        }
        return decoded;
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

    // ------------------------------------------------------------- expectations

    private static JsonNode parse(String id, String json) {
        try {
            // Strict: trailing content after the value fails, which a plain
            // readTree would ignore, so a port that appended to its output
            // cannot pass.
            return MAPPER.reader()
                    .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .readTree(json);
        } catch (Exception e) {
            throw new AssertionError(id + ": the library returned JSON that does not parse: " + json, e);
        }
    }

    /** {@code fields} and {@code lengths}: only the listed pointers are pinned. */
    private static void check(String id, JsonNode expected, JsonNode actual) {
        if (expected.has("fields")) {
            Iterator<Map.Entry<String, JsonNode>> fields =
                    expected.get("fields").fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String where = id + " " + field.getKey();
                assertValue(where, field.getValue(), resolve(where, actual, field.getKey()));
            }
        }
        if (expected.has("lengths")) {
            Iterator<Map.Entry<String, JsonNode>> lengths =
                    expected.get("lengths").fields();
            while (lengths.hasNext()) {
                Map.Entry<String, JsonNode> length = lengths.next();
                String where = id + " " + length.getKey();
                JsonNode array = resolve(where, actual, length.getKey());
                assertTrue(array != null && array.isArray(), where + ": expected an array but got " + array);
                assertEquals(length.getValue().asInt(), array.size(), where + " length");
            }
        }
    }

    /** null means absent or JSON null; numbers compare by value, exactly. */
    private static void assertValue(String where, JsonNode expected, JsonNode actual) {
        if (expected.isNull()) {
            assertTrue(actual == null || actual.isNull(), where + ": expected absent or null but got " + actual);
        } else if (expected.isNumber()) {
            assertTrue(
                    actual != null && actual.isNumber(),
                    where + ": expected the number " + expected + " but got " + actual);
            assertTrue(
                    expected.decimalValue().compareTo(actual.decimalValue()) == 0,
                    where + ": expected " + expected + " but got " + actual);
        } else if (expected.isBoolean()) {
            assertTrue(
                    actual != null && actual.isBoolean() && actual.booleanValue() == expected.booleanValue(),
                    where + ": expected " + expected + " but got " + actual);
        } else {
            assertTrue(
                    actual != null && actual.isTextual(),
                    where + ": expected the string " + expected + " but got " + actual);
            assertEquals(expected.textValue(), actual.textValue(), where);
        }
    }

    /**
     * An RFC 6901 pointer, plus the one extension: a token {@code [key=value]}
     * selects the single array element whose member {@code key} is the JSON
     * string {@code value}, and fails unless exactly one matches. Null when
     * the pointer leads nowhere.
     */
    private static JsonNode resolve(String where, JsonNode root, String pointer) {
        if (!pointer.startsWith("/")) {
            throw new IllegalStateException(where + ": harness error: not a pointer");
        }
        JsonNode current = root;
        for (String raw : pointer.substring(1).split("/", -1)) {
            if (current == null) {
                return null;
            }
            String token = raw.replace("~1", "/").replace("~0", "~");
            if (raw.startsWith("[") && raw.endsWith("]") && raw.indexOf('=') > 0) {
                int equals = raw.indexOf('=');
                String key = raw.substring(1, equals);
                String value = raw.substring(equals + 1, raw.length() - 1);
                assertTrue(current.isArray(), where + ": " + raw + " needs an array, got " + current);
                JsonNode match = null;
                int matches = 0;
                for (JsonNode element : current) {
                    JsonNode member = element.get(key);
                    if (member != null && member.isTextual() && value.equals(member.textValue())) {
                        match = element;
                        matches++;
                    }
                }
                assertEquals(1, matches, where + ": elements matching " + raw);
                current = match;
            } else if (current.isArray()) {
                current = token.matches("0|[1-9][0-9]*") ? current.get(Integer.parseInt(token)) : null;
            } else if (current.isObject()) {
                current = current.get(token);
            } else {
                return null;
            }
        }
        return current;
    }
}
