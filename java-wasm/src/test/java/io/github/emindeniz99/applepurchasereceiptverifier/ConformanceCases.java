package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Every vector in {@code fixtures/cases.json} through this artifact's public
 * API on one engine: the main artifact's conformance runner, with the one
 * difference that 0.7's internal decoders are not reachable here (see
 * {@link #decodeBase64Failures}). {@link ConformanceCasesTest} runs it on
 * Endive, {@link ServerConformanceCasesTest} on the server engine.
 *
 * <p>Each case is its own {@link DynamicTest} named by its case id, and a last
 * test asserts that every case id in the file ran. While the module is a
 * stand-in (the 0.6 core, {@link StandIn}), the cases it is known to answer
 * differently are listed per engine ({@link #standInFile()}): such a case
 * passes only if it still differs, and a listed case that starts passing
 * fails, so the list can only shrink. With any other module the list is
 * ignored and every case must pass.</p>
 */
abstract class ConformanceCases {

    /** The engine's name in the report lines. */
    abstract String engineName();

    /** A verifier on this engine for {@code config}. */
    abstract Verifier verifier(Config config) throws Exception;

    /** The listed stand-in differences, or none when the module is not the stand-in. */
    abstract Set<String> standInDifferences() throws Exception;

    /** The file {@link #standInDifferences()} reads. */
    abstract String standInFile();

    private static final ObjectMapper MAPPER = Cases.MAPPER;

    @TestFactory
    List<DynamicTest> conformanceCases() throws Exception {
        JsonNode document = Cases.document();
        Set<String> known = standInDifferences();
        List<DynamicTest> tests = new ArrayList<>();
        List<String> ids = new ArrayList<>();
        Set<String> ran = Collections.synchronizedSet(new TreeSet<String>());
        Set<String> differed = Collections.synchronizedSet(new TreeSet<String>());
        Set<String> failed = Collections.synchronizedSet(new TreeSet<String>());
        for (JsonNode kase : document.get("cases")) {
            String id = kase.get("id").asText();
            ids.add(id);
            tests.add(DynamicTest.dynamicTest(id, () -> {
                ran.add(id);
                Throwable failure = null;
                try {
                    runCase(kase);
                } catch (AssertionError | Exception e) {
                    failure = e;
                }
                if (known.contains(id)) {
                    if (failure == null) {
                        fail(id + ": listed in " + standInFile() + " but now passes; remove it from the list");
                    }
                    differed.add(id);
                    System.out.println("stand-in difference: " + oneLine(failure));
                } else if (failure instanceof AssertionError) {
                    failed.add(id);
                    throw (AssertionError) failure;
                } else if (failure != null) {
                    failed.add(id);
                    throw new AssertionError(id + ": the runner threw " + failure, failure);
                }
            }));
        }
        System.out.println("conformance (" + engineName() + "): " + ids.size() + " cases in fixtures/" + Cases.CASES
                + ", " + known.size() + " listed as stand-in differences");
        tests.add(DynamicTest.dynamicTest(Cases.CASES + " every case ran", () -> {
            List<String> missing = new ArrayList<>();
            for (String id : ids) {
                if (!ran.contains(id)) {
                    missing.add(id);
                }
            }
            assertTrue(
                    missing.isEmpty(),
                    missing.size() + " of " + ids.size() + " cases did not run: " + String.join(", ", missing));
            Set<String> unknown = new TreeSet<>(known);
            unknown.removeAll(ids);
            assertTrue(unknown.isEmpty(), standInFile() + " lists ids that are not cases: " + unknown);
            System.out.println("conformance (" + engineName() + ", Java " + Engine.javaFeatureVersion() + "): "
                    + ran.size() + " ran, "
                    + (ran.size() - differed.size() - failed.size()) + " passed, " + failed.size() + " failed, "
                    + differed.size() + " stand-in differences, 0 skipped");
        }));
        return tests;
    }

    private static String oneLine(Throwable failure) {
        String message = String.valueOf(failure.getMessage());
        int newline = message.indexOf('\n');
        message = newline < 0 ? message : message.substring(0, newline);
        return message.length() > 300 ? message.substring(0, 300) + "..." : message;
    }

    // Surefire reports a dynamic test by its index, so every message repeats the case id.
    private void runCase(JsonNode kase) throws Exception {
        String id = kase.get("id").asText();
        String operation = kase.get("operation").asText();
        JsonNode expected = kase.get("expected");
        if ("decodeBase64".equals(operation)) {
            List<String> failures = decodeBase64Failures(kase);
            assertTrue(failures.isEmpty(), String.join("\n", failures));
            return;
        }
        Verifier verifier = verifier(Cases.config(kase));
        JsonNode input = kase.get("input");
        if ("verifyReceiptEndpoint".equals(operation)) {
            Environment environment =
                    Environment.valueOf(kase.get("config").get("environment").asText());
            String body = input.has("requestBody")
                    ? Cases.text(Cases.fixtureBytes(input.get("requestBody").asText()))
                    : MAPPER.writeValueAsString(Collections.singletonMap("receipt-data", Cases.receiptString(input)));
            String response = verifier.verifyReceiptEndpoint(environment, body);
            assertTrue(expected.get("fields").has("/status"), id + ": harness error: /status not pinned");
            check(id, expected, parse(id, response));
            return;
        }
        final String argument;
        final boolean receipt;
        if ("verifyReceipt".equals(operation)) {
            argument = Cases.receiptString(input);
            receipt = true;
        } else if ("verifySignedData".equals(operation)) {
            argument = Cases.text(Cases.fixtureBytes(input.get("fixture").asText()));
            receipt = false;
        } else {
            throw new IllegalStateException(id + ": harness error: unknown operation " + operation);
        }
        if (kase.has("maxMillis")) {
            call(verifier, receipt, argument);
            long start = System.nanoTime();
            call(verifier, receipt, argument);
            long millis = (System.nanoTime() - start) / 1_000_000;
            long budget = kase.get("maxMillis").asLong();
            assertTrue(millis <= budget, id + ": verify took " + millis + " ms, budget " + budget + " ms");
        }
        if (expected.has("oneOf")) {
            VerificationResult<?> result;
            try {
                result = call(verifier, receipt, argument);
            } catch (RuntimeException | Error e) {
                throw new AssertionError(id + ": the operation threw instead of answering", e);
            }
            Failure failure = result.failure();
            String outcome = failure == null ? "ok" : failure.reason().name();
            List<String> allowed = new ArrayList<>();
            for (JsonNode listed : expected.get("oneOf")) {
                allowed.add(listed.asText());
            }
            assertTrue(
                    allowed.contains(outcome),
                    id + ": answered " + outcome + (failure == null ? "" : " (" + failure.message() + ")")
                            + ", want one of " + allowed);
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

    // ------------------------------------------------------------ decodeBase64

    /** Keeps the synthetic JWS header ASCII, so a text's own characters reach the core as JSON escapes. */
    private static final ObjectMapper ASCII_JSON =
            JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();

    private Verifier defaults;

    /**
     * A decodeBase64 case through the public API, since this artifact has no
     * decoder of its own to call: the base64 rule lives in the core. Each
     * receipt-data text goes to {@code verifyReceipt} as the whole input,
     * and each x5c text becomes all three {@code x5c} entries of a JWS whose
     * other parts are well formed, sent to {@code verifySignedData}. A
     * refusal by the rule is the decoder's reason (MALFORMED for receipt-data,
     * INVALID_CERTIFICATE for x5c) with a message about base64; an accepted
     * text must get any other answer, since the decoded bytes are neither a
     * receipt nor a certificate. Telling the two apart by the message is this
     * host's limit: the main artifact's messages say "is not canonically
     * padded standard base64" for exactly these refusals.
     */
    private List<String> decodeBase64Failures(JsonNode kase) throws Exception {
        String id = kase.get("id").asText();
        JsonNode expected = kase.get("expected");
        boolean ok = "ok".equals(expected.get("status").asText());
        if (!ok) {
            assertEquals("MALFORMED", expected.get("reason").asText(), id + ": harness error");
        }
        JsonNode texts = kase.get("input").get("texts");
        assertTrue(texts.size() > 0 && kase.get("decoders").size() > 0, id + ": harness error: no texts");
        Verifier verifier;
        synchronized (this) {
            if (defaults == null) {
                defaults = verifier(Config.defaults());
            }
            verifier = defaults;
        }
        List<String> failures = new ArrayList<>();
        for (JsonNode decoderName : kase.get("decoders")) {
            String name = decoderName.asText();
            for (int index = 0; index < texts.size(); index++) {
                String text = texts.get(index).asText();
                String where = id + ": " + name + " texts[" + index + "]";
                Failure failure;
                Reason refusal;
                if ("receipt-data".equals(name)) {
                    refusal = Reason.MALFORMED;
                    failure = verifier.verifyReceipt(text).failure();
                } else if ("x5c".equals(name)) {
                    refusal = Reason.INVALID_CERTIFICATE;
                    failure = verifier.verifySignedData(x5cJws(text)).failure();
                } else {
                    throw new IllegalStateException(id + ": harness error: no decoder " + name);
                }
                if (failure == null) {
                    failures.add(where + " verified, which no decoded text can");
                    continue;
                }
                boolean refused =
                        failure.reason() == refusal && failure.message().contains("base64");
                if (ok && refused) {
                    failures.add(where + " was refused by the base64 rule: " + failure);
                } else if (!ok && !refused) {
                    failures.add(where + " was not refused by the base64 rule: " + failure);
                }
            }
        }
        return failures;
    }

    /** A compact JWS with ES256, three copies of {@code entry} as x5c, an empty payload and a zero signature. */
    private static String x5cJws(String entry) throws Exception {
        Map<String, Object> header = new java.util.LinkedHashMap<>();
        header.put("alg", "ES256");
        List<String> x5c = new ArrayList<>();
        Collections.addAll(x5c, entry, entry, entry);
        header.put("x5c", x5c);
        Base64.Encoder url = Base64.getUrlEncoder().withoutPadding();
        return url.encodeToString(ASCII_JSON.writeValueAsBytes(header)) + "."
                + url.encodeToString("{}".getBytes(StandardCharsets.US_ASCII)) + "."
                + url.encodeToString(new byte[64]);
    }

    // ------------------------------------------------------------- expectations

    private static JsonNode parse(String id, String json) {
        try {
            return MAPPER.reader()
                    .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .readTree(json);
        } catch (Exception e) {
            throw new AssertionError(id + ": the library returned JSON that does not parse: " + json, e);
        }
    }

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

    /** An RFC 6901 pointer plus the {@code [key=value]} selector of cases.json. */
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
