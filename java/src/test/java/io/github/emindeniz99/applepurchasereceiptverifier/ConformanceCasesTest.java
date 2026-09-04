package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.InAppPurchase;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Runs every vector in {@code fixtures/cases.json} — the normative
 * cross-language conformance set that java, node, python and swift all
 * answer identically.
 *
 * <p>This adapter carries no knowledge of any individual case. It resolves a
 * fixture id to bytes, builds a verifier from the generic config, dispatches
 * on {@code operation}, normalizes the success object onto the shared
 * (language-neutral) field names, and reads
 * {@link VerificationException#reason()} out of a failure. A case is added by
 * editing cases.json, never this file.</p>
 *
 * <p>Each case is its own {@link DynamicTest}, named by its case id, so a
 * failure names the vector that broke.</p>
 *
 * <p>A case carrying a {@code clock} is run with that instant injected, so a
 * verdict that moves with wall-clock time is deterministic. Only two surfaces
 * take one: the JWS verifier (the max-signed-age staleness rule) and the
 * endpoint (request_date stamping). The receipt verifier takes none — its only
 * "now" is a certificate-validity instant, which no injected clock may move —
 * so a receipt case cannot pin a clock and none does. A case without one gets
 * the library default, the system clock.</p>
 *
 * <p>Every fixture the adapter loads is checked against the
 * {@code contentSha256} the registry records for it, over the DECODED bytes,
 * so fixture bytes and cases.json cannot drift apart unnoticed.</p>
 */
class ConformanceCasesTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures");

    /** FIELD visibility so the payload models normalize without accessors. */
    private static final ObjectMapper MAPPER =
            new ObjectMapper().setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<Map<String, Object>>() {};

    @TestFactory
    List<DynamicTest> conformanceCases() throws Exception {
        JsonNode document = MAPPER.readTree(FIXTURES.resolve("cases.json").toFile());
        final JsonNode fixtures = document.get("fixtures");
        List<DynamicTest> tests = new ArrayList<DynamicTest>();
        int pinned = 0;
        for (JsonNode node : document.get("cases")) {
            final JsonNode kase = node;
            if (kase.has("clock")) {
                pinned++;
            }
            tests.add(DynamicTest.dynamicTest(kase.get("id").asText(), () -> runCase(fixtures, kase)));
        }
        System.out.println("conformance: " + tests.size() + " cases in fixtures/cases.json, " + pinned
                + " with a pinned clock, 0 skipped");
        return tests;
    }

    // Surefire reports a dynamic test by its index, not its display name, so
    // every message repeats the case id — otherwise a CI log names no vector.
    private static void runCase(JsonNode fixtures, JsonNode kase) throws Exception {
        String id = kase.get("id").asText();
        JsonNode expected = kase.get("expected");
        boolean expectError = "error".equals(expected.get("status").asText());
        Object result;
        try {
            result = invoke(fixtures, kase);
        } catch (VerificationException e) {
            if (!expectError) {
                throw new AssertionError(
                        id + ": expected success but failed with " + e.reason() + ": " + e.getMessage(), e);
            }
            assertEquals(Reason.valueOf(expected.get("reason").asText()), e.reason(), id + ": " + e.getMessage());
            return;
        } catch (Exception e) {
            // Never map an arbitrary failure onto an expected Reason: anything
            // other than a VerificationException is a harness/library defect.
            throw new AssertionError(
                    id + ": harness error — the operation raised "
                            + e.getClass().getName() + " instead of a VerificationException",
                    e);
        }
        if (expectError) {
            fail(id + ": expected " + expected.get("reason").asText() + " but the operation succeeded");
        }
        assertFields(id, expected.get("fields"), result);
    }

    // ---------------------------------------------------------------- dispatch

    private static Object invoke(JsonNode fixtures, JsonNode kase) throws Exception {
        JsonNode config = kase.get("config");
        Set<X509Certificate> roots = trustedRoots(fixtures, config.get("trustedRoots"));
        String fixtureId = kase.get("input").get("fixture").asText();
        byte[] input = fixtureBytes(fixtures, fixtureId);
        String operation = kase.get("operation").asText();
        Clock clock = clock(kase);
        if ("verifyTransaction".equals(operation)) {
            return MAPPER.convertValue(jwsVerifier(roots, config, clock).verifyTransaction(text(input)), MAP);
        }
        if ("verifyAppTransaction".equals(operation)) {
            return MAPPER.convertValue(jwsVerifier(roots, config, clock).verifyAppTransaction(text(input)), MAP);
        }
        if ("verifyRaw".equals(operation)) {
            return jwsVerifier(roots, config, clock).verifyRaw(text(input));
        }
        if ("verifyReceipt".equals(operation)) {
            // No clock: receipt verification has no verdict that moves with
            // wall-clock time, and its one "now" is a certificate-validity
            // instant that an injected clock must not be able to shift.
            ReceiptVerifier verifier =
                    new ReceiptVerifier(roots, config.get("bundleId").asText());
            byte[] deviceGuid = config.has("deviceGuidHex")
                    ? unhex(config.get("deviceGuidHex").asText())
                    : null;
            return normalize(verifier.verify(input, deviceGuid));
        }
        if ("verifyReceiptBase64".equals(operation)) {
            // Same DER underneath as verifyReceipt, but the fixture is a text
            // fixture: the verbatim string is what a client actually sends,
            // and how it turns into DER is exactly what this operation pins.
            ReceiptVerifier verifier =
                    new ReceiptVerifier(roots, config.get("bundleId").asText());
            byte[] deviceGuid = config.has("deviceGuidHex")
                    ? unhex(config.get("deviceGuidHex").asText())
                    : null;
            return normalize(verifier.verify(text(input), deviceGuid));
        }
        if ("verifyReceiptEndpoint".equals(operation)) {
            Environment environment =
                    Environment.fromValue(config.get("environment").asText());
            if (environment == null) {
                throw new IllegalStateException(
                        "unknown environment " + config.get("environment").asText());
            }
            // A text fixture's bytes go into receipt-data verbatim, exactly
            // as a client would send them; a raw or base64 fixture is
            // re-encoded as canonical base64, as before.
            String codec = fixtures.get(fixtureId).get("codec").asText();
            String receiptData =
                    "text".equals(codec) ? text(input) : Base64.getEncoder().encodeToString(input);
            return new VerifyReceiptEndpoint(roots, environment, clock)
                    .verifyReceipt(Collections.singletonMap("receipt-data", receiptData));
        }
        throw new IllegalStateException("unknown operation " + operation);
    }

    /**
     * The case's pinned "now", or null for the library default (the system
     * clock). cases.json spells it as an ISO-8601 UTC instant.
     */
    private static Clock clock(JsonNode kase) {
        if (!kase.has("clock")) {
            return null;
        }
        return Clock.fixed(Instant.parse(kase.get("clock").get("now").asText()), ZoneOffset.UTC);
    }

    private static JwsVerifier jwsVerifier(Set<X509Certificate> roots, JsonNode config, Clock clock) {
        // verifyRaw enforces no claim, so its cases need not pin a bundle id or
        // an accept set — but the constructor demands both. Neutral stand-ins
        // (a bundle id no payload can carry, every environment) keep that
        // generic rather than per-case.
        String bundleId = config.has("bundleId") ? config.get("bundleId").asText() : "";
        Set<Environment> environments = EnumSet.allOf(Environment.class);
        if (config.has("acceptedEnvironments")) {
            environments = EnumSet.noneOf(Environment.class);
            for (JsonNode name : config.get("acceptedEnvironments")) {
                Environment environment = Environment.fromValue(name.asText());
                if (environment == null) {
                    throw new IllegalStateException("unknown environment " + name.asText());
                }
                environments.add(environment);
            }
        }
        Long appAppleId = null;
        if (config.has("appAppleId")) {
            appAppleId = Long.valueOf(config.get("appAppleId").asLong());
        }
        Long maxSignedAge = null;
        if (config.has("maxSignedAgeSeconds")) {
            maxSignedAge = Long.valueOf(config.get("maxSignedAgeSeconds").asLong() * 1000L);
        }
        return new JwsVerifier(roots, bundleId, environments, appAppleId, maxSignedAge, clock);
    }

    // ---------------------------------------------------------------- fixtures

    private static Set<X509Certificate> trustedRoots(JsonNode fixtures, JsonNode spec) throws Exception {
        if ("builtin".equals(spec.get("source").asText())) {
            String name = spec.get("name").asText();
            if ("apple-receipt-roots".equals(name)) {
                return AppleRootCerts.receiptRoots();
            }
            if ("apple-jws-roots".equals(name)) {
                return AppleRootCerts.jwsRoots();
            }
            throw new IllegalStateException("unknown builtin root set " + name);
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Set<X509Certificate> roots = new HashSet<X509Certificate>();
        for (JsonNode id : spec.get("fixtures")) {
            roots.add((X509Certificate)
                    factory.generateCertificate(new ByteArrayInputStream(fixtureBytes(fixtures, id.asText()))));
        }
        return roots;
    }

    /**
     * Every fixture in the registry hashes to the {@code contentSha256} it
     * declares. {@link #fixtureBytes} checks the ones the cases actually load;
     * this walks the whole registry, so a fixture that drifted while no case
     * currently reaches it is still caught — which is the entire reason the
     * field exists.
     */
    @Test
    void everyFixtureMatchesItsRecordedContentDigest() throws Exception {
        JsonNode fixtures =
                MAPPER.readTree(FIXTURES.resolve("cases.json").toFile()).get("fixtures");
        int checked = 0;
        Iterator<String> ids = fixtures.fieldNames();
        while (ids.hasNext()) {
            fixtureBytes(fixtures, ids.next());
            checked++;
        }
        assertTrue(checked > 0, "cases.json declares no fixtures");
        System.out.println("conformance: " + checked + " fixture content digests verified against cases.json");
    }

    /**
     * A fixture id to its logical bytes, per the registry's {@code codec} —
     * and only after those bytes hash to the {@code contentSha256} the
     * registry records for them. The digest is over the DECODED bytes (the
     * file itself for {@code raw} and for {@code text} — verbatim, untrimmed
     * — the base64-decoded bytes for {@code base64}, the UTF-8 of the
     * trimmed text for {@code utf8}), so it pins what the verifier is
     * actually handed rather than how it is stored.
     */
    private static byte[] fixtureBytes(JsonNode fixtures, String id) throws Exception {
        JsonNode fixture = fixtures.get(id);
        if (fixture == null) {
            throw new IllegalStateException("cases.json declares no fixture " + id);
        }
        byte[] stored = Files.readAllBytes(FIXTURES.resolve(fixture.get("path").asText()));
        String codec = fixture.get("codec").asText();
        byte[] decoded;
        if ("raw".equals(codec) || "text".equals(codec)) {
            // text = the file bytes verbatim, untrimmed -- unlike utf8 below,
            // which trims. One registered fixture is 0 bytes and some carry
            // CRLF; both must survive exactly as stored.
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
        JsonNode expected = fixture.get("contentSha256");
        if (expected == null || !expected.isTextual()) {
            throw new IllegalStateException("fixture " + id + " declares no contentSha256");
        }
        String actual = hex(MessageDigest.getInstance("SHA-256").digest(decoded));
        if (!expected.textValue().equals(actual)) {
            throw new AssertionError(
                    "fixture " + id + " (" + fixture.get("path").asText()
                            + ", codec " + codec + ") hashes to " + actual
                            + " but cases.json records " + expected.textValue()
                            + " — the fixture bytes and the registry have drifted apart");
        }
        return decoded;
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

    // --------------------------------------------------------------- normalize

    /** The receipt model onto the shared field names of cases.json. */
    private static Map<String, Object> normalize(AppReceipt receipt) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("receiptType", receipt.receiptType());
        out.put("bundleId", receipt.bundleId());
        out.put("appVersion", receipt.appVersion());
        out.put("originalAppVersion", receipt.originalAppVersion());
        out.put("creationDate", iso(receipt.creationDate()));
        out.put("originalPurchaseDate", iso(receipt.originalPurchaseDate()));
        out.put("expirationDate", iso(receipt.expirationDate()));
        out.put("opaqueValueHex", hex(receipt.opaqueValue()));
        out.put("sha1HashHex", hex(receipt.sha1Hash()));
        List<Object> purchases = new ArrayList<Object>();
        for (InAppPurchase purchase : receipt.inAppPurchases()) {
            purchases.add(normalize(purchase));
        }
        out.put("inAppPurchases", purchases);
        out.put("unknownAttributes", unknownAttributes(receipt.unknownAttributes()));
        return out;
    }

    private static Map<String, Object> normalize(InAppPurchase purchase) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("quantity", purchase.quantity());
        out.put("productId", purchase.productId());
        out.put("transactionId", purchase.transactionId());
        out.put("originalTransactionId", purchase.originalTransactionId());
        out.put("purchaseDate", iso(purchase.purchaseDate()));
        out.put("originalPurchaseDate", iso(purchase.originalPurchaseDate()));
        out.put("expiresDate", iso(purchase.expiresDate()));
        out.put("cancellationDate", iso(purchase.cancellationDate()));
        out.put("webOrderLineItemId", purchase.webOrderLineItemId());
        out.put("isInIntroOfferPeriod", purchase.isInIntroOfferPeriod());
        out.put("unknownAttributes", unknownAttributes(purchase.unknownAttributes()));
        return out;
    }

    /** Raw attribute values become lowercase hex, keyed by decimal type. */
    private static Map<String, Object> unknownAttributes(Map<Integer, List<byte[]>> attributes) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            List<Object> values = new ArrayList<Object>();
            for (byte[] value : entry.getValue()) {
                values.add(hex(value));
            }
            out.put(String.valueOf(entry.getKey()), values);
        }
        return out;
    }

    private static String iso(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    // ------------------------------------------------------------- assertions

    /** Subset semantics: only the listed fields are pinned, extras are ignored. */
    private static void assertFields(String id, JsonNode fields, Object result) {
        Iterator<Map.Entry<String, JsonNode>> entries = fields.fields();
        while (entries.hasNext()) {
            Map.Entry<String, JsonNode> field = entries.next();
            String path = id + " " + field.getKey();
            assertValue(path, field.getValue(), resolve(result, field.getKey(), path));
        }
    }

    private static void assertValue(String path, JsonNode expected, Object actual) {
        if (expected.isNull()) {
            assertNull(actual, path);
        } else if (expected.isNumber()) {
            assertTrue(
                    actual instanceof Number,
                    path + ": expected the number " + expected + " but got " + describe(actual));
            assertTrue(
                    expected.decimalValue().compareTo(new BigDecimal(actual.toString())) == 0,
                    path + ": expected " + expected + " but got " + actual);
        } else if (expected.isBoolean()) {
            assertEquals(Boolean.valueOf(expected.booleanValue()), actual, path);
        } else {
            assertEquals(expected.textValue(), actual, path);
        }
    }

    private static String describe(Object value) {
        return value == null ? "null" : value + " (" + value.getClass().getSimpleName() + ")";
    }

    // ------------------------------------------------------- field-path syntax
    // "a.b" navigates; "x.length" is a collection size; "list[k=v]" selects the
    // element whose k equals v; "map[9999][0]" indexes a keyed list.

    private static Object resolve(Object root, String field, String path) {
        Object current = root;
        for (String segment : segments(field)) {
            if ("length".equals(segment)) {
                current = length(current, path);
                continue;
            }
            int bracket = segment.indexOf('[');
            current = member(current, bracket < 0 ? segment : segment.substring(0, bracket), path);
            if (bracket >= 0) {
                for (String selector : selectors(segment.substring(bracket), path)) {
                    current = select(current, selector, path);
                }
            }
        }
        return current;
    }

    /** Splits on dots outside brackets — selector values contain dots. */
    private static List<String> segments(String path) {
        List<String> segments = new ArrayList<String>();
        int depth = 0;
        StringBuilder segment = new StringBuilder();
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
            } else if (c == '.' && depth == 0) {
                segments.add(segment.toString());
                segment.setLength(0);
                continue;
            }
            segment.append(c);
        }
        segments.add(segment.toString());
        return segments;
    }

    private static List<String> selectors(String brackets, String path) {
        List<String> selectors = new ArrayList<String>();
        int i = 0;
        while (i < brackets.length()) {
            int close = brackets.indexOf(']', i);
            if (brackets.charAt(i) != '[' || close < 0) {
                throw new IllegalStateException("unparseable field path " + path);
            }
            selectors.add(brackets.substring(i + 1, close));
            i = close + 1;
        }
        return selectors;
    }

    @SuppressWarnings("unchecked")
    private static Object member(Object current, String name, String path) {
        if (current == null) {
            return null;
        }
        if (current instanceof Map) {
            return ((Map<String, Object>) current).get(name);
        }
        throw new IllegalStateException(path + ": cannot read '" + name + "' of " + describe(current));
    }

    @SuppressWarnings("unchecked")
    private static Object select(Object current, String selector, String path) {
        int equals = selector.indexOf('=');
        if (equals >= 0) {
            String key = selector.substring(0, equals);
            String value = selector.substring(equals + 1);
            if (!(current instanceof List)) {
                throw new IllegalStateException(path + ": [" + selector + "] needs a list, got " + describe(current));
            }
            for (Object element : (List<Object>) current) {
                Object candidate = member(element, key, path);
                if (candidate != null && value.equals(candidate.toString())) {
                    return element;
                }
            }
            throw new IllegalStateException(path + ": no element with " + selector);
        }
        if (current instanceof List) {
            return ((List<Object>) current).get(Integer.parseInt(selector));
        }
        if (current instanceof Map) {
            return ((Map<String, Object>) current).get(selector);
        }
        throw new IllegalStateException(path + ": [" + selector + "] needs a list or map, got " + describe(current));
    }

    private static Object length(Object current, String path) {
        if (current instanceof Collection) {
            return Integer.valueOf(((Collection<?>) current).size());
        }
        if (current instanceof Map) {
            return Integer.valueOf(((Map<?, ?>) current).size());
        }
        throw new IllegalStateException(path + ": .length needs a collection, got " + describe(current));
    }
}
