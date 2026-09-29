package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
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
import java.util.List;

/**
 * {@code fixtures/cases.json} and its fixture registry, as the main
 * artifact's conformance runner reads them: every fixture checked against
 * its {@code contentSha256} before use. The fixtures directory is
 * {@code ../fixtures} from the module directory, where Maven runs the tests.
 */
final class Cases {

    static final Path FIXTURES = Paths.get("..", "fixtures");
    static final String CASES = "cases.json";

    // Big decimals for fractions and exact integers, so a pinned value
    // compares without rounding (the endpoint's download_id is 2^63-1).
    static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);

    private static JsonNode document;

    private Cases() {}

    static synchronized JsonNode document() throws Exception {
        if (document == null) {
            JsonNode read = MAPPER.readTree(FIXTURES.resolve(CASES).toFile());
            if (read.get("schemaVersion").asInt() != 2) {
                throw new IllegalStateException(CASES + " is not schema version 2");
            }
            document = read;
        }
        return document;
    }

    static JsonNode fixtures() throws Exception {
        return document().get("fixtures");
    }

    static JsonNode byId(String id) throws Exception {
        for (JsonNode kase : document().get("cases")) {
            if (id.equals(kase.get("id").asText())) {
                return kase;
            }
        }
        throw new IllegalStateException(CASES + " has no case " + id);
    }

    /**
     * A fixture id to its logical bytes, per the registry's {@code codec},
     * and only after those bytes hash to the {@code contentSha256} the
     * registry records.
     */
    static byte[] fixtureBytes(String id) throws Exception {
        JsonNode fixture = fixtures().get(id);
        if (fixture == null) {
            throw new IllegalStateException(CASES + " declares no fixture " + id);
        }
        byte[] stored = Files.readAllBytes(FIXTURES.resolve(fixture.get("path").asText()));
        String codec = fixture.get("codec").asText();
        byte[] decoded;
        if ("raw".equals(codec) || "text".equals(codec)) {
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
                    "fixture " + id + " hashes to " + actual + " but " + CASES + " records " + expected);
        }
        return decoded;
    }

    /** The case's roots, and a clock fixed at {@code clock.now} when it pins one. */
    static Config config(JsonNode kase) throws Exception {
        JsonNode roots = kase.get("config").get("trustedRoots");
        Config.Builder builder = Config.builder();
        String source = roots.get("source").asText();
        if ("fixtures".equals(source)) {
            builder.roots(roots(roots.get("fixtures")));
        } else if (!"defaults".equals(source)) {
            throw new IllegalStateException("harness error: unknown trustedRoots source " + source);
        }
        if (kase.has("clock")) {
            builder.clock(Clock.fixed(Instant.parse(kase.get("clock").get("now").asText()), ZoneOffset.UTC));
        }
        return builder.build();
    }

    static List<X509Certificate> roots(JsonNode ids) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificates = new ArrayList<>();
        for (JsonNode id : ids) {
            certificates.add(
                    (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(fixtureBytes(id.asText()))));
        }
        return certificates;
    }

    /**
     * The string verifyReceipt gets: a text fixture verbatim; any other
     * fixture holds DER, encoded as canonical base64.
     */
    static String receiptString(JsonNode input) throws Exception {
        String id = input.get("fixture").asText();
        byte[] bytes = fixtureBytes(id);
        String codec = fixtures().get(id).get("codec").asText();
        return "text".equals(codec) ? text(bytes) : Base64.getEncoder().encodeToString(bytes);
    }

    static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }
}
