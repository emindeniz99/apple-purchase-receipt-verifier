package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptResult;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@link VerifyReceiptResult}: one verification, then any number of renders.
 *
 * <p>What matters here is what a caller builds a retry on. The receipt must
 * survive a 21007/21008 so the other environment can be rendered without a
 * second verification, and that re-render must recompute the status from the
 * receipt itself: a result from a production endpoint must never be turned
 * into a production 0 for a sandbox receipt, or the 21007 routing that keeps
 * sandbox purchases out of production would be one method call away from
 * being bypassed.</p>
 */
class VerifyReceiptResultTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "generated");
    private static final Instant CLOCK_NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant EXPLICIT = Instant.parse("2025-06-15T12:34:56.789Z");

    private static X509Certificate cert(String name) throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve(name));
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    private static VerifyReceiptEndpoint endpoint(Environment environment) throws Exception {
        return endpoint(environment, "receipt-root.der");
    }

    private static VerifyReceiptEndpoint endpoint(Environment environment, String root) throws Exception {
        return new VerifyReceiptEndpoint(
                Collections.singleton(cert(root)), environment, Clock.fixed(CLOCK_NOW, ZoneOffset.UTC));
    }

    private static String base64(String fixture) throws Exception {
        return Base64.getEncoder().encodeToString(Files.readAllBytes(FIXTURES.resolve(fixture)));
    }

    private static Map<String, Object> body(Object receiptData) {
        return Collections.<String, Object>singletonMap("receipt-data", receiptData);
    }

    private static void assertInvariant(VerifyReceiptResult result, String label) {
        assertTrue(
                (result.receipt() == null) != (result.failureReason() == null),
                label + ": exactly one of receipt and failureReason must be set");
        assertEquals(result.receipt() != null, result.isVerified(), label + ": isVerified must match receipt()");
        assertEquals(
                result.failureReason() == Reason.INTERNAL_ERROR,
                result.failureCause() != null,
                label + ": failureCause is set exactly for INTERNAL_ERROR");
        assertEquals(Integer.valueOf(result.status()), result.toResponse().get("status"), label);
        assertNotNull(result.requestDate(), label);
    }

    @Test
    void exactlyOneOfReceiptAndFailureReasonIsSetForEveryStatus() throws Exception {
        Map<String, VerifyReceiptResult> results = new LinkedHashMap<String, VerifyReceiptResult>();
        results.put("0 sandbox", endpoint(Environment.SANDBOX).verifyReceiptData(base64("receipt.der")));
        results.put(
                "0 production",
                endpoint(Environment.PRODUCTION).verifyReceiptData(base64("receipt-type-production.der")));
        results.put("21007", endpoint(Environment.PRODUCTION).verifyReceiptData(base64("receipt.der")));
        results.put("21008", endpoint(Environment.SANDBOX).verifyReceiptData(base64("receipt-type-production.der")));
        results.put("21002", endpoint(Environment.SANDBOX).verifyReceiptData("AQIDBA=="));
        results.put("21003", endpoint(Environment.SANDBOX).verifyReceiptData(base64("receipt-foreign.der")));
        results.put("21009", endpoint(Environment.SANDBOX).verifyReceiptResult(throwingMap()));
        for (Map.Entry<String, VerifyReceiptResult> entry : results.entrySet()) {
            VerifyReceiptResult result = entry.getValue();
            assertInvariant(result, entry.getKey());
            assertEquals(Integer.parseInt(entry.getKey().split(" ")[0]), result.status(), entry.getKey());
        }
        // 21007 and 21008 are routing answers, not failures: the receipt verified.
        assertNotNull(results.get("21007").receipt());
        assertNotNull(results.get("21008").receipt());
        // isVerified() is true for status 0 and for 21007/21008 alike, since
        // all three carry a verified receipt; it is false for every failure,
        // even though 21002/21003/21009 are also non-zero statuses.
        for (String verified : Arrays.asList("0 sandbox", "0 production", "21007", "21008")) {
            assertTrue(results.get(verified).isVerified(), verified);
        }
        for (String failed : Arrays.asList("21002", "21003", "21009")) {
            assertTrue(!results.get(failed).isVerified(), failed);
        }
    }

    /**
     * The whole re-render table, on committed fixtures. A production receipt
     * gives 0 on PRODUCTION and 21008 on SANDBOX; a sandbox receipt (and one
     * with no receipt_type, which fails closed as sandbox) gives 21007 on
     * PRODUCTION and 0 on SANDBOX; a failed result keeps its own status. The
     * table is the same whichever environment the endpoint itself had.
     */
    @Test
    void reRendersForEitherEnvironmentFromTheReceiptsOwnType() throws Exception {
        Object[][] table = {
            // fixture, root, status on PRODUCTION, status on SANDBOX
            {"receipt-type-production.der", "receipt-root.der", 0, 21008},
            {"receipt-type-vpp.der", "receipt-root.der", 0, 21008},
            {"receipt.der", "receipt-root.der", 21007, 0},
            {"receipt-type-vpp-sandbox.der", "receipt-root.der", 21007, 0},
            {"receipt-no-type.der", "receipt-root.der", 21007, 0},
            {"receipt-foreign.der", "receipt-root.der", 21003, 21003},
            {"receipt-tampered-payload.der", "gaps-receipt-root.der", 21003, 21003},
        };
        for (Object[] row : table) {
            String fixture = (String) row[0];
            for (Environment own : Arrays.asList(Environment.PRODUCTION, Environment.SANDBOX)) {
                VerifyReceiptResult result =
                        endpoint(own, (String) row[1]).verifyReceiptData(base64(fixture), EXPLICIT);
                String label = fixture + " from a " + own + " endpoint";
                assertEquals(row[2], result.toResponse(Environment.PRODUCTION).get("status"), label);
                assertEquals(row[3], result.toResponse(Environment.SANDBOX).get("status"), label);
                for (Environment target : Arrays.asList(Environment.PRODUCTION, Environment.SANDBOX)) {
                    // Each render equals what an endpoint of that environment
                    // answers on its own, byte for byte.
                    String direct = endpoint(target, (String) row[1])
                            .verifyReceiptData(base64(fixture), EXPLICIT)
                            .toJson();
                    assertEquals(direct, result.toJson(target), label + " rendered for " + target);
                }
            }
        }
    }

    @Test
    void aSandboxReceiptNeverRendersAProductionZero() throws Exception {
        for (String fixture : Arrays.asList("receipt.der", "receipt-type-vpp-sandbox.der", "receipt-no-type.der")) {
            for (Environment own : Arrays.asList(Environment.PRODUCTION, Environment.SANDBOX)) {
                VerifyReceiptResult result = endpoint(own).verifyReceiptData(base64(fixture));
                assertNotNull(result.receipt(), fixture);
                assertEquals("{\"status\":21007}", result.toJson(Environment.PRODUCTION), fixture + " via " + own);
                assertEquals(
                        Collections.<String, Object>singletonMap("status", 21007),
                        result.toResponse(Environment.PRODUCTION),
                        fixture + " via " + own);
            }
        }
    }

    @Test
    void renderingForAnEnvironmentAppleDoesNotHaveIsRefused() throws Exception {
        VerifyReceiptResult result = endpoint(Environment.SANDBOX).verifyReceiptData(base64("receipt.der"));
        for (Environment environment : Arrays.asList(Environment.XCODE, Environment.LOCAL_TESTING)) {
            assertThrows(IllegalArgumentException.class, () -> result.toResponse(environment));
            assertThrows(IllegalArgumentException.class, () -> result.toJson(environment));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void anExplicitRequestDateIsRenderedAndWinsOverTheClock() throws Exception {
        VerifyReceiptEndpoint endpoint = endpoint(Environment.SANDBOX);
        String receiptData = base64("receipt.der");
        VerifyReceiptResult explicit = endpoint.verifyReceiptResult(body(receiptData), EXPLICIT);
        assertEquals(EXPLICIT, explicit.requestDate());
        Map<String, Object> receipt =
                (Map<String, Object>) explicit.toResponse().get("receipt");
        assertEquals("2025-06-15 12:34:56 Etc/GMT", receipt.get("request_date"));
        assertEquals(String.valueOf(EXPLICIT.toEpochMilli()), receipt.get("request_date_ms"));
        assertEquals("2025-06-15 05:34:56 America/Los_Angeles", receipt.get("request_date_pst"));
        // Deterministic: the same call renders the same bytes, and so does
        // rendering the same result twice.
        assertEquals(
                explicit.toJson(),
                endpoint.verifyReceiptResult(body(receiptData), EXPLICIT).toJson());
        assertEquals(explicit.toJson(), explicit.toJson());
        // Without one, the endpoint's clock supplies it.
        assertEquals(CLOCK_NOW, endpoint.verifyReceiptResult(body(receiptData)).requestDate());
        assertEquals(CLOCK_NOW, endpoint.verifyReceiptData(receiptData).requestDate());
        assertEquals(
                CLOCK_NOW,
                endpoint.verifyReceiptResult("{\"receipt-data\":\"" + receiptData + "\"}")
                        .requestDate());
        assertEquals(
                EXPLICIT,
                endpoint.verifyReceiptResult("{\"receipt-data\":\"" + receiptData + "\"}", EXPLICIT)
                        .requestDate());
    }

    @Test
    void theJsonRenderIsWhatVerifyReceiptJsonAnswers() throws Exception {
        VerifyReceiptEndpoint endpoint = endpoint(Environment.SANDBOX);
        String json = "{\"receipt-data\":\"" + base64("receipt.der") + "\"}";
        assertEquals(
                endpoint.verifyReceiptJson(json),
                endpoint.verifyReceiptResult(json).toJson());
        assertEquals(
                endpoint.verifyReceiptJson(json),
                endpoint.verifyReceiptResult(json).toJson(Environment.SANDBOX));
    }

    @Test
    void theBareReceiptAnswersAsTheSameReceiptInABody() throws Exception {
        for (Environment environment : Arrays.asList(Environment.PRODUCTION, Environment.SANDBOX)) {
            VerifyReceiptEndpoint endpoint = endpoint(environment);
            for (String receiptData : Arrays.asList(
                    base64("receipt.der"),
                    base64("receipt-type-production.der"),
                    base64("receipt-foreign.der"),
                    "AQIDBA==",
                    "not base64!",
                    "")) {
                VerifyReceiptResult bare = endpoint.verifyReceiptData(receiptData, EXPLICIT);
                VerifyReceiptResult wrapped = endpoint.verifyReceiptResult(body(receiptData), EXPLICIT);
                assertEquals(wrapped.status(), bare.status(), receiptData);
                assertEquals(wrapped.failureReason(), bare.failureReason(), receiptData);
                assertEquals(wrapped.toJson(), bare.toJson(), receiptData);
                assertEquals(wrapped.toJson(Environment.PRODUCTION), bare.toJson(Environment.PRODUCTION), receiptData);
                assertEquals(wrapped.toJson(Environment.SANDBOX), bare.toJson(Environment.SANDBOX), receiptData);
            }
        }
    }

    @Test
    void eachFailureNamesItsReason() throws Exception {
        VerifyReceiptEndpoint endpoint = endpoint(Environment.SANDBOX);
        StringBuilder tooLarge = new StringBuilder("{\"receipt-data\":\"");
        while (tooLarge.length() <= VerifyReceiptEndpoint.MAX_REQUEST_BYTES) {
            tooLarge.append("AAAA");
        }
        tooLarge.append("\"}");

        Map<String, VerifyReceiptResult> malformed = new LinkedHashMap<String, VerifyReceiptResult>();
        malformed.put("body not JSON", endpoint.verifyReceiptResult("not json"));
        malformed.put("body a JSON array", endpoint.verifyReceiptResult("[{\"receipt-data\":\"AQIDBA==\"}]"));
        malformed.put("null body", endpoint.verifyReceiptResult((String) null));
        malformed.put("null map", endpoint.verifyReceiptResult((Map<String, Object>) null));
        malformed.put("receipt-data missing", endpoint.verifyReceiptResult(Collections.<String, Object>emptyMap()));
        malformed.put("receipt-data empty", endpoint.verifyReceiptResult(body("")));
        malformed.put("receipt-data a number", endpoint.verifyReceiptResult("{\"receipt-data\":5}"));
        malformed.put("receipt-data a list", endpoint.verifyReceiptResult(body(Arrays.asList("AQIDBA=="))));
        malformed.put("bare receipt null", endpoint.verifyReceiptData(null));
        for (Map.Entry<String, VerifyReceiptResult> entry : malformed.entrySet()) {
            assertEquals(Reason.MALFORMED_REQUEST, entry.getValue().failureReason(), entry.getKey());
            assertEquals(
                    VerifyReceiptEndpoint.STATUS_MALFORMED, entry.getValue().status(), entry.getKey());
            assertInvariant(entry.getValue(), entry.getKey());
        }

        // Over Apple's request limit: 21002 like the malformed bodies, but its
        // own reason, so an HTTP layer can answer 413 where Apple does.
        VerifyReceiptResult tooLargeResult = endpoint.verifyReceiptResult(tooLarge.toString());
        assertEquals(Reason.REQUEST_TOO_LARGE, tooLargeResult.failureReason());
        assertEquals(VerifyReceiptEndpoint.STATUS_MALFORMED, tooLargeResult.status());
        assertInvariant(tooLargeResult, "body too large");

        Map<String, VerifyReceiptResult> format = new LinkedHashMap<String, VerifyReceiptResult>();
        format.put("not base64", endpoint.verifyReceiptResult(body("not base64!")));
        format.put("not a receipt", endpoint.verifyReceiptResult(body("AQIDBA==")));
        for (Map.Entry<String, VerifyReceiptResult> entry : format.entrySet()) {
            assertEquals(Reason.INVALID_RECEIPT_FORMAT, entry.getValue().failureReason(), entry.getKey());
            assertEquals(
                    VerifyReceiptEndpoint.STATUS_MALFORMED, entry.getValue().status(), entry.getKey());
            assertInvariant(entry.getValue(), entry.getKey());
        }

        VerifyReceiptResult foreign = endpoint.verifyReceiptResult(body(base64("receipt-foreign.der")));
        assertEquals(Reason.INVALID_CHAIN, foreign.failureReason());
        assertEquals(VerifyReceiptEndpoint.STATUS_NOT_AUTHENTICATED, foreign.status());
        VerifyReceiptResult tampered = endpoint(Environment.SANDBOX, "gaps-receipt-root.der")
                .verifyReceiptResult(body(base64("receipt-tampered-payload.der")));
        assertEquals(Reason.INVALID_SIGNATURE, tampered.failureReason());
        assertEquals(VerifyReceiptEndpoint.STATUS_NOT_AUTHENTICATED, tampered.status());
    }

    /**
     * A request map whose lookup throws stands in for any unexpected runtime
     * failure inside the pipeline. The endpoint promises never to throw, so
     * the exception must come back as INTERNAL_ERROR, status 21009, with the
     * exception itself kept for logging.
     */
    @Test
    void anUnexpectedRuntimeExceptionIsAnInternalErrorNotAThrow() throws Exception {
        for (Environment environment : Arrays.asList(Environment.PRODUCTION, Environment.SANDBOX)) {
            VerifyReceiptResult result = endpoint(environment).verifyReceiptResult(throwingMap());
            assertEquals(Reason.INTERNAL_ERROR, result.failureReason());
            assertNull(result.receipt());
            assertEquals(VerifyReceiptEndpoint.STATUS_INTERNAL, result.status());
            assertSame(BOOM, result.failureCause());
            assertEquals("{\"status\":21009}", result.toJson());
            assertEquals("{\"status\":21009}", result.toJson(Environment.PRODUCTION));
            assertEquals("{\"status\":21009}", result.toJson(Environment.SANDBOX));
        }
    }

    private static final IllegalStateException BOOM = new IllegalStateException("broken request map");

    private static Map<String, Object> throwingMap() {
        return new AbstractMap<String, Object>() {
            @Override
            public Object get(Object key) {
                throw BOOM;
            }

            @Override
            public Set<Map.Entry<String, Object>> entrySet() {
                throw BOOM;
            }
        };
    }

    @Test
    void theResultTypeHasNoPublicConstructor() {
        // Only the endpoint creates one, so no caller can fabricate status 0.
        assertEquals(0, VerifyReceiptResult.class.getConstructors().length);
    }
}
