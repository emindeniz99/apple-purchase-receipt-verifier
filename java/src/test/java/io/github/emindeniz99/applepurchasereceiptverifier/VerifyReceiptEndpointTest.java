package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * verifyReceipt-compat semantics over the shared receipt fixture that
 * {@code fixtures/cases.json} does not pin: the raw-JSON wire form, the
 * malformed-request statuses, and the date fields that move with the clock.
 * Every status-code routing verdict lives in cases.json instead, asserted by
 * {@link ConformanceCasesTest}.
 */
class VerifyReceiptEndpointTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "generated");

    private static VerifyReceiptEndpoint endpoint(boolean production) throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve("receipt-root.der"));
        X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        return new VerifyReceiptEndpoint(Collections.singleton(root), production);
    }

    private static Map<String, Object> request() throws Exception {
        byte[] receipt = Files.readAllBytes(FIXTURES.resolve("receipt.der"));
        return Collections.singletonMap("receipt-data",
                Base64.getEncoder().encodeToString(receipt));
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** request_date is "now": two calls legitimately disagree on it. */
    private static JsonNode withoutRequestDate(JsonNode response) {
        JsonNode receipt = response.get("receipt");
        if (receipt != null) {
            ((ObjectNode) receipt).remove(java.util.Arrays.asList(
                    "request_date", "request_date_ms", "request_date_pst"));
        }
        return response;
    }

    /**
     * The fixed values of this response are pinned in {@code cases.json}
     * (endpoint/sandbox-receipt-on-sandbox-answers-0). What stays here is what
     * a language-neutral vector cannot pin: {@code request_date}, which is
     * "now", and the {@code _ms}/{@code _pst} companions of every date — the
     * COMPARISON.md "full fidelity" field set, present in Node too.
     */
    @Test
    @SuppressWarnings("unchecked")
    void emitsTheRequestDateAndEveryDateCompanionField() throws Exception {
        Map<String, Object> response = endpoint(false).verifyReceipt(request());
        Map<String, Object> receipt = (Map<String, Object>) response.get("receipt");
        assertNotNull(receipt.get("request_date_ms"));
        assertNotNull(receipt.get("request_date"));
        assertNotNull(receipt.get("request_date_pst"));
        List<Map<String, Object>> inApp = (List<Map<String, Object>>) receipt.get("in_app");
        Map<String, Object> coins = inApp.get(0).get("product_id").equals("com.example.app.coins100")
                ? inApp.get(0) : inApp.get(1);
        assertNotNull(coins.get("purchase_date"));
        assertNotNull(coins.get("purchase_date_ms"));
        assertNotNull(coins.get("purchase_date_pst"));
        Map<String, Object> vip = inApp.get(0).get("product_id").equals("com.example.app.vip")
                ? inApp.get(0) : inApp.get(1);
        assertNotNull(vip.get("expires_date_ms"));
        assertNotNull(vip.get("expires_date_pst"));
    }

    @Test
    void reportsMalformedRequestsAs21002() throws Exception {
        assertEquals(21002, endpoint(false)
                .verifyReceipt(Collections.<String, Object>emptyMap()).get("status"));
        assertEquals(21002, endpoint(false)
                .verifyReceipt(null).get("status"));
        assertEquals(21002, endpoint(false)
                .verifyReceipt(Collections.singletonMap("receipt-data", "AQIDBA==")).get("status"));
    }

    @Test
    void rejectsAnEmptyRootSet() {
        assertThrows(IllegalArgumentException.class,
                () -> new VerifyReceiptEndpoint(Collections.<X509Certificate>emptySet(), false));
    }

    @Test
    void rawJsonOverloadPinsTheWireTypes() throws Exception {
        String body = endpoint(false).verifyReceiptJson(MAPPER.writeValueAsString(request()));
        // Raw bytes, not just the parse: status is a JSON number and every
        // number-shaped receipt field is a JSON string, as Apple sends them.
        assertTrue(body.contains("\"status\":0"), body);
        assertTrue(body.contains("\"quantity\":\"1\""), body);
        assertTrue(body.contains("\"web_order_line_item_id\":\"42\""), body);
        JsonNode parsed = MAPPER.readTree(body);
        assertTrue(parsed.get("status").isNumber(), body);
        assertEquals("Sandbox", parsed.get("environment").asText());
        JsonNode receipt = parsed.get("receipt");
        assertTrue(receipt.get("receipt_creation_date_ms").isTextual());
        assertTrue(receipt.get("request_date_ms").isTextual());
        for (JsonNode purchase : receipt.get("in_app")) {
            assertTrue(purchase.get("quantity").isTextual());
            assertTrue(purchase.get("web_order_line_item_id").isTextual());
            assertTrue(purchase.get("purchase_date_ms").isTextual());
        }
    }

    @Test
    void rawJsonOverloadRendersIsInIntroOfferPeriodAsAString() throws Exception {
        Path publicReceipts = Paths.get("..", "fixtures", "public-receipts");
        String receiptData = new String(
                Files.readAllBytes(publicReceipts.resolve("receipt-sandbox-g5.b64")),
                StandardCharsets.US_ASCII).trim();
        String body = new VerifyReceiptEndpoint(AppleRootCerts.receiptRoots(), false)
                .verifyReceiptJson(MAPPER.writeValueAsString(
                        Collections.singletonMap("receipt-data", receiptData)));
        assertTrue(body.contains("\"is_in_intro_offer_period\":\"false\""), body);
        JsonNode purchases = MAPPER.readTree(body).get("receipt").get("in_app");
        assertTrue(purchases.size() > 0);
        for (JsonNode purchase : purchases) {
            assertTrue(purchase.get("is_in_intro_offer_period").isTextual());
        }
    }

    @Test
    void rawJsonOverloadOmitsReceiptAndEnvironmentOnNonZeroStatus() throws Exception {
        assertEquals("{\"status\":21007}",
                endpoint(true).verifyReceiptJson(MAPPER.writeValueAsString(request())));
    }

    @Test
    void rawJsonOverloadAnswers21002ForABodyThatIsNotAnObject() throws Exception {
        VerifyReceiptEndpoint endpoint = endpoint(false);
        String[] bodies = {"", "not json", "{", "[]", "[{\"receipt-data\":\"x\"}]",
                "null", "3", "\"receipt\"", "true", null};
        for (String body : bodies) {
            assertEquals("{\"status\":21002}", endpoint.verifyReceiptJson(body),
                    String.valueOf(body));
        }
    }

    @Test
    void rawJsonOverloadMatchesTheMapApi() throws Exception {
        VerifyReceiptEndpoint endpoint = endpoint(false);
        JsonNode viaMap = MAPPER.valueToTree(endpoint.verifyReceipt(request()));
        JsonNode viaJson = MAPPER.readTree(
                endpoint.verifyReceiptJson(MAPPER.writeValueAsString(request())));
        assertEquals(withoutRequestDate(viaMap), withoutRequestDate(viaJson));
    }

    /**
     * request_date is the wall clock at call time, so an injected clock drives
     * it — the endpoint's only time-dependent output. Omitting the clock keeps
     * the system clock (asserted by
     * {@link #emitsTheRequestDateAndEveryDateCompanionField()}).
     */
    @Test
    @SuppressWarnings("unchecked")
    void injectedClockDrivesTheRequestDate() throws Exception {
        Instant now = Instant.parse("2025-01-01T00:00:00Z");
        byte[] der = Files.readAllBytes(FIXTURES.resolve("receipt-root.der"));
        X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        VerifyReceiptEndpoint pinned = new VerifyReceiptEndpoint(
                Collections.singleton(root), false, Clock.fixed(now, ZoneOffset.UTC));
        Map<String, Object> receipt = (Map<String, Object>)
                pinned.verifyReceipt(request()).get("receipt");
        assertEquals(String.valueOf(now.toEpochMilli()), receipt.get("request_date_ms"));
        assertEquals("2025-01-01 00:00:00 Etc/GMT", receipt.get("request_date"));
        assertEquals("2024-12-31 16:00:00 America/Los_Angeles", receipt.get("request_date_pst"));
    }
}
